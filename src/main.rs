//! `ce-cdn` — content-delivery / edge-cache network over CE.
//!
//! A thin CLI over the [`ce_cdn`] library and the CE SDK (`ce-rs`). On a publisher,
//! `ce-cdn put <file>` stores the file in the content-addressed data layer, records it in the
//! catalog, and replicates it to ranked edges; `ce-cdn get <cid>` fetches it back (trustless — every
//! chunk is CID-verified, including a `--range`). `ce-cdn serve` runs an edge that caches and serves
//! content (public or capability-gated). `ce-cdn purge <cid>` evicts content from edges.

use std::path::PathBuf;

use anyhow::{Context, Result};
use ce_cdn::catalog::{Access, Catalog, Content, EdgeReplica, Entry};
use ce_cdn::client::CdnClient;
use ce_cdn::{caps, load_roots};
use ce_rs::CeClient;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "ce-cdn",
    version,
    about = "Content-delivery / edge-cache network over CE — cache-and-serve by CID, content-addressing is the cache key and the proof.",
    long_about = None
)]
struct Cli {
    /// CE node HTTP API base URL.
    #[arg(long, default_value = ce_rs::DEFAULT_BASE_URL, global = true)]
    api: String,

    /// Path to the catalog index file (default: <config dir>/ce-cdn/catalog.json).
    #[arg(long, global = true)]
    catalog: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Store a file on the CDN (content-addressed) and replicate it to N edges. Prints CID + URL.
    Put {
        /// Path to the file to publish.
        file: PathBuf,
        /// Desired number of edge replicas.
        #[arg(long, default_value_t = 3)]
        replication: u8,
        /// Cache TTL the edges should apply, in seconds (0 = edge default).
        #[arg(long, default_value_t = 3600)]
        ttl: u64,
        /// Mark the content private (consumers must present a `cdn:read` capability chain).
        #[arg(long)]
        private: bool,
        /// Optional human label for `ce-cdn ls`.
        #[arg(long)]
        label: Option<String>,
        /// Capability chain (hex) to present to edges; overrides $CE_CDN_CAPS / config file.
        #[arg(long)]
        caps: Option<String>,
        /// Skip replication — just publish to the local data layer and record the CID.
        #[arg(long)]
        no_replicate: bool,
    },
    /// Fetch content by CID and write it to a file. `--range` fetches only a byte range.
    Get {
        /// The object CID.
        cid: String,
        /// Output path (default: ./<cid>.bin).
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// HTTP-style byte range, e.g. "bytes=0-1023" or "0-1023" (partial / resumable fetch).
        #[arg(long)]
        range: Option<String>,
    },
    /// List published content and its edge-replica health.
    Ls,
    /// Evict content from edges (and forget it locally). Targets recorded edges unless --edge given.
    Purge {
        /// The object CID to purge.
        cid: String,
        /// Purge from a specific edge NodeId only (default: all recorded edges).
        #[arg(long)]
        edge: Option<String>,
        /// Capability chain (hex) granting `cdn:purge` on the edges.
        #[arg(long)]
        caps: Option<String>,
        /// Keep the catalog entry (only evict from edges, do not forget locally).
        #[arg(long)]
        keep: bool,
    },
    /// Check which edges currently hold a CID (cheap status probe across recorded + advertised edges).
    Status {
        /// The object CID to check.
        cid: String,
        /// Capability chain (hex) for the status probe (edges gate `cdn:read` on private content).
        #[arg(long)]
        caps: Option<String>,
    },
    /// Run as a CDN edge: cache cap-gated/public content and serve it (whole or by range).
    Serve {
        /// Maximum cache size in megabytes.
        #[arg(long, default_value_t = 1024)]
        max_mb: u64,
        /// Default cache TTL in seconds applied to cached objects (0 = never expire).
        #[arg(long, default_value_t = 3600)]
        ttl: u64,
        /// CIDs to serve publicly (no capability required). Repeatable.
        #[arg(long = "public")]
        public: Vec<String>,
        /// Also run the HTTP front-end on this address (e.g. `127.0.0.1:8845`), exposing
        /// `GET /cdn/<cid>` (+ `/status`, `/health`). Omit to run mesh-only.
        #[arg(long)]
        http: Option<std::net::SocketAddr>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    let ce = CeClient::new(cli.api.clone());
    let catalog_path = cli.catalog.clone().unwrap_or_else(Catalog::default_path);

    match cli.cmd {
        Cmd::Put { file, replication, ttl, private, label, caps: caps_arg, no_replicate } => {
            cmd_put(
                ce,
                &catalog_path,
                &file,
                replication,
                ttl,
                private,
                label,
                caps_arg.as_deref(),
                no_replicate,
            )
            .await
        }
        Cmd::Get { cid, out, range } => cmd_get(ce, &cid, out, range.as_deref()).await,
        Cmd::Ls => cmd_ls(&catalog_path),
        Cmd::Purge { cid, edge, caps: caps_arg, keep } => {
            cmd_purge(ce, &catalog_path, &cid, edge.as_deref(), caps_arg.as_deref(), keep).await
        }
        Cmd::Status { cid, caps: caps_arg } => {
            cmd_status(ce, &catalog_path, &cid, caps_arg.as_deref()).await
        }
        Cmd::Serve { max_mb, ttl, public, http } => {
            let max_bytes = max_mb.saturating_mul(1024 * 1024);
            cmd_serve(ce, max_bytes, ttl, public, http).await
        }
    }
}

/// Run a CDN edge. Always serves over the mesh; if `http` is set, *also* runs the HTTP front-end
/// bound to that address. The two front-ends share one edge state (cache + public set), so a CID
/// cached via the mesh is served over HTTP and vice versa.
async fn cmd_serve(
    ce: CeClient,
    max_bytes: u64,
    ttl: u64,
    public: Vec<String>,
    http: Option<std::net::SocketAddr>,
) -> Result<()> {
    let roots = load_roots();
    let Some(addr) = http else {
        // Mesh-only edge (unchanged behaviour).
        return ce_cdn::host::serve(&ce, roots, max_bytes, ttl, public).await;
    };

    use std::sync::Arc;
    use ce_cdn::host::EdgeState;
    use ce_cdn::server::{CeOrigin, ServerState};

    let edge_hex = ce.status().await?.node_id;
    let edge_id: [u8; 32] = hex::decode(&edge_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .context("node returned a malformed node id")?;

    let edge = EdgeState::new(max_bytes, ttl);
    {
        let mut p = edge.public.lock().await;
        for cid in &public {
            p.allow_public(cid);
        }
    }
    let state = Arc::new(ServerState::new(edge, CeOrigin::new(ce), edge_id, roots));
    println!("ce-cdn HTTP front-end on http://{addr}  (GET /cdn/<cid>, /status, /health)");
    ce_cdn::server::run(addr, state).await
}

#[allow(clippy::too_many_arguments)]
async fn cmd_put(
    ce: CeClient,
    catalog_path: &std::path::Path,
    file: &std::path::Path,
    replication: u8,
    ttl: u64,
    private: bool,
    label: Option<String>,
    caps_arg: Option<&str>,
    no_replicate: bool,
) -> Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let client = CdnClient::new(ce);
    let put = client.put(&bytes).await?;
    println!("published {} ({} bytes)", file.display(), put.bytes_len);
    println!("  cid: {}", put.cid);
    println!("  url: {}", put.url);

    let access = if private { Access::Private } else { Access::Public };
    let mut catalog = Catalog::load(catalog_path)?;
    let mut edges: Vec<EdgeReplica> = Vec::new();

    if !no_replicate && replication > 0 {
        let caps_hex = caps::resolve(caps_arg);
        let picks = client.pick_edges(replication as usize, &[]).await.unwrap_or_default();
        if picks.is_empty() {
            eprintln!(
                "no edges advertised cdn:edge on the mesh yet — recorded locally; \
                 start edges with `ce-cdn serve`."
            );
        } else {
            for edge in &picks {
                match client.replicate_to(edge, &put.cid, put.bytes_len, ttl, &caps_hex).await {
                    Ok(r) if r.cached => {
                        let short = &edge[..16.min(edge.len())];
                        println!("  cached on {short}… ({} bytes, ttl {}s)", r.stored_bytes, r.ttl_secs);
                        edges.push(EdgeReplica { edge: edge.clone(), healthy: true });
                    }
                    Ok(r) => {
                        let short = &edge[..16.min(edge.len())];
                        eprintln!("  {short}… declined: {}", r.reason.unwrap_or_default());
                    }
                    Err(e) => eprintln!("  {edge}: {e}"),
                }
            }
            println!("replicated to {}/{} edge(s)", edges.len(), replication);
        }
    }

    catalog.upsert(Entry {
        content: Content {
            cid: put.cid.clone(),
            bytes_len: put.bytes_len,
            access,
            replication,
            ttl_secs: ttl,
            label,
        },
        edges,
    });
    catalog.save(catalog_path)?;
    println!("recorded in {}", catalog_path.display());
    Ok(())
}

async fn cmd_get(
    ce: CeClient,
    cid: &str,
    out: Option<PathBuf>,
    range: Option<&str>,
) -> Result<()> {
    let client = CdnClient::new(ce);
    let path = out.unwrap_or_else(|| PathBuf::from(format!("{cid}.bin")));
    match range {
        Some(r) => {
            let (bytes, range, total) = client.get_range(cid, Some(r)).await?;
            std::fs::write(&path, &bytes).with_context(|| format!("writing {}", path.display()))?;
            println!(
                "fetched {cid} bytes {}-{}/{} ({} bytes) -> {}",
                range.start,
                range.end,
                total,
                bytes.len(),
                path.display()
            );
        }
        None => {
            let bytes = client.get(cid).await?;
            std::fs::write(&path, &bytes).with_context(|| format!("writing {}", path.display()))?;
            println!("fetched {cid} ({} bytes) -> {}", bytes.len(), path.display());
        }
    }
    Ok(())
}

fn cmd_ls(catalog_path: &std::path::Path) -> Result<()> {
    let catalog = Catalog::load(catalog_path)?;
    if catalog.items.is_empty() {
        println!("no content recorded ({})", catalog_path.display());
        return Ok(());
    }
    println!(
        "{:<66}  {:>10}  {:>7}  {:>5}  {:>8}  LABEL",
        "CID", "BYTES", "ACCESS", "REPL", "HEALTHY"
    );
    for (cid, e) in &catalog.items {
        let access = if e.content.access.is_public() { "public" } else { "private" };
        println!(
            "{:<66}  {:>10}  {:>7}  {:>5}  {:>4}/{:<3}  {}",
            cid,
            e.content.bytes_len,
            access,
            e.content.replication,
            e.healthy_edges(),
            e.edges.len(),
            e.content.label.as_deref().unwrap_or("-"),
        );
    }
    Ok(())
}

async fn cmd_purge(
    ce: CeClient,
    catalog_path: &std::path::Path,
    cid: &str,
    edge: Option<&str>,
    caps_arg: Option<&str>,
    keep: bool,
) -> Result<()> {
    let client = CdnClient::new(ce);
    let caps_hex = caps::resolve(caps_arg);

    // Determine which edges to purge from: the explicit one, else all recorded edges.
    let edges: Vec<String> = match edge {
        Some(e) => vec![e.to_string()],
        None => Catalog::load(catalog_path)?
            .get(cid)
            .map(|entry| entry.edge_ids())
            .unwrap_or_default(),
    };

    if edges.is_empty() {
        println!("{cid}: no edges to purge (no recorded replicas; pass --edge to target one)");
    } else {
        let mut purged = 0usize;
        for e in &edges {
            let short = &e[..16.min(e.len())];
            match client.purge_at(e, cid, &caps_hex).await {
                Ok(r) if r.purged => {
                    purged += 1;
                    println!("  {short}… purged");
                }
                Ok(r) => println!("  {short}… not held{}", reason_suffix(r.reason)),
                Err(err) => println!("  {short}… error: {err}"),
            }
        }
        println!("purged from {purged}/{} edge(s)", edges.len());
    }

    if !keep {
        let mut catalog = Catalog::load(catalog_path)?;
        if catalog.remove(cid).is_some() {
            catalog.save(catalog_path)?;
            println!("forgot {cid} from the catalog");
        }
    }
    Ok(())
}

async fn cmd_status(
    ce: CeClient,
    catalog_path: &std::path::Path,
    cid: &str,
    caps_arg: Option<&str>,
) -> Result<()> {
    let client = CdnClient::new(ce);
    let caps_hex = caps::resolve(caps_arg);

    // Combine DHT-advertised edges with any recorded in the catalog.
    let advertised = client.ce().find_service(&ce_cdn::proto::service_for(cid)).await.unwrap_or_default();
    let mut all = advertised.clone();
    if let Ok(catalog) = Catalog::load(catalog_path)
        && let Some(entry) = catalog.get(cid)
    {
        for id in entry.edge_ids() {
            if !all.contains(&id) {
                all.push(id);
            }
        }
    }

    println!("{cid}: {} edge(s) advertised on the DHT", advertised.len());
    if all.is_empty() {
        println!("  (no edges known — replicate via `ce-cdn put` or ensure edges are serving)");
        return Ok(());
    }

    let mut live = 0usize;
    for edge in &all {
        let short = &edge[..16.min(edge.len())];
        match client.probe(edge, cid, &caps_hex).await {
            Ok(s) if s.held => {
                live += 1;
                println!("  {short}…  HELD (ttl {}s)", s.ttl_remaining);
            }
            Ok(_) => println!("  {short}…  not held"),
            Err(e) => println!("  {short}…  unreachable: {e}"),
        }
    }
    println!("served by {live}/{} edge(s)", all.len());

    // Reflect freshly-measured health into the catalog if we track this CID.
    if let Ok(mut catalog) = Catalog::load(catalog_path)
        && let Some(entry) = catalog.get_mut(cid)
    {
        for r in entry.edges.iter_mut() {
            r.healthy = advertised.contains(&r.edge);
        }
        let _ = catalog.save(catalog_path);
    }
    Ok(())
}

fn reason_suffix(reason: Option<String>) -> String {
    match reason {
        Some(r) if !r.is_empty() => format!(" ({r})"),
        _ => String::new(),
    }
}

/// Initialize tracing once; level from `$RUST_LOG`, defaulting to `info`.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_target(false).try_init();
}
