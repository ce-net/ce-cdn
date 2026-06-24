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
        /// Tag for invalidation-by-tag (`ce-cdn purge --tag T` evicts every CID tagged T). Repeatable.
        #[arg(long = "tag")]
        tags: Vec<String>,
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
    /// Evict content from edges (and forget it locally). Targets recorded + DHT-advertised edges
    /// unless --edge given; --tag purges every CID with that tag.
    Purge {
        /// The object CID to purge (omit when using --tag).
        cid: Option<String>,
        /// Purge every CID tagged with this tag (bulk invalidation).
        #[arg(long)]
        tag: Option<String>,
        /// Purge from a specific edge NodeId only (default: all recorded + advertised edges).
        #[arg(long)]
        edge: Option<String>,
        /// Capability chain (hex) granting `cdn:purge` on the edges.
        #[arg(long)]
        caps: Option<String>,
        /// Keep the catalog entry (only evict from edges, do not forget locally).
        #[arg(long)]
        keep: bool,
    },
    /// Force-forget a CID from the local catalog without contacting any edge (for a deployment whose
    /// host is permanently unreachable). Does NOT evict from edges — use `purge` for that.
    Forget {
        /// The object CID to drop from the catalog.
        cid: String,
    },
    /// Run the re-replication maintenance loop: probe each recorded object's edges and re-cache to
    /// restore its target replication factor. One pass by default; --watch loops forever.
    Maintain {
        /// Capability chain (hex) presented to edges for status/cache during maintenance.
        #[arg(long)]
        caps: Option<String>,
        /// Loop forever, sleeping this many seconds between passes (default: one pass and exit).
        #[arg(long)]
        watch: Option<u64>,
    },
    /// Mint a presigned, time-limited public link for a CID, signed by the local node's key. Anyone
    /// with the link can fetch until it expires — no client key needed (the Cloud-CDN signed-URL
    /// analog). The serving edge must trust this node's key (`--presign-key`).
    Presign {
        /// The object CID to sign a link for.
        cid: String,
        /// Link lifetime in seconds (default: 1 hour).
        #[arg(long, default_value_t = 3600)]
        ttl: u64,
        /// Optional `scheme://host:port` to prepend so the printed link is directly clickable.
        #[arg(long)]
        base: Option<String>,
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
        /// `GET /cdn/<cid>` (+ `/status`, `/health`, `/metrics`). Omit to run mesh-only.
        #[arg(long)]
        http: Option<std::net::SocketAddr>,
        /// Publisher NodeId (64-hex) whose presigned links this edge honors over HTTP. Repeatable.
        /// With none set, presigned links are disabled and private content needs PoP + a cap chain.
        #[arg(long = "presign-key")]
        presign_keys: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    let ce = CeClient::new(cli.api.clone());
    let catalog_path = cli.catalog.clone().unwrap_or_else(Catalog::default_path);

    match cli.cmd {
        Cmd::Put { file, replication, ttl, private, label, tags, caps: caps_arg, no_replicate } => {
            cmd_put(
                ce,
                &catalog_path,
                &file,
                replication,
                ttl,
                private,
                label,
                tags,
                caps_arg.as_deref(),
                no_replicate,
            )
            .await
        }
        Cmd::Get { cid, out, range } => cmd_get(ce, &cid, out, range.as_deref()).await,
        Cmd::Ls => cmd_ls(&catalog_path),
        Cmd::Purge { cid, tag, edge, caps: caps_arg, keep } => {
            cmd_purge(ce, &catalog_path, cid, tag, edge.as_deref(), caps_arg.as_deref(), keep).await
        }
        Cmd::Forget { cid } => cmd_forget(&catalog_path, &cid),
        Cmd::Status { cid, caps: caps_arg } => {
            cmd_status(ce, &catalog_path, &cid, caps_arg.as_deref()).await
        }
        Cmd::Maintain { caps: caps_arg, watch } => {
            cmd_maintain(ce, &catalog_path, caps_arg.as_deref(), watch).await
        }
        Cmd::Presign { cid, ttl, base } => cmd_presign(ce, &cid, ttl, base.as_deref()).await,
        Cmd::Serve { max_mb, ttl, public, http, presign_keys } => {
            let max_bytes = max_mb.saturating_mul(1024 * 1024);
            cmd_serve(ce, max_bytes, ttl, public, http, presign_keys).await
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
    presign_keys_hex: Vec<String>,
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

    let presign_keys = parse_node_ids(&presign_keys_hex)?;

    let edge = EdgeState::new(max_bytes, ttl);
    {
        let mut p = edge.public.lock().await;
        for cid in &public {
            p.allow_public(cid);
        }
    }
    let state = Arc::new(
        ServerState::new(edge, CeOrigin::new(ce), edge_id, roots)
            .with_presign_keys(presign_keys)
            .with_max_object_bytes(max_bytes),
    );
    println!(
        "ce-cdn HTTP front-end on http://{addr}  (GET /cdn/<cid>, /status, /health, /metrics)"
    );
    ce_cdn::server::run(addr, state).await
}

/// Parse a list of 64-hex NodeId strings into `[u8; 32]`, failing on the first malformed entry.
fn parse_node_ids(hexes: &[String]) -> Result<Vec<[u8; 32]>> {
    hexes
        .iter()
        .map(|h| {
            hex::decode(h.trim())
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or_else(|| anyhow::anyhow!("'{h}' is not a 64-hex node id"))
        })
        .collect()
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
    tags: Vec<String>,
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

    Catalog::update(catalog_path, |catalog| {
        catalog.upsert(Entry {
            content: Content {
                cid: put.cid.clone(),
                bytes_len: put.bytes_len,
                access,
                replication,
                ttl_secs: ttl,
                label,
                tags,
            },
            edges,
        });
        Ok(())
    })?;
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
        "{:<66}  {:>10}  {:>7}  {:>5}  {:>8}  {:<16}  TAGS",
        "CID", "BYTES", "ACCESS", "REPL", "HEALTHY", "LABEL"
    );
    for (cid, e) in &catalog.items {
        let access = if e.content.access.is_public() { "public" } else { "private" };
        let tags = if e.content.tags.is_empty() { "-".to_string() } else { e.content.tags.join(",") };
        println!(
            "{:<66}  {:>10}  {:>7}  {:>5}  {:>4}/{:<3}  {:<16}  {}",
            cid,
            e.content.bytes_len,
            access,
            e.content.replication,
            e.healthy_edges(),
            e.edges.len(),
            e.content.label.as_deref().unwrap_or("-"),
            tags,
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_purge(
    ce: CeClient,
    catalog_path: &std::path::Path,
    cid: Option<String>,
    tag: Option<String>,
    edge: Option<&str>,
    caps_arg: Option<&str>,
    keep: bool,
) -> Result<()> {
    let client = CdnClient::new(ce);
    let caps_hex = caps::resolve(caps_arg);

    // Resolve the set of CIDs to purge: explicit CID, or every CID with the given tag.
    let cids: Vec<String> = match (&cid, &tag) {
        (Some(c), _) => vec![c.clone()],
        (None, Some(t)) => {
            let cids = Catalog::load(catalog_path)?.cids_with_tag(t);
            if cids.is_empty() {
                println!("no content tagged '{t}'");
                return Ok(());
            }
            println!("purging {} CID(s) tagged '{t}'", cids.len());
            cids
        }
        (None, None) => anyhow::bail!("provide a CID or --tag"),
    };

    for cid in &cids {
        // Fan out to ALL edges: explicit one, else recorded replicas UNION DHT-advertised holders
        // (an edge advertising cdn:<cid> that isn't in our local catalog still gets purged).
        let edges: Vec<String> = match edge {
            Some(e) => vec![e.to_string()],
            None => {
                let mut set: Vec<String> = Catalog::load(catalog_path)?
                    .get(cid)
                    .map(|entry| entry.edge_ids())
                    .unwrap_or_default();
                if let Ok(adv) = client.ce().find_service(&ce_cdn::proto::service_for(cid)).await {
                    for a in adv {
                        if !set.contains(&a) {
                            set.push(a);
                        }
                    }
                }
                set
            }
        };

        if edges.is_empty() {
            println!("{cid}: no edges to purge (no recorded/advertised replicas)");
        } else {
            let mut purged = 0usize;
            for e in &edges {
                let short = &e[..16.min(e.len())];
                match client.purge_at(e, cid, &caps_hex).await {
                    Ok(r) if r.purged => {
                        purged += 1;
                        println!("  {cid} {short}… purged");
                    }
                    Ok(r) => println!("  {cid} {short}… not held{}", reason_suffix(r.reason)),
                    Err(err) => println!("  {cid} {short}… error: {err}"),
                }
            }
            println!("{cid}: purged from {purged}/{} edge(s)", edges.len());
        }

        if !keep {
            Catalog::update(catalog_path, |catalog| {
                if catalog.remove(cid).is_some() {
                    println!("forgot {cid} from the catalog");
                }
                Ok(())
            })?;
        }
    }
    Ok(())
}

/// Force-forget a CID locally without contacting any edge — for a deployment whose host is gone.
fn cmd_forget(catalog_path: &std::path::Path, cid: &str) -> Result<()> {
    Catalog::update(catalog_path, |catalog| {
        if catalog.remove(cid).is_some() {
            println!("forgot {cid} from the catalog (no edges contacted)");
        } else {
            println!("{cid} was not in the catalog");
        }
        Ok(())
    })
}

/// Run the re-replication maintenance loop: one pass, or forever with `--watch`.
async fn cmd_maintain(
    ce: CeClient,
    catalog_path: &std::path::Path,
    caps_arg: Option<&str>,
    watch: Option<u64>,
) -> Result<()> {
    let client = CdnClient::new(ce);
    let caps_hex = caps::resolve(caps_arg);
    match watch {
        Some(interval) => {
            ce_cdn::maintain::run_forever(&client, catalog_path, &caps_hex, interval).await
        }
        None => {
            let report = ce_cdn::maintain::run_once(&client, catalog_path, &caps_hex).await?;
            println!(
                "maintenance: examined {} object(s), recruited {} new replica(s), {} shortfall(s)",
                report.examined, report.recruited, report.shortfalls
            );
            Ok(())
        }
    }
}

/// Mint a presigned, time-limited public link for a CID, signed with the local CE identity key (read
/// from the node's data dir). The signer's NodeId must be configured as a trusted `--presign-key` on
/// the serving edge. This is a purely local, offline operation (no node API call needed).
async fn cmd_presign(
    _ce: CeClient,
    cid: &str,
    ttl: u64,
    base: Option<&str>,
) -> Result<()> {
    if !ce_cdn::limits::is_valid_cid(cid) {
        anyhow::bail!("'{cid}' is not a valid 64-hex content id");
    }
    let identity = load_identity().context("loading the local CE identity for presigning")?;
    let expires = ce_cdn::host::now_secs().saturating_add(ttl);
    let url_path = ce_cdn::presign::presign_url(|m| identity.sign(m), cid, expires);
    match base {
        Some(b) => println!("{}{url_path}", b.trim_end_matches('/')),
        None => println!("{url_path}"),
    }
    let signer = identity.node_id_hex();
    eprintln!(
        "presigned by {}… valid for {ttl}s (edge must trust this key via --presign-key {})",
        &signer[..16.min(signer.len())],
        signer
    );
    Ok(())
}

/// Load the local CE identity (the Ed25519 key the node uses), from `$CE_DATA_DIR/identity` else
/// `~/.local/share/ce/identity` — the same location the node and ce-pin read.
fn load_identity() -> Result<ce_identity::Identity> {
    use std::path::PathBuf;
    let dir = std::env::var_os("CE_DATA_DIR")
        .map(|d| PathBuf::from(d).join("identity"))
        .or_else(|| {
            directories::ProjectDirs::from("", "", "ce")
                .map(|p| p.data_dir().join("identity"))
        })
        .ok_or_else(|| anyhow::anyhow!("could not locate the CE data dir"))?;
    ce_identity::Identity::load_or_generate(&dir)
        .with_context(|| format!("loading identity from {}", dir.display()))
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

    // Reflect freshly-measured health into the catalog if we track this CID (atomic, under lock).
    let _ = Catalog::update(catalog_path, |catalog| {
        if let Some(entry) = catalog.get_mut(cid) {
            for r in entry.edges.iter_mut() {
                r.healthy = advertised.contains(&r.edge);
            }
        }
        Ok(())
    });
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
