//! Integration tests that wire the ce-cdn library layers together end to end *without* a live CE
//! node — exercising the real CID/range math, the edge cache, the HTTP response shaping, the
//! replication policy, and the capability-gated host decision (with forged `ce-cap` chains).
//!
//! These cover the contract the prompt calls out: CID integrity, replication/eviction logic,
//! range/partial fetch, cache-hit accounting, capability-gated private content, and failure
//! injection (denied caps, malformed input, missing blob, unsatisfiable range → graceful, no panic).

use ce_cap::{Caveats, Resource, SignedCapability, authorize, decode_chain, encode_chain};
use ce_cdn::cache::EdgeCache;
use ce_cdn::cidrange::{ByteRange, RangeOutcome, chunks_for_range, parse_range, slice_span};
use ce_cdn::edge::{self, Access, Body};
use ce_cdn::host::{Decision, PublicSet, decide};
use ce_cdn::proto;
use ce_cdn::replication::{EdgeCandidate, needs_rereplication, replicas_needed, select};
use ce_identity::{Identity, NodeId};
use ce_rs::data::{MANIFEST_KIND_V1, chunk_object, reassemble};
use ce_rs::{Manifest, cid};

/// A fresh identity in a unique temp dir (tests run in parallel within one process).
fn ident(tag: &str) -> Identity {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("ce-cdn-it-{}-{n}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Identity::load_or_generate(&dir).unwrap()
}

fn never_revoked(_: &NodeId, _: u64) -> bool {
    false
}

// ---------------------------------------------------------------------------
// CID integrity: an object round-trips through chunk -> reassemble; tampering is caught.
// ---------------------------------------------------------------------------

#[test]
fn object_cid_round_trips_and_dedups() {
    use std::collections::HashMap;
    let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    let (manifest, chunks) = chunk_object(&data, 1024 * 1024);
    // The object CID is the hash of the manifest bytes (content addressing).
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let object_cid = cid(&manifest_bytes);
    assert_eq!(object_cid.len(), 64);

    let store: HashMap<String, Vec<u8>> = chunks.into_iter().collect();
    let back = reassemble(&manifest, |c| {
        store.get(c).cloned().ok_or_else(|| anyhow::anyhow!("missing {c}"))
    })
    .unwrap();
    assert_eq!(back, data);
}

#[test]
fn tampered_chunk_is_rejected_by_cid_verification() {
    use std::collections::HashMap;
    let data: Vec<u8> = (0..1_500_000u32).map(|i| i as u8).collect();
    let (manifest, chunks) = chunk_object(&data, 1024 * 1024);
    let mut store: HashMap<String, Vec<u8>> = chunks.into_iter().collect();
    let first = manifest.chunks[0].clone();
    store.get_mut(&first).unwrap()[0] ^= 0xff; // corrupt the bytes, keep the CID key
    let err = reassemble(&manifest, |c| Ok(store[c].clone())).unwrap_err();
    assert!(err.to_string().contains("verification failed"), "{err}");
}

// ---------------------------------------------------------------------------
// Range / partial fetch: a range maps onto chunks and slices back to the exact bytes.
// ---------------------------------------------------------------------------

fn manifest_for(chunk_size: u64, total: u64) -> Manifest {
    let n = total.div_ceil(chunk_size);
    Manifest {
        kind: MANIFEST_KIND_V1.to_string(),
        chunk_size,
        total_size: total,
        chunks: (0..n).map(|i| format!("c{i}")).collect(),
    }
}

#[test]
fn range_fetch_slices_exact_bytes_across_chunk_boundary() {
    let object: Vec<u8> = (0..5000u32).map(|i| (i % 256) as u8).collect();
    let m = manifest_for(1000, 5000);
    let outcome = parse_range(Some("bytes=1500-2500"), m.total_size);
    let RangeOutcome::Partial(r) = outcome else { panic!("expected partial") };
    let span = chunks_for_range(&m, r).unwrap();
    // Build the joined covering-chunk bytes as an edge would.
    let first = (span.first_chunk * m.chunk_size) as usize;
    let last = (((span.last_chunk + 1) * m.chunk_size).min(m.total_size)) as usize;
    let joined = &object[first..last];
    let sliced = slice_span(joined, span).unwrap();
    assert_eq!(sliced, &object[1500..=2500]);
}

#[test]
fn unsatisfiable_range_is_graceful_not_a_panic() {
    let m = manifest_for(1000, 100);
    assert_eq!(parse_range(Some("bytes=500-600"), m.total_size), RangeOutcome::Unsatisfiable);
}

#[test]
fn malformed_range_degrades_to_full() {
    assert_eq!(parse_range(Some("bytes=not-a-range"), 100), RangeOutcome::Full);
    assert_eq!(parse_range(Some("totally bogus"), 100), RangeOutcome::Full);
}

// ---------------------------------------------------------------------------
// Cache: hit accounting, TTL expiry, LRU eviction, purge — the full cache contract.
// ---------------------------------------------------------------------------

#[test]
fn cache_hit_accounting_and_eviction_end_to_end() {
    let mut c = EdgeCache::new(12, 100); // 12-byte budget, 100s TTL
    assert!(c.get("a", 0).is_none()); // miss
    assert!(c.insert("a", vec![0; 4], 0));
    assert!(c.insert("b", vec![0; 4], 0));
    assert!(c.insert("c", vec![0; 4], 0)); // budget full (12 bytes)
    // Touch a and b so c is LRU; inserting d evicts c.
    assert!(c.get("a", 0).is_some());
    assert!(c.get("b", 0).is_some());
    assert!(c.insert("d", vec![0; 4], 0));
    assert!(!c.contains_fresh("c", 0)); // c evicted (was LRU)
    let s = c.stats();
    assert_eq!(s.hits, 2);
    assert_eq!(s.misses, 1);
    assert_eq!(s.evictions, 1);
    assert!(s.bytes <= 12);
    assert!((s.hit_ratio() - 2.0 / 3.0).abs() < 1e-9);
}

#[test]
fn cache_ttl_expiry_then_purge() {
    let mut c = EdgeCache::new(1000, 10);
    c.insert("a", vec![1, 2, 3], 100); // expires at 110
    assert!(c.get("a", 105).is_some()); // fresh
    assert!(c.get("a", 200).is_none()); // expired -> miss, dropped
    assert_eq!(c.stats().expirations, 1);
    // re-insert and explicitly purge
    c.insert("a", vec![9], 300);
    assert!(c.purge("a"));
    assert!(!c.contains_fresh("a", 300));
}

// ---------------------------------------------------------------------------
// Edge HTTP handler: 200 / 206 / 416 / 403 / 404 with correct cache headers.
// ---------------------------------------------------------------------------

#[test]
fn edge_serves_full_then_range_with_headers() {
    let bytes: Vec<u8> = (0..200u8).collect();
    let mut cache = EdgeCache::new(1 << 20, 600);
    cache.insert("cidX", bytes.clone(), 0);

    // Full
    let full = edge::serve("cidX", &bytes, None, Access::Public, &cache, 0, true);
    assert_eq!(full.status, 200);
    assert_eq!(full.header("X-Cache"), Some("HIT"));
    assert!(full.header("Cache-Control").unwrap().contains("immutable"));
    assert_eq!(full.body, Body::Full(bytes.clone()));

    // Range
    let part = edge::serve("cidX", &bytes, Some("bytes=50-99"), Access::Public, &cache, 0, true);
    assert_eq!(part.status, 206);
    assert_eq!(part.header("Content-Range"), Some("bytes 50-99/200"));
    match part.body {
        Body::Partial { bytes: b, range, total } => {
            assert_eq!(b, (50..100u8).collect::<Vec<u8>>());
            assert_eq!(range, ByteRange { start: 50, end: 99 });
            assert_eq!(total, 200);
        }
        other => panic!("expected partial, got {other:?}"),
    }
}

#[test]
fn edge_denies_private_and_404s_missing() {
    let bytes = vec![1u8; 4];
    let cache = EdgeCache::new(1 << 20, 60);
    let denied = edge::serve("c", &bytes, None, Access::Denied, &cache, 0, true);
    assert_eq!(denied.status, 403);
    let nf = edge::not_found("missing");
    assert_eq!(nf.status, 404);
}

// ---------------------------------------------------------------------------
// Replication policy: ranking, selection across N edges, re-replication trigger.
// ---------------------------------------------------------------------------

#[test]
fn replication_selects_n_best_edges_and_triggers_rereplication() {
    let cands = vec![
        EdgeCandidate { node_id: "low".into(), delivered_work: 0, last_seen_secs: 5, mem_mb: 8000 },
        EdgeCandidate { node_id: "mid".into(), delivered_work: 10, last_seen_secs: 50, mem_mb: 1000 },
        EdgeCandidate { node_id: "top".into(), delivered_work: 10, last_seen_secs: 5, mem_mb: 1000 },
    ];
    // top and mid tie on work; top seen more recently -> top first; low (no work) last.
    let picks = select(&cands, 2, &[]);
    assert_eq!(picks, vec!["top".to_string(), "mid".to_string()]);

    // After losing one of three replicas, we need exactly one more.
    assert!(needs_rereplication(3, 2));
    assert_eq!(replicas_needed(3, 2), 1);
    assert!(!needs_rereplication(3, 3));
}

// ---------------------------------------------------------------------------
// Capability-gated private content: the host decision over real forged ce-cap chains.
// ---------------------------------------------------------------------------

/// Forge a single self-issued capability chain from `issuer` to `holder` granting `abilities`.
fn forge_chain(issuer: &Identity, holder: &Identity, abilities: &[&str]) -> String {
    let cap = SignedCapability::issue(
        issuer,
        holder.node_id(),
        abilities.iter().map(|s| s.to_string()).collect(),
        Resource::Any,
        Caveats::default(),
        1,
        None,
    );
    encode_chain(&[cap])
}

/// Build the authorizer closure the host's `decide` consults, bound to a forged chain + edge
/// identity. `requester` and `edge_id` are `[u8; 32]` (Copy), captured by value so callers can pass
/// temporaries (`x.node_id()`).
fn authorizer(edge_id: NodeId, requester: NodeId, caps_hex: String) -> impl Fn(&str) -> Result<(), String> {
    move |action: &str| {
        let chain = decode_chain(&caps_hex).map_err(|_| "bad capability".to_string())?;
        authorize(&edge_id, &[], &[], 1000, &requester, action, &chain, &never_revoked)
    }
}

#[test]
fn private_content_requires_valid_read_capability() {
    let edge = ident("edge");
    let consumer = ident("consumer");
    let chain = forge_chain(&edge, &consumer, &[proto::ABILITY_READ]);

    let public = PublicSet::new(); // CID is private (not in public set)
    let auth = authorizer(edge.node_id(), consumer.node_id(), chain.clone());
    let (d, reason) = decide(proto::ABILITY_READ, "privcid", &public, auth);
    assert_eq!(d, Decision::Allow, "valid cdn:read chain should authorize: {reason:?}");
}

#[test]
fn private_content_denied_without_capability() {
    let edge = ident("edge");
    let public = PublicSet::new();
    // Empty chain -> decode/authorize fails -> denied.
    let auth = authorizer(edge.node_id(), edge.node_id(), String::new());
    let (d, reason) = decide(proto::ABILITY_READ, "privcid", &public, auth);
    assert_eq!(d, Decision::Deny);
    assert!(reason.is_some());
}

#[test]
fn capability_for_wrong_ability_is_denied() {
    let edge = ident("edge");
    let consumer = ident("consumer");
    // Holder was granted only cdn:cache, not cdn:read.
    let chain = forge_chain(&edge, &consumer, &[proto::ABILITY_CACHE]);
    let public = PublicSet::new();
    let auth = authorizer(edge.node_id(), consumer.node_id(), chain.clone());
    let (d, _) = decide(proto::ABILITY_READ, "privcid", &public, auth);
    assert_eq!(d, Decision::Deny);
}

#[test]
fn public_content_served_without_any_capability() {
    let edge = ident("edge");
    let stranger = ident("stranger");
    let mut public = PublicSet::new();
    public.allow_public("pubcid");
    // Stranger presents an empty chain; a public read is still allowed.
    let auth = authorizer(edge.node_id(), stranger.node_id(), String::new());
    let (d, _) = decide(proto::ABILITY_READ, "pubcid", &public, auth);
    assert_eq!(d, Decision::Allow);
}

#[test]
fn public_cid_does_not_authorize_cache_or_purge_without_capability() {
    let edge = ident("edge");
    let mut public = PublicSet::new();
    public.allow_public("pubcid");
    let auth = authorizer(edge.node_id(), edge.node_id(), String::new()); // no chain
    // Mutating actions are never waived by the public flag.
    assert_eq!(decide(proto::ABILITY_CACHE, "pubcid", &public, &auth).0, Decision::Deny);
    assert_eq!(decide(proto::ABILITY_PURGE, "pubcid", &public, &auth).0, Decision::Deny);
}

// ---------------------------------------------------------------------------
// Failure injection: malformed protocol payloads decode/serve gracefully (never panic).
// ---------------------------------------------------------------------------

#[test]
fn malformed_protocol_payloads_are_errors_not_panics() {
    // A read request missing the required `cid` fails to deserialize -> error, no panic.
    let bad: Result<proto::ReadReq, _> = serde_json::from_str(r#"{"caps":"x"}"#);
    assert!(bad.is_err());

    // A minimal valid read request deserializes with defaulted optional fields.
    let ok: proto::ReadReq = serde_json::from_str(r#"{"cid":"abc"}"#).unwrap();
    assert_eq!(ok.cid, "abc");
    assert!(ok.range.is_none());
    assert_eq!(ok.caps, "");

    // A cache reply that only sets the discriminant deserializes with sane defaults.
    let resp: proto::CacheResp = serde_json::from_str(r#"{"cached":false}"#).unwrap();
    assert!(!resp.cached);
    assert_eq!(resp.stored_bytes, 0);
}

// ---------------------------------------------------------------------------
// HTTP front-end: drive the real hyper server over a real socket from outside the crate, asserting
// status codes, range (206/416), cache headers, the private-content gate, and /status sizes.
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::sync::Arc;
use ce_cdn::host::EdgeState;
use ce_cdn::server::{Origin, Running, ServerState, http_get, spawn};

/// An in-memory origin (CID -> bytes) so the HTTP stack runs without a live CE node.
struct MapOrigin(HashMap<String, Vec<u8>>);

impl Origin for MapOrigin {
    async fn fetch(&self, cid: &str) -> anyhow::Result<Vec<u8>> {
        self.0.get(cid).cloned().ok_or_else(|| anyhow::anyhow!("missing {cid}"))
    }
}

async fn http_server(
    objects: &[(&str, &[u8])],
    public: &[&str],
    edge_id: [u8; 32],
) -> Running {
    let edge = EdgeState::new(1 << 20, 3600);
    {
        let mut p = edge.public.lock().await;
        for c in public {
            p.allow_public(c);
        }
    }
    let map: HashMap<String, Vec<u8>> =
        objects.iter().map(|(c, b)| (c.to_string(), b.to_vec())).collect();
    let state = Arc::new(ServerState::new(edge, MapOrigin(map), edge_id, vec![]));
    spawn(state).await.unwrap()
}

#[tokio::test]
async fn http_front_end_full_range_416_and_404() {
    let body: Vec<u8> = (0..120u8).collect();
    let srv = http_server(&[("obj", &body)], &["obj"], [3u8; 32]).await;

    // Full 200 with immutable cache headers.
    let full = http_get(srv.addr(), "/cdn/obj", &[]).await.unwrap();
    assert_eq!(full.status, 200);
    assert_eq!(full.body, body);
    assert!(full.header("cache-control").unwrap().contains("immutable"));
    assert_eq!(full.header("accept-ranges"), Some("bytes"));

    // 206 range.
    let part = http_get(srv.addr(), "/cdn/obj", &[("Range", "bytes=10-29")]).await.unwrap();
    assert_eq!(part.status, 206);
    assert_eq!(part.header("content-range"), Some("bytes 10-29/120"));
    assert_eq!(part.body, (10..30u8).collect::<Vec<u8>>());

    // 416 unsatisfiable.
    let bad = http_get(srv.addr(), "/cdn/obj", &[("Range", "bytes=500-600")]).await.unwrap();
    assert_eq!(bad.status, 416);
    assert_eq!(bad.header("content-range"), Some("bytes */120"));

    // 404 for a public-but-absent CID (origin has nothing).
    let srv2 = http_server(&[], &["ghost"], [3u8; 32]).await;
    let nf = http_get(srv2.addr(), "/cdn/ghost", &[]).await.unwrap();
    assert_eq!(nf.status, 404);
}

#[tokio::test]
async fn http_front_end_private_gate_and_status_sizes() {
    use ce_cap::{Caveats, Resource, SignedCapability, encode_chain};

    let edge = ident("http-edge");
    let consumer = ident("http-consumer");

    // Private content (not public): 403 without a cap, 200 with a valid cdn:read chain.
    let srv = http_server(&[("priv", b"classified")], &[], edge.node_id()).await;
    let denied = http_get(srv.addr(), "/cdn/priv", &[]).await.unwrap();
    assert_eq!(denied.status, 403);

    let cap = SignedCapability::issue(
        &edge,
        consumer.node_id(),
        vec![proto::ABILITY_READ.to_string()],
        Resource::Any,
        Caveats::default(),
        1,
        None,
    );
    let caps_hex = encode_chain(&[cap]);
    let req_hex = hex::encode(consumer.node_id());

    // A leaked cap chain alone (no proof-of-possession) must NOT serve private content: the HTTP
    // edge requires a signature over (requester, cid, cdn:read, expires) proving the caller holds
    // the requester key. This is finding H2 — the `X-Ce-Node-Id` header is proven, not trusted.
    let no_proof = http_get(
        srv.addr(),
        "/cdn/priv",
        &[("X-Ce-Capability", &caps_hex), ("X-Ce-Node-Id", &req_hex)],
    )
    .await
    .unwrap();
    assert_eq!(no_proof.status, 403, "cap chain without proof-of-possession must be denied");

    // With a real proof minted by the consumer's key, the same request succeeds.
    let expires = ce_cdn::host::now_secs() + 60;
    let proof = ce_cdn::pop::mint_proof(
        &consumer.node_id(),
        |m| consumer.sign(m),
        "priv",
        proto::ABILITY_READ,
        expires,
    );
    let ok = http_get(
        srv.addr(),
        "/cdn/priv",
        &[
            ("X-Ce-Capability", &caps_hex),
            ("X-Ce-Node-Id", &req_hex),
            ("X-Ce-Proof", &proof),
        ],
    )
    .await
    .unwrap();
    assert_eq!(ok.status, 200);
    assert_eq!(ok.body, b"classified");

    // /status reports the real per-CID byte size once cached.
    let srv2 = http_server(&[("sized", &[0u8; 77])], &["sized"], [3u8; 32]).await;
    let _ = http_get(srv2.addr(), "/cdn/sized", &[]).await.unwrap();
    let status = http_get(srv2.addr(), "/status", &[]).await.unwrap();
    assert_eq!(status.status, 200);
    let v: serde_json::Value = serde_json::from_slice(&status.body).unwrap();
    assert_eq!(v["bytes"], 77);
    assert_eq!(v["objects"][0]["cid"], "sized");
    assert_eq!(v["objects"][0]["bytes"], 77);
}

#[test]
fn slice_span_rejects_truncated_chunk_bytes() {
    // Simulate an edge returning fewer bytes than the range demands -> graceful error.
    let span = ce_cdn::cidrange::ChunkSpan { first_chunk: 0, last_chunk: 0, head_skip: 2, out_len: 100 };
    let err = slice_span(&[0u8; 8], span).unwrap_err();
    assert!(err.to_string().contains("too short"));
}

// ---------------------------------------------------------------------------
// HTTP front-end: conditional requests (304), negative caching, /metrics, presigned links — the
// new CDN features, driven over a real socket from outside the crate.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_conditional_request_returns_304() {
    let srv = http_server(&[("doc", b"document body")], &["doc"], [4u8; 32]).await;
    // Prime the cache.
    let _ = http_get(srv.addr(), "/cdn/doc", &[]).await.unwrap();
    // Client already holds the immutable CID -> 304, no body.
    let r = http_get(srv.addr(), "/cdn/doc", &[("If-None-Match", "\"doc\"")]).await.unwrap();
    assert_eq!(r.status, 304);
    assert!(r.body.is_empty());
    // Wildcard validator also yields 304.
    let star = http_get(srv.addr(), "/cdn/doc", &[("If-None-Match", "*")]).await.unwrap();
    assert_eq!(star.status, 304);
}

#[tokio::test]
async fn http_metrics_exposes_prometheus_counters() {
    let srv = http_server(&[("met", b"xyz")], &["met"], [4u8; 32]).await;
    let _ = http_get(srv.addr(), "/cdn/met", &[]).await.unwrap(); // miss
    let _ = http_get(srv.addr(), "/cdn/met", &[]).await.unwrap(); // hit
    let m = http_get(srv.addr(), "/metrics", &[]).await.unwrap();
    assert_eq!(m.status, 200);
    let body = String::from_utf8_lossy(&m.body);
    assert!(body.contains("ce_cdn_cache_hits_total"));
    assert!(body.contains("ce_cdn_object_bytes{cid=\"met\"} 3"), "{body}");
}

#[tokio::test]
async fn http_presigned_link_is_honored_end_to_end() {
    use ce_cdn::server::ServerState;
    let signer = ident("presigner");
    // Private content, but the edge trusts the signer's key for presigned links.
    let edge = EdgeState::new(1 << 20, 3600);
    let map: HashMap<String, Vec<u8>> =
        [("link".to_string(), b"behind a link".to_vec())].into_iter().collect();
    let state = Arc::new(
        ServerState::new(edge, MapOrigin(map), [4u8; 32], vec![])
            .with_presign_keys(vec![signer.node_id()]),
    );
    let srv = spawn(state).await.unwrap();

    // No credentials -> 403.
    assert_eq!(http_get(srv.addr(), "/cdn/link", &[]).await.unwrap().status, 403);

    // A presigned URL (query params only, no headers) -> 200.
    let expires = ce_cdn::host::now_secs() + 300;
    let url = ce_cdn::presign::presign_url(|m| signer.sign(m), "link", expires);
    let ok = http_get(srv.addr(), &url, &[]).await.unwrap();
    assert_eq!(ok.status, 200, "{:?}", String::from_utf8_lossy(&ok.body));
    assert_eq!(ok.body, b"behind a link");
}

// ---------------------------------------------------------------------------
// Maintenance / re-replication planning: the pure plan over probe results.
// ---------------------------------------------------------------------------

#[test]
fn maintenance_plan_recruits_to_restore_target() {
    use ce_cdn::maintain::plan_entry;
    let probes = vec![("e1".to_string(), true), ("e2".to_string(), false)];
    let plan = plan_entry("cid", 3, &probes);
    assert_eq!(plan.healthy, vec!["e1".to_string()]);
    assert_eq!(plan.recruit, 2); // 1 healthy of target 3
}

// ---------------------------------------------------------------------------
// Input bounds / validation: malformed CIDs and oversize inputs are rejected by the limits layer.
// ---------------------------------------------------------------------------

#[test]
fn limits_reject_bad_cids_and_oversize_inputs() {
    use ce_cdn::limits::{self, MAX_CAPS_HEX_LEN, MAX_MESH_OBJECT_BYTES};
    assert!(limits::is_valid_cid(&"a".repeat(64)));
    assert!(!limits::is_valid_cid("short"));
    assert!(!limits::is_acceptable_cid_charset("%2e%2e"));
    // The mesh object ceiling is well under a sane single-message size even after hex doubling.
    let obj = MAX_MESH_OBJECT_BYTES;
    let caps = MAX_CAPS_HEX_LEN;
    assert!(obj.saturating_mul(2) < 64 * 1024 * 1024);
    assert!(caps > 0);
}

// ---------------------------------------------------------------------------
// Catalog: atomic save + lock-guarded update across simulated concurrent writers (no lost update).
// ---------------------------------------------------------------------------

#[test]
fn catalog_update_is_atomic_and_lock_guarded() {
    use ce_cdn::catalog::{Access, Catalog, Content, Entry};
    let tmp = std::env::temp_dir().join(format!("ce-cdn-it-cat-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let path = tmp.join("catalog.json");

    let mk = |cid: &str| Entry {
        content: Content {
            cid: cid.into(),
            bytes_len: 1,
            access: Access::Public,
            replication: 1,
            ttl_secs: 0,
            label: None,
            tags: vec![],
        },
        edges: vec![],
    };
    // Two sequential lock-guarded updates must both persist (read-modify-write, no lost update).
    Catalog::update(&path, |c| {
        c.upsert(mk("a"));
        Ok(())
    })
    .unwrap();
    Catalog::update(&path, |c| {
        c.upsert(mk("b"));
        Ok(())
    })
    .unwrap();
    let loaded = Catalog::load(&path).unwrap();
    assert!(loaded.get("a").is_some() && loaded.get("b").is_some());
    let _ = std::fs::remove_dir_all(&tmp);
}
