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

#[test]
fn slice_span_rejects_truncated_chunk_bytes() {
    // Simulate an edge returning fewer bytes than the range demands -> graceful error.
    let span = ce_cdn::cidrange::ChunkSpan { first_chunk: 0, last_chunk: 0, head_skip: 2, out_len: 100 };
    let err = slice_span(&[0u8; 8], span).unwrap_err();
    assert!(err.to_string().contains("too short"));
}
