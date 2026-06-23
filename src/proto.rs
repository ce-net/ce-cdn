//! ce-cdn wire protocol: the typed messages exchanged over the CE mesh on the `cdn/*` topics.
//!
//! An edge node both *caches* content (so it can serve it close to consumers) and *serves* it to
//! other nodes / HTTP clients. Private content is gated by a signed, attenuating `ce-cap` chain
//! the requester presents, which the edge host authorizes (rooted at its own key or a configured
//! org root) before serving. Abilities are opaque app-chosen strings:
//!   - [`ABILITY_CACHE`] (`cdn:cache`)  — ask an edge to fetch-and-cache an object (replication).
//!   - [`ABILITY_READ`]  (`cdn:read`)   — fetch private (cap-gated) content, whole or by range.
//!   - [`ABILITY_PURGE`] (`cdn:purge`)  — evict an object from an edge's cache.
//!
//! Public content needs no capability (`caps` is the empty string); the edge serves it to anyone,
//! which is exactly what a CDN should do. Content-addressing is the integrity proof: the object CID
//! *is* the manifest hash, and `get_object` re-verifies every chunk against its CID, so an edge can
//! never serve bytes the publisher did not publish, and a cache cannot be poisoned.
//!
//! Payloads are JSON, hex-encoded by the SDK's `request`/`reply` transport.

use serde::{Deserialize, Serialize};

/// Topic prefix for all ce-cdn mesh messages.
pub const TOPIC_PREFIX: &str = "cdn/";

/// `cdn/cache` topic: ask an edge to fetch-and-cache an object (it becomes a replica/edge for it).
pub const TOPIC_CACHE: &str = "cdn/cache";
/// `cdn/read` topic: fetch (possibly a range of) an object's bytes from an edge.
pub const TOPIC_READ: &str = "cdn/read";
/// `cdn/purge` topic: evict an object from an edge's cache.
pub const TOPIC_PURGE: &str = "cdn/purge";
/// `cdn/status` topic: a cheap "do you hold this CID?" probe.
pub const TOPIC_STATUS: &str = "cdn/status";

/// Ability: an edge caches an object only for a holder of a chain granting this.
pub const ABILITY_CACHE: &str = "cdn:cache";
/// Ability: an edge serves *private* (cap-gated) content only to a holder of this.
pub const ABILITY_READ: &str = "cdn:read";
/// Ability: drop a cached object from an edge.
pub const ABILITY_PURGE: &str = "cdn:purge";

/// The DHT service string an edge advertises for a given object, so consumers can discover which
/// edges hold (a copy of) it without a central tracker (`advertise_service` / `find_service`).
pub fn service_for(cid: &str) -> String {
    format!("cdn:{cid}")
}

/// The DHT service string advertised by any node willing to act as a CDN edge. A client ranks
/// these (atlas + on-chain history) when choosing which edges to replicate to.
pub const SERVICE_EDGE: &str = "cdn:edge";

/// `cdn/cache` request: ask an edge to fetch-and-hold an object so it can serve it locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheReq {
    /// Hex-encoded capability chain granting `cdn:cache` on the edge (empty for public objects an
    /// edge accepts open replication of — most edges still require a chain; the host decides).
    #[serde(default)]
    pub caps: String,
    /// The object CID to cache (manifest hash from `put_object`).
    pub cid: String,
    /// Total object size in bytes (informational; the edge enforces its own cache budget).
    #[serde(default)]
    pub bytes_len: u64,
    /// Requested cache TTL in seconds (`0` = the edge's default). The edge may clamp it.
    #[serde(default)]
    pub ttl_secs: u64,
}

/// `cdn/cache` reply.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheResp {
    /// Whether the edge accepted and now holds (or is fetching) the object.
    pub cached: bool,
    /// If cached, the bytes the edge now holds for this object.
    #[serde(default)]
    pub stored_bytes: u64,
    /// The TTL the edge actually applied (after any clamp).
    #[serde(default)]
    pub ttl_secs: u64,
    /// Human-readable reason when `cached == false`.
    #[serde(default)]
    pub reason: Option<String>,
}

/// `cdn/read` request: fetch an object's bytes from an edge, optionally a single byte range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadReq {
    /// Hex-encoded capability chain granting `cdn:read`. Empty for public content.
    #[serde(default)]
    pub caps: String,
    /// The object CID to read.
    pub cid: String,
    /// Optional HTTP-style `Range` header value (e.g. `"bytes=0-1023"`). `None` = whole object.
    #[serde(default)]
    pub range: Option<String>,
}

/// `cdn/read` reply. The bytes are hex-encoded (the SDK's request/reply carries opaque bytes; we
/// keep the envelope JSON for the metadata). The consumer re-verifies against the CID/manifest, so
/// a tampered reply is rejected client-side regardless of what the edge claims here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReadResp {
    /// Whether the edge served the bytes.
    pub ok: bool,
    /// Hex-encoded payload bytes (the whole object, or the requested range).
    #[serde(default)]
    pub bytes_hex: String,
    /// Total object size in bytes (so the consumer can render `Content-Range` for a partial read).
    #[serde(default)]
    pub total_len: u64,
    /// Whether `bytes_hex` is a partial range (HTTP 206) rather than the whole object (HTTP 200).
    #[serde(default)]
    pub partial: bool,
    /// Inclusive range start, when `partial`.
    #[serde(default)]
    pub range_start: u64,
    /// Inclusive range end, when `partial`.
    #[serde(default)]
    pub range_end: u64,
    /// Whether the bytes came from the edge's hot cache (vs. a cold origin fetch). Lets callers and
    /// dashboards observe cache effectiveness end to end.
    #[serde(default)]
    pub cache_hit: bool,
    /// Human-readable reason when `ok == false` (denied / not satisfiable / missing).
    #[serde(default)]
    pub reason: Option<String>,
}

/// `cdn/purge` request: ask an edge to evict an object from its cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurgeReq {
    #[serde(default)]
    pub caps: String,
    pub cid: String,
}

/// `cdn/purge` reply.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PurgeResp {
    /// True if the object was present and is now evicted.
    pub purged: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

/// `cdn/status` request: a lightweight "do you hold this CID right now?" probe (no bytes served).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReq {
    #[serde(default)]
    pub caps: String,
    pub cid: String,
}

/// `cdn/status` reply.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatusResp {
    /// True if the edge currently holds the object (fresh) and can serve it.
    pub held: bool,
    /// Size in bytes the edge holds for this CID (0 if not held).
    #[serde(default)]
    pub bytes: u64,
    /// Seconds until the cached copy expires (`0` if not held or no TTL info).
    #[serde(default)]
    pub ttl_remaining: u64,
}

/// A denial reply body the host returns (as the typed `reason`) when authorization fails. Kept as a
/// helper so the denial string is uniform across actions.
pub fn denied(reason: impl Into<String>) -> String {
    format!("denied: {}", reason.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_strings_are_cid_namespaced() {
        assert_eq!(service_for("abc123"), "cdn:abc123");
        assert_ne!(service_for("abc123"), SERVICE_EDGE);
    }

    #[test]
    fn cache_req_roundtrips_json() {
        let req = CacheReq {
            caps: "deadbeef".into(),
            cid: "f00d".into(),
            bytes_len: 4096,
            ttl_secs: 3600,
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let back: CacheReq = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.cid, "f00d");
        assert_eq!(back.ttl_secs, 3600);
    }

    #[test]
    fn read_req_defaults_caps_and_range() {
        // A public, whole-object read sets only `cid`.
        let r: ReadReq = serde_json::from_str(r#"{"cid":"abc"}"#).unwrap();
        assert_eq!(r.cid, "abc");
        assert_eq!(r.caps, "");
        assert!(r.range.is_none());
    }

    #[test]
    fn read_resp_defaults_when_minimal() {
        let r: ReadResp = serde_json::from_str(r#"{"ok":true,"bytes_hex":"00ff"}"#).unwrap();
        assert!(r.ok);
        assert_eq!(r.bytes_hex, "00ff");
        assert!(!r.partial);
        assert!(!r.cache_hit);
        assert!(r.reason.is_none());
    }

    #[test]
    fn denied_formats_uniformly() {
        assert_eq!(denied("no cap"), "denied: no cap");
    }

    #[test]
    fn purge_and_status_roundtrip() {
        let p = PurgeReq { caps: "c".into(), cid: "x".into() };
        let pj = serde_json::to_vec(&p).unwrap();
        let pb: PurgeReq = serde_json::from_slice(&pj).unwrap();
        assert_eq!(pb.cid, "x");

        let s: StatusResp = serde_json::from_str(r#"{"held":true,"bytes":10}"#).unwrap();
        assert!(s.held);
        assert_eq!(s.bytes, 10);
        assert_eq!(s.ttl_remaining, 0);
    }
}
