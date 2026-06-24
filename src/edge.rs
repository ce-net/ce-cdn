//! The HTTP edge handler — pure response-shaping logic for "serve a blob by CID with cache headers".
//!
//! A CDN edge answers `GET /cdn/<cid>` (optionally with a `Range` header). This module is the
//! *decision core*: given the cache state, the requested range, and whether the caller is authorized,
//! it produces an [`EdgeResponse`] (status, headers, body span) — without owning a socket. The CLI's
//! HTTP server and the mesh host loop both drive this same function, so the header/status/range
//! behaviour is defined once and exhaustively tested.
//!
//! Header policy (CDN-correct because content is immutable / content-addressed):
//!   - On a hit: `Cache-Control: public, max-age=<ttl-remaining>, immutable`, plus `ETag: "<cid>"`,
//!     `Age: <age>`, `X-Cache: HIT`, and `Accept-Ranges: bytes`.
//!   - On a range hit: HTTP 206 + `Content-Range: bytes start-end/total`.
//!   - On an unsatisfiable range: HTTP 416 + `Content-Range: bytes */total`.
//!   - Private content with no/invalid capability: HTTP 403.
//!   - A CID the edge does not hold (and could not fetch): HTTP 404.

use crate::cache::EdgeCache;
use crate::cidrange::{ByteRange, RangeOutcome, parse_range};

/// The body the edge will serve: either the whole cached object or a contiguous span of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// Serve the full object bytes.
    Full(Vec<u8>),
    /// Serve a partial range (already sliced) plus the resolved inclusive range and total size.
    Partial { bytes: Vec<u8>, range: ByteRange, total: u64 },
    /// No body (error responses).
    None,
}

impl Body {
    /// The bytes to write (empty for `None`).
    pub fn bytes(&self) -> &[u8] {
        match self {
            Body::Full(b) => b,
            Body::Partial { bytes, .. } => bytes,
            Body::None => &[],
        }
    }
}

/// A fully-shaped edge response: HTTP status, ordered headers, and the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeResponse {
    /// HTTP status code (200, 206, 403, 404, 416).
    pub status: u16,
    /// Response headers as `(name, value)` pairs, in a stable order.
    pub headers: Vec<(String, String)>,
    /// The response body.
    pub body: Body,
}

impl EdgeResponse {
    /// Look up a header value by case-insensitive name (test/inspection helper).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Whether the requested object is public or requires a capability the caller must hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Anyone may fetch — no capability required.
    Public,
    /// Private — the caller must be authorized (the host already verified the `ce-cap` chain).
    Authorized,
    /// Private and the caller is **not** authorized — answer 403.
    Denied,
}

/// Build the standard cache/validator headers attached to every successful (200/206) response.
fn cache_headers(cid: &str, cache: &EdgeCache, now: u64, hit: bool) -> Vec<(String, String)> {
    let mut h = Vec::new();
    h.push(("Accept-Ranges".to_string(), "bytes".to_string()));
    // Content-addressed bytes never change for a CID -> a strong ETag and `immutable`.
    h.push(("ETag".to_string(), format!("\"{cid}\"")));
    h.push(("X-Cache".to_string(), if hit { "HIT".into() } else { "MISS".into() }));
    let max_age = match cache.ttl_remaining(cid, now) {
        Some(u64::MAX) => cache.default_ttl_secs().max(31_536_000), // effectively forever
        Some(secs) => secs,
        None => 0,
    };
    h.push((
        "Cache-Control".to_string(),
        format!("public, max-age={max_age}, immutable"),
    ));
    if let Some(age) = cache.age(cid, now) {
        h.push(("Age".to_string(), age.to_string()));
    }
    h
}

/// Serve `cid` from the cache, honoring an optional `Range` header and the access decision.
///
/// `bytes` is the object's full bytes as the edge currently holds them (the caller fetches/caches
/// before calling; this function does no network I/O). `range_header` is the raw HTTP `Range` value.
/// `hit` records whether the bytes came from the hot cache (HIT) or a cold origin fetch (MISS) — it
/// only affects the `X-Cache` header, not correctness.
///
/// Returns the shaped [`EdgeResponse`]. Never panics on malformed input: a bad `Range` degrades to
/// a full 200 (RFC 7233), an out-of-bounds range yields 416, and denied access yields 403.
pub fn serve(
    cid: &str,
    bytes: &[u8],
    range_header: Option<&str>,
    access: Access,
    cache: &EdgeCache,
    now: u64,
    hit: bool,
) -> EdgeResponse {
    if access == Access::Denied {
        return EdgeResponse {
            status: 403,
            headers: vec![("Content-Type".into(), "text/plain".into())],
            body: Body::None,
        };
    }

    let total = bytes.len() as u64;
    match parse_range(range_header, total) {
        RangeOutcome::Full => {
            let mut headers = cache_headers(cid, cache, now, hit);
            headers.push(("Content-Length".into(), total.to_string()));
            EdgeResponse { status: 200, headers, body: Body::Full(bytes.to_vec()) }
        }
        RangeOutcome::Partial(r) => {
            let slice = bytes[r.start as usize..=r.end as usize].to_vec();
            let mut headers = cache_headers(cid, cache, now, hit);
            headers.push(("Content-Range".into(), r.content_range_header(total)));
            headers.push(("Content-Length".into(), r.len().to_string()));
            EdgeResponse {
                status: 206,
                headers,
                body: Body::Partial { bytes: slice, range: r, total },
            }
        }
        RangeOutcome::Unsatisfiable => EdgeResponse {
            status: 416,
            headers: vec![
                ("Content-Range".into(), format!("bytes */{total}")),
                ("Content-Type".into(), "text/plain".into()),
            ],
            body: Body::None,
        },
    }
}

/// Does an `If-None-Match` header value match the strong ETag `"<cid>"` for this object? Because a
/// CID is immutable, a matching `If-None-Match` means the client already has the exact bytes, so the
/// edge can answer `304 Not Modified` with no body — the single biggest CDN bandwidth win, and free
/// here. Accepts a comma-separated list of entity-tags and the wildcard `*` (RFC 7232 §3.2). Weak
/// validators (`W/"..."`) are compared on the opaque tag only.
pub fn if_none_match_matches(header: Option<&str>, cid: &str) -> bool {
    let Some(h) = header else { return false };
    let etag = format!("\"{cid}\"");
    h.split(',').any(|raw| {
        let t = raw.trim();
        let t = t.strip_prefix("W/").unwrap_or(t).trim();
        t == "*" || t == etag
    })
}

/// A `304 Not Modified` response for `cid`: the client's cached copy is still valid (immutable CID),
/// so re-send only the validators and cache directives, never the body.
pub fn not_modified(cid: &str, cache: &EdgeCache, now: u64) -> EdgeResponse {
    let headers = cache_headers(cid, cache, now, true);
    EdgeResponse { status: 304, headers, body: Body::None }
}

/// The response for a CID the edge does not hold and could not obtain — a plain 404.
pub fn not_found(cid: &str) -> EdgeResponse {
    EdgeResponse {
        status: 404,
        headers: vec![
            ("Content-Type".into(), "text/plain".into()),
            ("X-Cache".into(), "MISS".into()),
            ("ETag".into(), format!("\"{cid}\"")),
        ],
        body: Body::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache_with(cid: &str, bytes: Vec<u8>, ttl: u64, now: u64) -> EdgeCache {
        let mut c = EdgeCache::new(1 << 20, ttl);
        c.insert(cid, bytes, now);
        c
    }

    #[test]
    fn full_hit_has_cache_headers() {
        let bytes = b"hello world".to_vec();
        let c = cache_with("cid1", bytes.clone(), 3600, 0);
        let resp = serve("cid1", &bytes, None, Access::Public, &c, 0, true);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, Body::Full(bytes.clone()));
        assert_eq!(resp.header("X-Cache"), Some("HIT"));
        assert_eq!(resp.header("ETag"), Some("\"cid1\""));
        assert_eq!(resp.header("Accept-Ranges"), Some("bytes"));
        assert_eq!(resp.header("Content-Length"), Some("11"));
        assert!(resp.header("Cache-Control").unwrap().contains("immutable"));
        assert!(resp.header("Cache-Control").unwrap().contains("max-age=3600"));
    }

    #[test]
    fn miss_marks_x_cache_miss() {
        let bytes = b"abc".to_vec();
        let c = cache_with("cid1", bytes.clone(), 60, 0);
        let resp = serve("cid1", &bytes, None, Access::Public, &c, 0, false);
        assert_eq!(resp.header("X-Cache"), Some("MISS"));
    }

    #[test]
    fn range_request_yields_206_with_content_range() {
        let bytes: Vec<u8> = (0..100u8).collect();
        let c = cache_with("cid1", bytes.clone(), 60, 0);
        let resp = serve("cid1", &bytes, Some("bytes=10-19"), Access::Public, &c, 0, true);
        assert_eq!(resp.status, 206);
        assert_eq!(resp.header("Content-Range"), Some("bytes 10-19/100"));
        assert_eq!(resp.header("Content-Length"), Some("10"));
        match &resp.body {
            Body::Partial { bytes, range, total } => {
                assert_eq!(bytes, &(10..20u8).collect::<Vec<u8>>());
                assert_eq!(*range, ByteRange { start: 10, end: 19 });
                assert_eq!(*total, 100);
            }
            other => panic!("expected partial body, got {other:?}"),
        }
    }

    #[test]
    fn unsatisfiable_range_yields_416() {
        let bytes = vec![0u8; 50];
        let c = cache_with("cid1", bytes.clone(), 60, 0);
        let resp = serve("cid1", &bytes, Some("bytes=100-200"), Access::Public, &c, 0, true);
        assert_eq!(resp.status, 416);
        assert_eq!(resp.header("Content-Range"), Some("bytes */50"));
        assert_eq!(resp.body, Body::None);
    }

    #[test]
    fn malformed_range_degrades_to_full_200() {
        let bytes = vec![7u8; 8];
        let c = cache_with("cid1", bytes.clone(), 60, 0);
        let resp = serve("cid1", &bytes, Some("bytes=garbage"), Access::Public, &c, 0, true);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, Body::Full(bytes));
    }

    #[test]
    fn denied_access_yields_403() {
        let bytes = vec![1u8; 4];
        let c = cache_with("cid1", bytes.clone(), 60, 0);
        let resp = serve("cid1", &bytes, None, Access::Denied, &c, 0, true);
        assert_eq!(resp.status, 403);
        assert_eq!(resp.body, Body::None);
    }

    #[test]
    fn authorized_private_serves_like_public() {
        let bytes = b"secret".to_vec();
        let c = cache_with("cid1", bytes.clone(), 60, 0);
        let resp = serve("cid1", &bytes, None, Access::Authorized, &c, 0, true);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, Body::Full(bytes));
    }

    #[test]
    fn not_found_is_404() {
        let resp = not_found("missingcid");
        assert_eq!(resp.status, 404);
        assert_eq!(resp.header("X-Cache"), Some("MISS"));
        assert_eq!(resp.body, Body::None);
    }

    #[test]
    fn age_header_reflects_insertion_time() {
        let bytes = vec![0u8; 4];
        let c = cache_with("cid1", bytes.clone(), 3600, 100); // inserted at t=100
        let resp = serve("cid1", &bytes, None, Access::Public, &c, 150, true);
        assert_eq!(resp.header("Age"), Some("50"));
        // ttl remaining at t=150 is 3600-(150-100)=3550
        assert!(resp.header("Cache-Control").unwrap().contains("max-age=3550"));
    }

    #[test]
    fn if_none_match_matches_strong_weak_and_wildcard() {
        assert!(if_none_match_matches(Some("\"cid1\""), "cid1"));
        assert!(if_none_match_matches(Some("W/\"cid1\""), "cid1"));
        assert!(if_none_match_matches(Some("*"), "anything"));
        assert!(if_none_match_matches(Some("\"x\", \"cid1\", \"y\""), "cid1"));
        assert!(!if_none_match_matches(Some("\"other\""), "cid1"));
        assert!(!if_none_match_matches(None, "cid1"));
    }

    #[test]
    fn not_modified_has_validators_and_no_body() {
        let bytes = vec![0u8; 4];
        let c = cache_with("cid1", bytes, 3600, 0);
        let resp = not_modified("cid1", &c, 0);
        assert_eq!(resp.status, 304);
        assert_eq!(resp.body, Body::None);
        assert_eq!(resp.header("ETag"), Some("\"cid1\""));
        assert!(resp.header("Cache-Control").unwrap().contains("immutable"));
    }

    #[test]
    fn never_expiring_entry_reports_long_max_age() {
        let bytes = vec![0u8; 4];
        let c = cache_with("cid1", bytes.clone(), 0, 0); // 0 TTL = never expires
        let resp = serve("cid1", &bytes, None, Access::Public, &c, 0, true);
        // max-age should be a large (>= 1 year) value, not 0.
        let cc = resp.header("Cache-Control").unwrap();
        let max_age: u64 = cc
            .split("max-age=")
            .nth(1)
            .and_then(|s| s.split([',', ' ']).next())
            .and_then(|s| s.parse().ok())
            .unwrap();
        assert!(max_age >= 31_536_000, "max-age was {max_age}");
    }
}
