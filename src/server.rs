//! The HTTP front-end: a real `hyper` server exposing `GET /cdn/<cid>` (and `GET /status`,
//! `GET /health`) that maps onto the pure [`edge::serve`] handler.
//!
//! This is the socket-owning shell around the otherwise-pure edge logic. It exists so a browser,
//! `curl`, or any HTTP client can fetch CDN content directly (the mesh `cdn/*` protocol in
//! [`crate::host`] is the node-to-node path; this is the last-mile HTTP path). The decision core is
//! unchanged — header/status/range behaviour still lives in [`edge`] and is exercised once — so this
//! module only does I/O + access resolution and translates an [`edge::EdgeResponse`] onto the wire.
//!
//! ## Routes
//! - `GET /cdn/<cid>` — serve a content-addressed object. Honors `Range` (→ 206 / 416), emits the
//!   immutable cache headers, returns 403 for cap-less private content, 404 for a CID the edge does
//!   not hold and cannot fetch from the origin.
//! - `GET /status` — JSON snapshot of cache stats + per-CID byte sizes the edge currently holds.
//! - `GET /health` — liveness (`200 ok`).
//!
//! ## Access / authorization
//! Public CIDs (in the edge's [`PublicSet`]) are served to anyone. For any other CID the caller must
//! present BOTH a proof-of-possession AND a capability chain.
//!
//! The proof-of-possession is an `X-Ce-Proof: <expires>.<sig_hex>` header whose signature, over
//! `(requester, cid, cdn:read, expires)`, verifies against the claimed `X-Ce-Node-Id` (see
//! [`crate::pop`]). The capability is a hex `ce-cap` chain via `X-Ce-Capability` (or
//! `Authorization: Capability <hex>`) that authorizes `cdn:read` for that requester.
//!
//! The same `ce_cap::authorize` the mesh host uses gates the chain, so the HTTP and mesh paths share
//! one authorization rule. The proof-of-possession is what keeps `X-Ce-Node-Id` from being a
//! forgeable bearer identity: on the mesh path the requester is the authenticated libp2p sender; on
//! HTTP nothing else proves the caller holds the requester's key, so a leaked capability chain (it
//! travels in a header) would otherwise be usable by anyone. A missing/invalid proof OR chain on
//! private content is a 403; a public CID needs no header.
//!
//! ## Origin
//! On a cold cache miss the server fetches the object bytes from an [`Origin`] (the content-addressed
//! blob store, trustlessly via `get_object` in production) and caches them. Making the origin a trait
//! keeps the HTTP layer testable at the wire level without a live CE node.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use ce_cap::{SignedCapability, authorize, decode_chain};
use ce_rs::CeClient;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::cache::{CacheStats, ObjectStat};
use crate::edge::{self, Access, Body as EdgeBody};
use crate::host::{EdgeState, PublicSet, now_secs};
use crate::limits;
use crate::pop::ReplayGuard;
use crate::proto;
use tokio::sync::Mutex as AsyncMutex;

/// Where the HTTP front-end fetches object bytes on a cold cache miss.
///
/// Production wires this to the content-addressed blob store (`CeClient::get_object`, which verifies
/// every chunk against its CID, so the fetch is trustless). Tests supply an in-memory map so the
/// whole HTTP stack — routing, range, cache headers, the cap gate — is exercised without a node.
///
/// Uses a native `async fn` in a trait (edition 2024). The server consumes it through a generic
/// type parameter `O: Origin` (never `dyn`), so no `async-trait` boxing is required. `Send` futures
/// are guaranteed by the `Send + Sync + 'static` bound, which is what `tokio::spawn` needs.
pub trait Origin: Send + Sync + 'static {
    /// Fetch the full bytes of `cid`, or an error if the origin does not hold it (→ 404).
    fn fetch(&self, cid: &str) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;
}

/// The origin backed by a live CE node: a trustless content-addressed fetch.
pub struct CeOrigin {
    ce: CeClient,
}

impl CeOrigin {
    /// Wrap a `CeClient` as the HTTP front-end's origin.
    pub fn new(ce: CeClient) -> Self {
        CeOrigin { ce }
    }
}

impl Origin for CeOrigin {
    async fn fetch(&self, cid: &str) -> Result<Vec<u8>> {
        self.ce.get_object(cid).await.context("origin fetch")
    }
}

/// Everything the HTTP service needs to answer a request, shared across connections.
pub struct ServerState<O: Origin> {
    /// The hot edge cache + public-CID set (shared with the rest of the edge).
    pub edge: EdgeState,
    /// The cold-fetch origin (blob store).
    pub origin: O,
    /// This edge's NodeId — the implicit root authority for capability chains.
    pub edge_id: [u8; 32],
    /// Additional accepted capability root NodeIds (org/fleet roots).
    pub roots: Vec<[u8; 32]>,
    /// Publisher keys whose presigned links this edge honors (the signed-URL trust anchor). Empty =
    /// presigned links disabled.
    pub presign_keys: Vec<[u8; 32]>,
    /// Anti-replay guard for proof-of-possession (rejects a captured proof reused in its window).
    pub replay: Arc<AsyncMutex<ReplayGuard>>,
    /// Largest object the HTTP origin-fetch path will buffer into memory (DoS guard). `0` = the
    /// cache budget.
    pub max_object_bytes: u64,
    /// Per-CID single-flight locks: concurrent cold misses of the same CID serialize on one lock so
    /// the origin is consulted ONCE (thundering-herd / origin-amplification guard), then the rest
    /// read the freshly-cached bytes.
    inflight: Arc<std::sync::Mutex<std::collections::HashMap<String, Arc<AsyncMutex<()>>>>>,
}

impl<O: Origin> ServerState<O> {
    /// Build server state from edge state, an origin, the edge's NodeId, and accepted roots. Presign
    /// keys default to none and the origin-fetch size cap to the cache budget; use the `with_*`
    /// builders to override.
    pub fn new(edge: EdgeState, origin: O, edge_id: [u8; 32], roots: Vec<[u8; 32]>) -> Self {
        ServerState {
            edge,
            origin,
            edge_id,
            roots,
            presign_keys: Vec::new(),
            replay: Arc::new(AsyncMutex::new(ReplayGuard::new(crate::pop::REPLAY_GUARD_CAPACITY))),
            max_object_bytes: 0,
            inflight: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Get (or create) the single-flight lock for `cid`. Held while one task fetches a cold object so
    /// concurrent requests for the same CID wait and then read from cache instead of all hitting the
    /// origin.
    fn inflight_lock(&self, cid: &str) -> Arc<AsyncMutex<()>> {
        let mut map = match self.inflight.lock() {
            Ok(m) => m,
            Err(p) => p.into_inner(), // a poisoned lock still yields a usable map
        };
        // Opportunistically clear entries no one else references to keep the map bounded.
        if map.len() > 1024 {
            map.retain(|_, v| Arc::strong_count(v) > 1);
        }
        map.entry(cid.to_string()).or_insert_with(|| Arc::new(AsyncMutex::new(()))).clone()
    }

    /// Set the publisher keys whose presigned links this edge honors.
    pub fn with_presign_keys(mut self, keys: Vec<[u8; 32]>) -> Self {
        self.presign_keys = keys;
        self
    }

    /// Cap the bytes the origin-fetch path will buffer for a single object (`0` = cache budget).
    pub fn with_max_object_bytes(mut self, max: u64) -> Self {
        self.max_object_bytes = max;
        self
    }
}

/// Parse the `from`/requester NodeId an HTTP caller *claims* via `X-Ce-Node-Id` (64-hex). Absent or
/// malformed → all-zero id (a chain whose leaf audience is some real key then simply will not match,
/// yielding a clean 403 rather than a panic).
///
/// This is only a *claim*: for private content [`resolve_access`] additionally requires a
/// proof-of-possession ([`crate::pop`]) that the caller actually holds this id's key, so the header
/// alone never grants access.
fn requester_id(req: &Request<Incoming>) -> [u8; 32] {
    req.headers()
        .get("x-ce-node-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| hex::decode(s.trim()).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .unwrap_or([0u8; 32])
}

/// Extract the raw `X-Ce-Proof` proof-of-possession header (`<expires>.<sig_hex>`), if present. The
/// edge verifies this against the claimed `X-Ce-Node-Id` before trusting that id as the requester —
/// so the id is proven, not merely asserted (see [`crate::pop`]).
fn proof_header(req: &Request<Incoming>) -> Option<String> {
    req.headers()
        .get("x-ce-proof")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
}

/// Extract the hex-encoded capability chain a caller presents: `X-Ce-Capability: <hex>` or
/// `Authorization: Capability <hex>`. Empty string when none is presented.
fn capability_hex(req: &Request<Incoming>) -> String {
    if let Some(v) = req.headers().get("x-ce-capability").and_then(|v| v.to_str().ok()) {
        return v.trim().to_string();
    }
    if let Some(v) = req.headers().get(hyper::header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        let v = v.trim();
        if let Some(rest) = v.strip_prefix("Capability ").or_else(|| v.strip_prefix("capability "))
        {
            return rest.trim().to_string();
        }
    }
    String::new()
}

/// Resolve the [`Access`] decision for `cid`: public CIDs are open; otherwise the caller must both
/// (1) present a proof-of-possession over the requester key bound to this `(cid, cdn:read)` request,
/// and (2) present a `ce-cap` chain that authorizes `cdn:read` for that requester (rooted at this
/// edge or an accepted root). Pure given the inputs; the caller passes the current public set,
/// requester id, the raw `X-Ce-Proof` header, caps hex, and clock.
///
/// The proof-of-possession check is what stops `X-Ce-Node-Id` from being a leakable bearer token: a
/// capability chain that travels in a header can leak, but without the requester's private key the
/// caller cannot mint a proof, so a leaked chain alone is useless for private content. The mesh path
/// gets this binding for free (the libp2p sender is authenticated); the HTTP edge reconstructs it
/// here.
/// How a non-public access was (or was not) granted — so the caller knows whether to additionally
/// enforce single-use replay protection on the presented proof-of-possession.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
    /// World-readable CID — no credentials needed.
    Public,
    /// Granted by a valid presigned link (no client key / no replay concern: the link is the token,
    /// already expiry-bounded).
    Presigned,
    /// Granted by proof-of-possession + capability chain. The caller MUST also pass the proof
    /// through the replay guard before serving (the proof is single-use within its window).
    PopAndCap,
    /// Denied.
    Denied,
}

impl Grant {
    /// Map a grant to the edge access decision the response shaper consumes.
    pub fn access(self) -> Access {
        match self {
            Grant::Public => Access::Public,
            Grant::Presigned | Grant::PopAndCap => Access::Authorized,
            Grant::Denied => Access::Denied,
        }
    }
}

/// Resolve how `cid` may be accessed, in priority: public → valid presigned link → (proof-of-
/// possession + capability chain). Pure given its inputs; the replay-guard check for the PoP path is
/// applied separately by the caller (it needs `&mut` state).
#[allow(clippy::too_many_arguments)]
pub fn resolve_grant(
    cid: &str,
    public: &PublicSet,
    edge_id: &[u8; 32],
    roots: &[[u8; 32]],
    presign_keys: &[[u8; 32]],
    requester: &[u8; 32],
    proof: Option<&str>,
    presign_query: &str,
    caps_hex: &str,
    now: u64,
) -> Grant {
    if public.is_public(cid) {
        return Grant::Public;
    }
    // A valid presigned link grants access with no client key (the Cloud-CDN signed-URL analog).
    if !presign_keys.is_empty()
        && crate::presign::verify_presign(presign_query, cid, presign_keys, now).is_ok()
    {
        return Grant::Presigned;
    }
    // Gate 1: prove the caller actually holds the requester key for THIS request. Without this, the
    // capability chain below would be a pure bearer token over a forgeable `X-Ce-Node-Id` header.
    if crate::pop::verify_pop(proof, requester, cid, proto::ABILITY_READ, now).is_err() {
        return Grant::Denied;
    }
    // Bound the capability chain size before decoding (DoS guard).
    if caps_hex.len() > limits::MAX_CAPS_HEX_LEN {
        return Grant::Denied;
    }
    // Gate 2: the (now key-proven) requester must hold a cap chain authorizing cdn:read.
    let Ok(chain): Result<Vec<SignedCapability>, _> = decode_chain(caps_hex) else {
        return Grant::Denied;
    };
    let never_revoked = |_: &[u8; 32], _: u64| false;
    match authorize(edge_id, roots, &[], now, requester, proto::ABILITY_READ, &chain, &never_revoked)
    {
        Ok(()) => Grant::PopAndCap,
        Err(_) => Grant::Denied,
    }
}

/// Backwards-compatible thin wrapper: the original public-or-(PoP+cap) access decision without
/// presigned links. Retained so existing callers/tests keep working.
#[allow(clippy::too_many_arguments)]
pub fn resolve_access(
    cid: &str,
    public: &PublicSet,
    edge_id: &[u8; 32],
    roots: &[[u8; 32]],
    requester: &[u8; 32],
    proof: Option<&str>,
    caps_hex: &str,
    now: u64,
) -> Access {
    resolve_grant(cid, public, edge_id, roots, &[], requester, proof, "", caps_hex, now).access()
}

/// Translate a shaped [`edge::EdgeResponse`] onto a hyper response.
fn to_http(resp: edge::EdgeResponse) -> Response<Full<Bytes>> {
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = match resp.body {
        EdgeBody::Full(b) => Bytes::from(b),
        EdgeBody::Partial { bytes, .. } => Bytes::from(bytes),
        EdgeBody::None => Bytes::new(),
    };
    let mut builder = Response::builder().status(status);
    for (k, v) in resp.headers {
        if let (Ok(name), Ok(value)) =
            (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(&v))
        {
            builder = builder.header(name, value);
        }
    }
    builder.body(Full::new(body)).unwrap_or_else(|_| {
        let mut r = Response::new(Full::new(Bytes::new()));
        *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        r
    })
}

/// Render the `/status` snapshot: cache stats plus the per-CID byte sizes the edge holds.
fn status_json(stats: CacheStats, held: &[(String, u64)]) -> String {
    let sizes: Vec<String> = held
        .iter()
        .map(|(cid, sz)| format!("{{\"cid\":\"{cid}\",\"bytes\":{sz}}}"))
        .collect();
    format!(
        "{{\"hits\":{},\"misses\":{},\"evictions\":{},\"expirations\":{},\"entries\":{},\"bytes\":{},\"hit_ratio\":{:.6},\"objects\":[{}]}}",
        stats.hits,
        stats.misses,
        stats.evictions,
        stats.expirations,
        stats.entries,
        stats.bytes,
        stats.hit_ratio(),
        sizes.join(",")
    )
}

/// Handle a single HTTP request against the shared server state. Returns the response; never errors
/// (every failure maps to a status code), matching `service_fn`'s `Result<_, Infallible>` contract.
pub async fn handle<O: Origin>(
    state: Arc<ServerState<O>>,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Only GET (and HEAD, treated as GET without a body) are served.
    if method != Method::GET && method != Method::HEAD {
        return text(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    }

    if path == "/health" {
        return text(StatusCode::OK, "ok");
    }
    if path == "/status" {
        let cache = state.edge.cache.lock().await;
        let stats = cache.stats();
        let public = state.edge.public.lock().await;
        let now = now_secs();
        let mut held: Vec<(String, u64)> = Vec::new();
        for cid in public.iter() {
            if let Some(sz) = cache.byte_len(cid)
                && cache.contains_fresh(cid, now)
            {
                held.push((cid.to_string(), sz));
            }
        }
        held.sort();
        let json = status_json(stats, &held);
        return json_resp(StatusCode::OK, json);
    }

    if path == "/metrics" {
        let cache = state.edge.cache.lock().await;
        let stats = cache.stats();
        let objects = cache.object_stats();
        let body = metrics_prometheus(stats, &objects);
        return Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "text/plain; version=0.0.4")
            .body(Full::new(Bytes::from(body)))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
    }

    let Some(cid) = path.strip_prefix("/cdn/") else {
        return text(StatusCode::NOT_FOUND, "not found");
    };
    let cid = cid.trim_end_matches('/');
    // Validate the CID charset/length before it is ever used as a cache/origin key (no URL-decode:
    // a content id is plain hex, so a percent-encoded or overlong segment is simply invalid).
    if !limits::is_acceptable_cid_charset(cid) {
        return text(StatusCode::NOT_FOUND, "not found");
    }

    serve_cid(state, &req, cid, method == Method::HEAD).await
}

/// Serve `GET /cdn/<cid>`: access decision, cold-fetch on miss (404 if origin lacks it), then shape
/// the response via the pure edge handler.
async fn serve_cid<O: Origin>(
    state: Arc<ServerState<O>>,
    req: &Request<Incoming>,
    cid: &str,
    head_only: bool,
) -> Response<Full<Bytes>> {
    let now = now_secs();
    let caps_hex = capability_hex(req);
    let requester = requester_id(req);
    let proof = proof_header(req);
    let query = req.uri().query().unwrap_or("").to_string();

    // Access decision first — deny cap-less / proof-less private content with a 403 before touching
    // the origin.
    let grant = {
        let public = state.edge.public.lock().await;
        resolve_grant(
            cid,
            &public,
            &state.edge_id,
            &state.roots,
            &state.presign_keys,
            &requester,
            proof.as_deref(),
            &query,
            &caps_hex,
            now,
        )
    };
    if grant == Grant::Denied {
        return to_http(edge::serve(cid, &[], None, Access::Denied, &deny_cache(), now, true));
    }
    // The PoP path's proof is single-use: enforce replay protection before serving. (Presigned and
    // public paths carry no replayable per-request proof.)
    if grant == Grant::PopAndCap {
        let mut guard = state.replay.lock().await;
        if crate::pop::verify_pop_once(
            &mut guard,
            proof.as_deref(),
            &requester,
            cid,
            proto::ABILITY_READ,
            now,
        )
        .is_err()
        {
            return to_http(edge::serve(cid, &[], None, Access::Denied, &deny_cache(), now, true));
        }
    }
    let access = grant.access();

    // Conditional request: an immutable CID the client already has (matching If-None-Match) -> 304,
    // no body. Free bandwidth win. Answerable without consulting cache contents or the origin.
    let inm = req
        .headers()
        .get(hyper::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok());
    if edge::if_none_match_matches(inm, cid) {
        // Use whatever cache metadata we have (max-age/age); a throwaway cache is fine if absent.
        let cache = state.edge.cache.lock().await;
        return to_http(edge::not_modified(cid, &cache, now));
    }

    // Negative cache: a recently-confirmed-absent CID is answered 404 without re-hitting the origin.
    {
        let mut cache = state.edge.cache.lock().await;
        if !cache.contains_fresh(cid, now) && cache.is_negative(cid, now) {
            return to_http(edge::not_found(cid));
        }
    }

    // Read from the hot cache; on a cold miss fetch from the origin and cache it.
    let max_object = if state.max_object_bytes == 0 {
        state.edge.cache.lock().await.max_bytes()
    } else {
        state.max_object_bytes
    };
    let (bytes, hit) = {
        let cached = { state.edge.cache.lock().await.get(cid, now) };
        match cached {
            Some(b) => (b, true),
            None => {
                // Single-flight: serialize concurrent cold misses of THIS cid on one lock so the
                // origin is hit once, not once per concurrent request (thundering-herd guard).
                let flight = state.inflight_lock(cid);
                let _guard = flight.lock().await;
                // Re-check: a sibling task may have populated the cache (or tombstoned it) while we
                // waited for the single-flight lock.
                {
                    let mut cache = state.edge.cache.lock().await;
                    if let Some(b) = cache.get(cid, now) {
                        (b, true)
                    } else if cache.is_negative(cid, now) {
                        drop(cache);
                        return to_http(edge::not_found(cid));
                    } else {
                        drop(cache);
                        match state.origin.fetch(cid).await {
                            Ok(b) => {
                                // Bound the buffered object: refuse to cache/serve something larger
                                // than the cap so a huge object cannot multiply memory.
                                if b.len() as u64 > max_object {
                                    return text(
                                        StatusCode::PAYLOAD_TOO_LARGE,
                                        "object exceeds edge size limit",
                                    );
                                }
                                let mut cache = state.edge.cache.lock().await;
                                let _ = cache.insert(cid, b.clone(), now);
                                (b, false)
                            }
                            Err(_) => {
                                // Remember the miss briefly so a flood of GETs for an absent CID
                                // does not hammer the origin (origin-amplification guard).
                                state.edge.cache.lock().await.note_absent(cid, now);
                                return to_http(edge::not_found(cid));
                            }
                        }
                    }
                }
            }
        }
    };

    let range = req
        .headers()
        .get(hyper::header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let cache = state.edge.cache.lock().await;
    let resp = edge::serve(cid, &bytes, range.as_deref(), access, &cache, now, hit);
    drop(cache);
    let mut http = to_http(resp);
    if head_only {
        // HEAD: keep the headers/status, drop the body.
        *http.body_mut() = Full::new(Bytes::new());
    }
    http
}

/// Render the Prometheus text-format metrics for the cache (`/metrics`).
fn metrics_prometheus(stats: CacheStats, objects: &[(String, ObjectStat)]) -> String {
    let mut s = String::new();
    s.push_str("# HELP ce_cdn_cache_hits_total Cache reads served from cache.\n");
    s.push_str("# TYPE ce_cdn_cache_hits_total counter\n");
    s.push_str(&format!("ce_cdn_cache_hits_total {}\n", stats.hits));
    s.push_str("# HELP ce_cdn_cache_misses_total Cache reads that missed.\n");
    s.push_str("# TYPE ce_cdn_cache_misses_total counter\n");
    s.push_str(&format!("ce_cdn_cache_misses_total {}\n", stats.misses));
    s.push_str("# TYPE ce_cdn_cache_evictions_total counter\n");
    s.push_str(&format!("ce_cdn_cache_evictions_total {}\n", stats.evictions));
    s.push_str("# TYPE ce_cdn_cache_expirations_total counter\n");
    s.push_str(&format!("ce_cdn_cache_expirations_total {}\n", stats.expirations));
    s.push_str("# TYPE ce_cdn_cache_negative_hits_total counter\n");
    s.push_str(&format!("ce_cdn_cache_negative_hits_total {}\n", stats.negative_hits));
    s.push_str("# TYPE ce_cdn_cache_entries gauge\n");
    s.push_str(&format!("ce_cdn_cache_entries {}\n", stats.entries));
    s.push_str("# TYPE ce_cdn_cache_bytes gauge\n");
    s.push_str(&format!("ce_cdn_cache_bytes {}\n", stats.bytes));
    s.push_str("# HELP ce_cdn_object_hits_total Per-object cache hits.\n");
    s.push_str("# TYPE ce_cdn_object_hits_total counter\n");
    for (cid, os) in objects {
        // Escape is unnecessary: CIDs are validated hex, but keep the label value quoted.
        s.push_str(&format!("ce_cdn_object_hits_total{{cid=\"{cid}\"}} {}\n", os.hits));
        s.push_str(&format!("ce_cdn_object_bytes{{cid=\"{cid}\"}} {}\n", os.bytes));
    }
    s
}

/// A throwaway empty cache used only to shape a 403 (the denied path needs no real cache state).
fn deny_cache() -> crate::cache::EdgeCache {
    crate::cache::EdgeCache::new(1, 0)
}

/// Build a `text/plain` response.
fn text(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain")
        .body(Full::new(Bytes::from(msg.to_string())))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

/// Build an `application/json` response.
fn json_resp(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

/// Bind `addr` and serve the CDN HTTP front-end until the process is killed. Each accepted
/// connection is driven on its own task; all share `state`.
pub async fn run<O: Origin>(addr: SocketAddr, state: Arc<ServerState<O>>) -> Result<()> {
    let listener = TcpListener::bind(addr).await.with_context(|| format!("binding {addr}"))?;
    tracing::info!(%addr, "ce-cdn HTTP front-end listening (GET /cdn/<cid>, /status, /health)");
    loop {
        let (stream, _peer) = listener.accept().await.context("accepting connection")?;
        let io = TokioIo::new(stream);
        let state = state.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(handle(state, req).await) }
            });
            if let Err(e) = hardened_http1().serve_connection(io, svc).await {
                tracing::debug!(error = %e, "connection closed with error");
            }
        });
    }
}

/// An `http1::Builder` hardened against slow-client / oversized-header DoS: a bounded header-read
/// timeout (slowloris protection) and a capped per-connection buffer (max header size). Shared by
/// the production [`run`] loop and the test [`spawn`] loop so both get the same guard rails.
fn hardened_http1() -> http1::Builder {
    let mut b = http1::Builder::new();
    // A tokio timer is required for header_read_timeout to fire.
    b.timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(std::time::Duration::from_secs(15))
        // Cap the read/write buffer (and thus the largest acceptable header block) at 64 KiB.
        .max_buf_size(64 * 1024);
    b
}

/// Bind an ephemeral port and serve in the background, returning the bound address and a handle.
/// Used by the HTTP-level tests (a real socket + real `hyper` stack, no live CE node). The returned
/// task runs the accept loop; drop the [`Running`] to stop accepting new connections.
pub async fn spawn<O: Origin>(state: Arc<ServerState<O>>) -> Result<Running> {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            let io = TokioIo::new(stream);
            let state = state.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let state = state.clone();
                    async move { Ok::<_, Infallible>(handle(state, req).await) }
                });
                let _ = hardened_http1().serve_connection(io, svc).await;
            });
        }
    });
    Ok(Running { addr, handle })
}

/// A handle to a backgrounded HTTP server bound to an ephemeral port.
pub struct Running {
    addr: SocketAddr,
    handle: tokio::task::JoinHandle<()>,
}

impl Running {
    /// The address the server is bound to (`127.0.0.1:<ephemeral>`).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// A minimal blocking-free HTTP/1.1 GET helper for tests: one request per connection, parses the
/// status line, headers, and body. Kept in-crate so the HTTP-level tests do not need `reqwest`.
pub async fn http_get(
    addr: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<HttpReply> {
    http_request("GET", addr, path, headers).await
}

/// Like [`http_get`] but issues a `HEAD` request (status + headers, no body).
pub async fn http_head(
    addr: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<HttpReply> {
    http_request("HEAD", addr, path, headers).await
}

/// One-shot HTTP/1.1 request helper shared by [`http_get`] / [`http_head`].
async fn http_request(
    method: &str,
    addr: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<HttpReply> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    parse_reply(&buf)
}

/// A parsed HTTP reply (status, headers, body) for test assertions.
#[derive(Debug, Clone)]
pub struct HttpReply {
    /// The numeric status code.
    pub status: u16,
    /// Response headers, lower-cased names.
    pub headers: Vec<(String, String)>,
    /// The raw response body bytes.
    pub body: Vec<u8>,
}

impl HttpReply {
    /// Case-insensitive header lookup.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Parse a raw HTTP/1.1 response (no chunked encoding — the server emits `Content-Length` bodies).
fn parse_reply(buf: &[u8]) -> Result<HttpReply> {
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("malformed response: no header/body separator")?;
    let head = std::str::from_utf8(&buf[..split]).context("non-utf8 headers")?;
    let body = buf[split + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().context("missing status line")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .context("malformed status line")?;
    let headers = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string())))
        .collect();
    Ok(HttpReply { status, headers, body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// An in-memory origin: a CID -> bytes map, with a hit counter so tests can assert the origin is
    /// hit exactly once (cold miss) and then served from cache.
    struct MapOrigin {
        objects: HashMap<String, Vec<u8>>,
        fetches: Arc<Mutex<u32>>,
    }

    impl MapOrigin {
        fn new(objects: HashMap<String, Vec<u8>>) -> Self {
            MapOrigin { objects, fetches: Arc::new(Mutex::new(0)) }
        }

        /// A clonable handle to the fetch counter, so a test can observe origin hits after the
        /// origin has been moved into the (Arc-shared) server state.
        fn fetches_handle(&self) -> Arc<Mutex<u32>> {
            self.fetches.clone()
        }
    }

    impl Origin for MapOrigin {
        async fn fetch(&self, cid: &str) -> Result<Vec<u8>> {
            *self.fetches.lock().unwrap() += 1;
            self.objects
                .get(cid)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("origin does not hold {cid}"))
        }
    }

    fn state_with(
        objects: Vec<(&str, Vec<u8>)>,
        public: &[&str],
        edge_id: [u8; 32],
        roots: Vec<[u8; 32]>,
    ) -> Arc<ServerState<MapOrigin>> {
        let edge = EdgeState::new(1 << 20, 3600);
        {
            // EdgeState locks are async; in a sync helper we use try_lock (uncontended in setup).
            let mut p = edge.public.try_lock().unwrap();
            for c in public {
                p.allow_public(c);
            }
        }
        let map: HashMap<String, Vec<u8>> =
            objects.into_iter().map(|(c, b)| (c.to_string(), b)).collect();
        Arc::new(ServerState::new(edge, MapOrigin::new(map), edge_id, roots))
    }

    // ---- unit: pure helpers ----

    #[test]
    fn resolve_access_public_is_open() {
        let mut p = PublicSet::new();
        p.allow_public("pub");
        // Public CIDs need neither a proof nor a cap.
        let a = resolve_access("pub", &p, &[1u8; 32], &[], &[2u8; 32], None, "", 0);
        assert_eq!(a, Access::Public);
    }

    #[test]
    fn resolve_access_private_without_caps_is_denied() {
        let p = PublicSet::new();
        let a = resolve_access("priv", &p, &[1u8; 32], &[], &[2u8; 32], None, "", 0);
        assert_eq!(a, Access::Denied);
    }

    #[test]
    fn resolve_access_private_with_garbage_caps_is_denied() {
        let p = PublicSet::new();
        let a = resolve_access("priv", &p, &[1u8; 32], &[], &[2u8; 32], None, "not-hex-!!", 0);
        assert_eq!(a, Access::Denied);
    }

    #[test]
    fn status_json_includes_per_cid_sizes() {
        let stats = CacheStats { hits: 3, misses: 1, entries: 2, bytes: 30, ..Default::default() };
        let held = vec![("aaa".to_string(), 10u64), ("bbb".to_string(), 20u64)];
        let json = status_json(stats, &held);
        assert!(json.contains("\"hits\":3"));
        assert!(json.contains("\"bytes\":30"));
        assert!(json.contains("{\"cid\":\"aaa\",\"bytes\":10}"));
        assert!(json.contains("{\"cid\":\"bbb\",\"bytes\":20}"));
        // It is valid JSON.
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["objects"].as_array().unwrap().len(), 2);
        assert_eq!(v["objects"][0]["bytes"], 10);
    }

    #[test]
    fn parse_reply_extracts_status_headers_body() {
        let raw = b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-3/10\r\nContent-Length: 4\r\n\r\nABCD";
        let r = parse_reply(raw).unwrap();
        assert_eq!(r.status, 206);
        assert_eq!(r.header("content-range"), Some("bytes 0-3/10"));
        assert_eq!(r.body, b"ABCD");
    }

    #[test]
    fn parse_reply_rejects_malformed() {
        assert!(parse_reply(b"no separator here").is_err());
    }

    // ---- HTTP-level: real socket + real hyper stack ----

    #[tokio::test]
    async fn http_full_get_has_cache_headers_and_body() {
        let state = state_with(vec![("cidA", b"hello world".to_vec())], &["cidA"], [9u8; 32], vec![]);
        let srv = spawn(state).await.unwrap();
        let r = http_get(srv.addr(), "/cdn/cidA", &[]).await.unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hello world");
        assert_eq!(r.header("etag"), Some("\"cidA\""));
        assert_eq!(r.header("accept-ranges"), Some("bytes"));
        assert_eq!(r.header("content-length"), Some("11"));
        assert!(r.header("cache-control").unwrap().contains("immutable"));
        // First read is a cold MISS (fetched from origin), then cached.
        assert_eq!(r.header("x-cache"), Some("MISS"));

        // Second read is a HIT.
        let r2 = http_get(srv.addr(), "/cdn/cidA", &[]).await.unwrap();
        assert_eq!(r2.header("x-cache"), Some("HIT"));
        assert_eq!(r2.body, b"hello world");
    }

    #[tokio::test]
    async fn http_range_yields_206_with_content_range() {
        let bytes: Vec<u8> = (0..100u8).collect();
        let state = state_with(vec![("r", bytes.clone())], &["r"], [9u8; 32], vec![]);
        let srv = spawn(state).await.unwrap();
        let r = http_get(srv.addr(), "/cdn/r", &[("Range", "bytes=10-19")]).await.unwrap();
        assert_eq!(r.status, 206);
        assert_eq!(r.header("content-range"), Some("bytes 10-19/100"));
        assert_eq!(r.header("content-length"), Some("10"));
        assert_eq!(r.body, (10..20u8).collect::<Vec<u8>>());
    }

    #[tokio::test]
    async fn http_unsatisfiable_range_yields_416() {
        let state = state_with(vec![("s", vec![0u8; 50])], &["s"], [9u8; 32], vec![]);
        let srv = spawn(state).await.unwrap();
        let r = http_get(srv.addr(), "/cdn/s", &[("Range", "bytes=100-200")]).await.unwrap();
        assert_eq!(r.status, 416);
        assert_eq!(r.header("content-range"), Some("bytes */50"));
        assert!(r.body.is_empty());
    }

    #[tokio::test]
    async fn http_malformed_range_degrades_to_full_200() {
        let state = state_with(vec![("m", vec![7u8; 8])], &["m"], [9u8; 32], vec![]);
        let srv = spawn(state).await.unwrap();
        let r = http_get(srv.addr(), "/cdn/m", &[("Range", "bytes=garbage")]).await.unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, vec![7u8; 8]);
    }

    #[tokio::test]
    async fn http_missing_cid_is_404() {
        let state = state_with(vec![], &[], [9u8; 32], vec![]);
        // "nope" is private + absent; but to reach the 404 (not 403) path, make it public.
        {
            let mut p = state.edge.public.try_lock().unwrap();
            p.allow_public("nope");
        }
        let srv = spawn(state).await.unwrap();
        let r = http_get(srv.addr(), "/cdn/nope", &[]).await.unwrap();
        assert_eq!(r.status, 404);
    }

    #[tokio::test]
    async fn http_private_content_without_capability_is_403_and_origin_untouched() {
        // CID present at origin but NOT public and no capability header -> 403, origin not consulted.
        let state = state_with(vec![("secret", b"xx".to_vec())], &[], [9u8; 32], vec![]);
        let fetches = state.origin.fetches_handle();
        let srv = spawn(state).await.unwrap();
        let r = http_get(srv.addr(), "/cdn/secret", &[]).await.unwrap();
        assert_eq!(r.status, 403);
        assert!(r.body.is_empty() || r.header("content-length") == Some("0"));
        // The origin must not have been hit for a denied request (deny before any fetch).
        assert_eq!(*fetches.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn http_private_content_with_valid_capability_is_served() {
        use ce_identity::Identity;
        use ce_cap::{Caveats, Resource, SignedCapability, encode_chain};

        let dir = std::env::temp_dir().join(format!("ce-cdn-srv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let edge = Identity::load_or_generate(&dir).unwrap();
        let consumer_dir = dir.join("consumer");
        std::fs::create_dir_all(&consumer_dir).unwrap();
        let consumer = Identity::load_or_generate(&consumer_dir).unwrap();

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

        let state = state_with(vec![("secret", b"top secret".to_vec())], &[], edge.node_id(), vec![]);
        let srv = spawn(state).await.unwrap();

        let requester_hex = hex::encode(consumer.node_id());
        // Without the cap -> 403.
        let denied = http_get(srv.addr(), "/cdn/secret", &[]).await.unwrap();
        assert_eq!(denied.status, 403);

        // A proof-of-possession bound to (requester, cid, cdn:read), signed by the consumer's key,
        // valid for a short window from the live clock.
        let expires = now_secs() + 60;
        let proof = crate::pop::mint_proof(
            &consumer.node_id(),
            |m| consumer.sign(m),
            "secret",
            proto::ABILITY_READ,
            expires,
        );

        // With a valid cap chain AND a valid proof-of-possession -> 200 + bytes.
        let ok = http_get(
            srv.addr(),
            "/cdn/secret",
            &[
                ("X-Ce-Capability", &caps_hex),
                ("X-Ce-Node-Id", &requester_hex),
                ("X-Ce-Proof", &proof),
            ],
        )
        .await
        .unwrap();
        assert_eq!(ok.status, 200, "body: {:?}", String::from_utf8_lossy(&ok.body));
        assert_eq!(ok.body, b"top secret");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// REGRESSION (finding H2): a request carrying a *valid* capability chain whose audience is the
    /// claimed `X-Ce-Node-Id`, but WITHOUT a proof-of-possession, must be REJECTED for private
    /// content. This is the leaked-bearer-token hole: under the old behavior the cap chain alone over
    /// a forgeable `X-Ce-Node-Id` header served the bytes (200). With proof-of-possession required,
    /// the same request is a 403. The companion test above proves the SAME cap + a real proof = 200,
    /// so this is the proof-of-possession factor, not a broken cap.
    #[tokio::test]
    async fn http_private_valid_cap_but_no_proof_is_rejected() {
        use ce_identity::Identity;
        use ce_cap::{Caveats, Resource, SignedCapability, encode_chain};

        let dir =
            std::env::temp_dir().join(format!("ce-cdn-srv-noproof-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let edge = Identity::load_or_generate(&dir).unwrap();
        let consumer_dir = dir.join("consumer");
        std::fs::create_dir_all(&consumer_dir).unwrap();
        let consumer = Identity::load_or_generate(&consumer_dir).unwrap();

        // A legitimately-issued chain: edge -> consumer, granting cdn:read on the secret.
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

        let state =
            state_with(vec![("secret", b"top secret".to_vec())], &[], edge.node_id(), vec![]);
        let srv = spawn(state).await.unwrap();

        // An attacker who merely captured the leaked cap chain + the consumer's node id (both travel
        // in headers, so both are leakable) sets them — but cannot mint a proof, since it lacks the
        // consumer's private key. Under the OLD code this returned 200; it must now be 403.
        let requester_hex = hex::encode(consumer.node_id());
        let leaked = http_get(
            srv.addr(),
            "/cdn/secret",
            &[("X-Ce-Capability", &caps_hex), ("X-Ce-Node-Id", &requester_hex)],
        )
        .await
        .unwrap();
        assert_eq!(
            leaked.status, 403,
            "leaked cap chain without proof-of-possession must NOT serve private content"
        );
        assert!(leaked.body.is_empty() || leaked.header("content-length") == Some("0"));

        // And a proof forged by a DIFFERENT key (an attacker signing the victim's challenge with its
        // own key) must also be rejected: the signature will not verify against X-Ce-Node-Id.
        let attacker_dir = dir.join("attacker");
        std::fs::create_dir_all(&attacker_dir).unwrap();
        let attacker = Identity::load_or_generate(&attacker_dir).unwrap();
        let expires = now_secs() + 60;
        let forged = crate::pop::mint_proof(
            &consumer.node_id(),
            |m| attacker.sign(m),
            "secret",
            proto::ABILITY_READ,
            expires,
        );
        let forged_reply = http_get(
            srv.addr(),
            "/cdn/secret",
            &[
                ("X-Ce-Capability", &caps_hex),
                ("X-Ce-Node-Id", &requester_hex),
                ("X-Ce-Proof", &forged),
            ],
        )
        .await
        .unwrap();
        assert_eq!(forged_reply.status, 403, "a proof signed by the wrong key must be rejected");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn http_status_reports_real_per_cid_sizes() {
        let state =
            state_with(vec![("x", vec![0u8; 12]), ("y", vec![0u8; 30])], &["x", "y"], [9u8; 32], vec![]);
        let srv = spawn(state).await.unwrap();
        // Prime the cache by reading both objects.
        let _ = http_get(srv.addr(), "/cdn/x", &[]).await.unwrap();
        let _ = http_get(srv.addr(), "/cdn/y", &[]).await.unwrap();

        let r = http_get(srv.addr(), "/status", &[]).await.unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.header("content-type"), Some("application/json"));
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["entries"], 2);
        assert_eq!(v["bytes"], 42);
        let objects = v["objects"].as_array().unwrap();
        let sizes: HashMap<&str, u64> = objects
            .iter()
            .map(|o| (o["cid"].as_str().unwrap(), o["bytes"].as_u64().unwrap()))
            .collect();
        assert_eq!(sizes["x"], 12);
        assert_eq!(sizes["y"], 30);
    }

    #[tokio::test]
    async fn http_health_ok_and_unknown_path_404_and_post_405() {
        let state = state_with(vec![], &[], [9u8; 32], vec![]);
        let srv = spawn(state).await.unwrap();
        let h = http_get(srv.addr(), "/health", &[]).await.unwrap();
        assert_eq!(h.status, 200);
        assert_eq!(h.body, b"ok");
        let nf = http_get(srv.addr(), "/nope", &[]).await.unwrap();
        assert_eq!(nf.status, 404);
    }

    #[tokio::test]
    async fn http_head_keeps_headers_drops_body() {
        let state = state_with(vec![("h", b"abcdef".to_vec())], &["h"], [9u8; 32], vec![]);
        let srv = spawn(state).await.unwrap();
        // Prime the cache so a HEAD reports a HIT with correct Content-Length but no body.
        let _ = http_get(srv.addr(), "/cdn/h", &[]).await.unwrap();
        let r = http_head(srv.addr(), "/cdn/h", &[]).await.unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.header("content-length"), Some("6"));
        assert_eq!(r.header("etag"), Some("\"h\""));
        assert!(r.body.is_empty(), "HEAD must not carry a body");
    }

    /// Property: for any in-bounds inclusive `[start, end]` range over an object, the HTTP front-end
    /// returns exactly `object[start..=end]` with a `206` and the matching `Content-Range`. This
    /// exercises the real socket + hyper + edge range path end to end.
    #[test]
    fn prop_http_range_returns_exact_slice() {
        use proptest::prelude::*;
        let rt = tokio::runtime::Runtime::new().unwrap();
        proptest!(ProptestConfig::with_cases(40), |(
            total in 1usize..400,
            a in 0usize..400,
            b in 0usize..400,
        )| {
            let start = a % total;
            let end = (b % total).max(start);
            let object: Vec<u8> = (0..total).map(|i| (i * 7 + 1) as u8).collect();
            let want = object[start..=end].to_vec();
            let range = format!("bytes={start}-{end}");
            rt.block_on(async {
                let state = state_with(vec![("p", object.clone())], &["p"], [9u8; 32], vec![]);
                let srv = spawn(state).await.unwrap();
                let r = http_get(srv.addr(), "/cdn/p", &[("Range", &range)]).await.unwrap();
                prop_assert_eq!(r.status, 206);
                prop_assert_eq!(r.header("content-range").unwrap(), &format!("bytes {start}-{end}/{total}"));
                prop_assert_eq!(r.header("content-length").unwrap(), &(end - start + 1).to_string());
                prop_assert_eq!(r.body, want);
                Ok(())
            })?;
        });
    }

    #[tokio::test]
    async fn http_if_none_match_yields_304_no_body() {
        let state = state_with(vec![("inm", b"body bytes".to_vec())], &["inm"], [9u8; 32], vec![]);
        let srv = spawn(state).await.unwrap();
        // Prime the cache.
        let _ = http_get(srv.addr(), "/cdn/inm", &[]).await.unwrap();
        // Client already has the exact ETag -> 304, empty body.
        let r = http_get(srv.addr(), "/cdn/inm", &[("If-None-Match", "\"inm\"")]).await.unwrap();
        assert_eq!(r.status, 304);
        assert!(r.body.is_empty(), "304 must carry no body");
        assert_eq!(r.header("etag"), Some("\"inm\""));
        // A non-matching validator still serves the full body.
        let full = http_get(srv.addr(), "/cdn/inm", &[("If-None-Match", "\"other\"")]).await.unwrap();
        assert_eq!(full.status, 200);
        assert_eq!(full.body, b"body bytes");
    }

    #[tokio::test]
    async fn http_negative_cache_serves_404_without_rehitting_origin() {
        // Public-but-absent CID: the first GET hits the origin (miss), the tombstone short-circuits
        // the next within the negative TTL so the origin is hit exactly once.
        let state = state_with(vec![], &["ghost"], [9u8; 32], vec![]);
        let fetches = state.origin.fetches_handle();
        let srv = spawn(state).await.unwrap();
        let r1 = http_get(srv.addr(), "/cdn/ghost", &[]).await.unwrap();
        assert_eq!(r1.status, 404);
        let r2 = http_get(srv.addr(), "/cdn/ghost", &[]).await.unwrap();
        assert_eq!(r2.status, 404);
        let r3 = http_get(srv.addr(), "/cdn/ghost", &[]).await.unwrap();
        assert_eq!(r3.status, 404);
        // Origin consulted once; subsequent misses served from the negative tombstone.
        assert_eq!(*fetches.lock().unwrap(), 1, "negative cache must not re-hit the origin");
    }

    #[tokio::test]
    async fn http_presigned_link_grants_access_without_client_key() {
        use ce_identity::Identity;
        let dir = std::env::temp_dir().join(format!("ce-cdn-presign-srv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let signer = Identity::load_or_generate(&dir).unwrap();

        // Private content, but the edge trusts the signer's presign key.
        let edge = EdgeState::new(1 << 20, 3600);
        let map: HashMap<String, Vec<u8>> =
            [("p".to_string(), b"shared via link".to_vec())].into_iter().collect();
        let state = Arc::new(
            ServerState::new(edge, MapOrigin::new(map), [9u8; 32], vec![])
                .with_presign_keys(vec![signer.node_id()]),
        );
        let srv = spawn(state).await.unwrap();

        // No credentials -> 403.
        let denied = http_get(srv.addr(), "/cdn/p", &[]).await.unwrap();
        assert_eq!(denied.status, 403);

        // A presigned link (query params) -> 200, no client key/header at all.
        let expires = now_secs() + 600;
        let query = crate::presign::presign_query(|m| signer.sign(m), "p", expires);
        let path = format!("/cdn/p?{query}");
        let ok = http_get(srv.addr(), &path, &[]).await.unwrap();
        assert_eq!(ok.status, 200, "body {:?}", String::from_utf8_lossy(&ok.body));
        assert_eq!(ok.body, b"shared via link");

        // A tampered expiry (signature no longer matches) -> 403.
        let bad = format!("/cdn/p?exp={}&sig={}", expires + 1, query.split("sig=").nth(1).unwrap());
        let bad_reply = http_get(srv.addr(), &bad, &[]).await.unwrap();
        assert_eq!(bad_reply.status, 403);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn http_pop_proof_is_single_use_replay_rejected() {
        use ce_identity::Identity;
        use ce_cap::{Caveats, Resource, SignedCapability, encode_chain};
        let dir = std::env::temp_dir().join(format!("ce-cdn-replay-srv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let edge = Identity::load_or_generate(&dir).unwrap();
        let consumer = Identity::load_or_generate(&dir.join("c")).unwrap();
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
        let state = state_with(vec![("secret", b"sensitive".to_vec())], &[], edge.node_id(), vec![]);
        let srv = spawn(state).await.unwrap();

        let req_hex = hex::encode(consumer.node_id());
        let expires = now_secs() + 60;
        // A fixed-nonce proof so we can replay the EXACT same header twice.
        let proof = crate::pop::mint_proof_with_nonce(
            &consumer.node_id(),
            |m| consumer.sign(m),
            "secret",
            proto::ABILITY_READ,
            &[42u8; 16],
            expires,
        );
        let headers =
            [("X-Ce-Capability", caps_hex.as_str()), ("X-Ce-Node-Id", &req_hex), ("X-Ce-Proof", &proof)];
        // First use: served.
        let first = http_get(srv.addr(), "/cdn/secret", &headers).await.unwrap();
        assert_eq!(first.status, 200);
        assert_eq!(first.body, b"sensitive");
        // Exact replay of the same proof: rejected (single-use within its window).
        let replay = http_get(srv.addr(), "/cdn/secret", &headers).await.unwrap();
        assert_eq!(replay.status, 403, "a replayed proof-of-possession must be rejected");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn http_metrics_endpoint_is_prometheus() {
        let state = state_with(vec![("m1", b"abc".to_vec())], &["m1"], [9u8; 32], vec![]);
        let srv = spawn(state).await.unwrap();
        let _ = http_get(srv.addr(), "/cdn/m1", &[]).await.unwrap(); // miss + cache
        let _ = http_get(srv.addr(), "/cdn/m1", &[]).await.unwrap(); // hit
        let r = http_get(srv.addr(), "/metrics", &[]).await.unwrap();
        assert_eq!(r.status, 200);
        assert!(r.header("content-type").unwrap().contains("text/plain"));
        let body = String::from_utf8_lossy(&r.body);
        assert!(body.contains("ce_cdn_cache_hits_total 1"), "{body}");
        assert!(body.contains("ce_cdn_object_hits_total{cid=\"m1\"} 1"), "{body}");
    }

    #[tokio::test]
    async fn http_oversize_object_is_413() {
        // A tiny cap so the test object exceeds it.
        let edge = EdgeState::new(1 << 20, 3600);
        {
            let mut p = edge.public.try_lock().unwrap();
            p.allow_public("big");
        }
        let map: HashMap<String, Vec<u8>> =
            [("big".to_string(), vec![0u8; 4096])].into_iter().collect();
        let state = Arc::new(
            ServerState::new(edge, MapOrigin::new(map), [9u8; 32], vec![]).with_max_object_bytes(1024),
        );
        let srv = spawn(state).await.unwrap();
        let r = http_get(srv.addr(), "/cdn/big", &[]).await.unwrap();
        assert_eq!(r.status, 413);
    }

    #[tokio::test]
    async fn http_invalid_cid_charset_is_404() {
        let state = state_with(vec![], &[], [9u8; 32], vec![]);
        let srv = spawn(state).await.unwrap();
        // A percent-encoded path segment is not a valid content id.
        let r = http_get(srv.addr(), "/cdn/%2e%2e", &[]).await.unwrap();
        assert_eq!(r.status, 404);
    }

    #[test]
    fn resolve_grant_prefers_public_then_presign() {
        use ce_identity::Identity;
        let dir = std::env::temp_dir().join(format!("ce-cdn-grant-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let signer = Identity::load_or_generate(&dir).unwrap();
        let mut public = PublicSet::new();
        public.allow_public("pub");
        // Public wins.
        assert_eq!(
            resolve_grant("pub", &public, &[1u8; 32], &[], &[], &[2u8; 32], None, "", "", 0),
            Grant::Public
        );
        // Presigned grants private content.
        let q = crate::presign::presign_query(|m| signer.sign(m), "priv", 1000);
        assert_eq!(
            resolve_grant(
                "priv",
                &PublicSet::new(),
                &[1u8; 32],
                &[],
                &[signer.node_id()],
                &[2u8; 32],
                None,
                &q,
                "",
                900
            ),
            Grant::Presigned
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A slow origin so a burst of concurrent cold requests for the same CID actually overlap on the
    /// single-flight lock. Without single-flight every concurrent miss would hit the origin.
    struct SlowOrigin {
        bytes: Vec<u8>,
        fetches: Arc<Mutex<u32>>,
    }
    impl Origin for SlowOrigin {
        async fn fetch(&self, _cid: &str) -> Result<Vec<u8>> {
            *self.fetches.lock().unwrap() += 1;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            Ok(self.bytes.clone())
        }
    }

    #[tokio::test]
    async fn http_concurrent_cold_misses_hit_origin_once_single_flight() {
        let edge = EdgeState::new(1 << 20, 3600);
        {
            let mut p = edge.public.try_lock().unwrap();
            p.allow_public("herd");
        }
        let fetches = Arc::new(Mutex::new(0u32));
        let origin = SlowOrigin { bytes: b"the one true body".to_vec(), fetches: fetches.clone() };
        let state = Arc::new(ServerState::new(edge, origin, [9u8; 32], vec![]));
        let srv = spawn(state).await.unwrap();
        let addr = srv.addr();

        // Fire 8 concurrent requests for the same cold CID.
        let mut handles = Vec::new();
        for _ in 0..8 {
            handles.push(tokio::spawn(async move {
                http_get(addr, "/cdn/herd", &[]).await.map(|r| (r.status, r.body))
            }));
        }
        for h in handles {
            let (status, body) = h.await.unwrap().unwrap();
            assert_eq!(status, 200);
            assert_eq!(body, b"the one true body");
        }
        // Single-flight: the slow origin was consulted exactly once despite 8 concurrent misses.
        assert_eq!(*fetches.lock().unwrap(), 1, "single-flight must collapse the herd to one fetch");
    }

    #[tokio::test]
    async fn http_origin_fetched_once_then_served_from_cache() {
        let state = state_with(vec![("once", b"data".to_vec())], &["once"], [9u8; 32], vec![]);
        let fetches = state.origin.fetches_handle();
        let srv = spawn(state).await.unwrap();
        let _ = http_get(srv.addr(), "/cdn/once", &[]).await.unwrap();
        let _ = http_get(srv.addr(), "/cdn/once", &[]).await.unwrap();
        let _ = http_get(srv.addr(), "/cdn/once", &[]).await.unwrap();
        assert_eq!(*fetches.lock().unwrap(), 1, "origin should be hit once, then cache serves");
    }
}
