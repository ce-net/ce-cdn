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

use crate::cache::CacheStats;
use crate::edge::{self, Access, Body as EdgeBody};
use crate::host::{EdgeState, PublicSet, now_secs};
use crate::proto;

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
}

impl<O: Origin> ServerState<O> {
    /// Build server state from edge state, an origin, the edge's NodeId, and accepted roots.
    pub fn new(edge: EdgeState, origin: O, edge_id: [u8; 32], roots: Vec<[u8; 32]>) -> Self {
        ServerState { edge, origin, edge_id, roots }
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
    if public.is_public(cid) {
        return Access::Public;
    }
    // Gate 1: prove the caller actually holds the requester key for THIS request. Without this, the
    // capability chain below would be a pure bearer token over a forgeable `X-Ce-Node-Id` header.
    if crate::pop::verify_pop(proof, requester, cid, proto::ABILITY_READ, now).is_err() {
        return Access::Denied;
    }
    // Gate 2: the (now key-proven) requester must hold a cap chain authorizing cdn:read.
    let Ok(chain): Result<Vec<SignedCapability>, _> = decode_chain(caps_hex) else {
        return Access::Denied;
    };
    let never_revoked = |_: &[u8; 32], _: u64| false;
    match authorize(edge_id, roots, &[], now, requester, proto::ABILITY_READ, &chain, &never_revoked)
    {
        Ok(()) => Access::Authorized,
        Err(_) => Access::Denied,
    }
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

    let Some(cid) = path.strip_prefix("/cdn/") else {
        return text(StatusCode::NOT_FOUND, "not found");
    };
    let cid = cid.trim_end_matches('/');
    if cid.is_empty() || cid.contains('/') {
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

    // Access decision first — deny cap-less / proof-less private content with a 403 before touching
    // the origin.
    let access = {
        let public = state.edge.public.lock().await;
        resolve_access(
            cid,
            &public,
            &state.edge_id,
            &state.roots,
            &requester,
            proof.as_deref(),
            &caps_hex,
            now,
        )
    };
    if access == Access::Denied {
        return to_http(edge::serve(cid, &[], None, Access::Denied, &deny_cache(), now, true));
    }

    // Read from the hot cache; on a cold miss fetch from the origin and cache it.
    let (bytes, hit) = {
        let mut cache = state.edge.cache.lock().await;
        match cache.get(cid, now) {
            Some(b) => (b, true),
            None => {
                drop(cache);
                match state.origin.fetch(cid).await {
                    Ok(b) => {
                        let mut cache = state.edge.cache.lock().await;
                        let _ = cache.insert(cid, b.clone(), now);
                        (b, false)
                    }
                    Err(_) => return to_http(edge::not_found(cid)),
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
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                tracing::debug!(error = %e, "connection closed with error");
            }
        });
    }
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
                let _ = http1::Builder::new().serve_connection(io, svc).await;
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
