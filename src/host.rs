//! The edge host: a capability-gated loop that caches and serves content over the CE mesh.
//!
//! An edge subscribes to the `cdn/*` topics, and for each request:
//!   1. for **private** content or cache/purge actions, authorizes the presented `ce-cap` chain
//!      (rooted at the edge's own key or a configured org root) — public reads need no chain;
//!   2. on a `cdn/cache` it fetches the object (trustless: `get_object` verifies every chunk) and
//!      stores it in the [`EdgeCache`] with a TTL;
//!   3. on a `cdn/read` it serves the bytes (whole or a range), recording a cache hit/miss;
//!   4. on a `cdn/purge` it evicts the object;
//!   5. on a `cdn/status` it answers whether it still holds the CID.
//!
//! The authorization decision is factored into the pure [`decide`] function so the policy is
//! exhaustively testable without a live mesh, and the async loop only does I/O.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use ce_cap::{SignedCapability, authorize, decode_chain};
use ce_rs::CeClient;
use tokio::sync::Mutex;

use crate::cache::EdgeCache;
use crate::limits;
use crate::proto;

/// What a request is allowed to do, after evaluating the presented capability chain. The pure
/// [`decide`] function returns this; the loop acts on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The action is permitted.
    Allow,
    /// The action is refused; the carried reason is safe to return to the caller.
    Deny,
}

/// The set of CIDs this edge is willing to serve *publicly* (no capability needed). Anything not in
/// this set is treated as private and requires a `cdn:read` chain. An edge that wants to be an open
/// public CDN can mark every cached CID public; a private edge leaves the set empty.
#[derive(Debug, Clone, Default)]
pub struct PublicSet {
    cids: HashSet<String>,
}

impl PublicSet {
    /// An empty set — every CID is private (capability required).
    pub fn new() -> Self {
        PublicSet { cids: HashSet::new() }
    }

    /// Mark `cid` as public (served without a capability).
    pub fn allow_public(&mut self, cid: &str) {
        self.cids.insert(cid.to_string());
    }

    /// Stop serving `cid` publicly.
    pub fn revoke_public(&mut self, cid: &str) {
        self.cids.remove(cid);
    }

    /// Is `cid` public?
    pub fn is_public(&self, cid: &str) -> bool {
        self.cids.contains(cid)
    }

    /// Iterate the CIDs currently marked public. Order is unspecified (backed by a `HashSet`); the
    /// HTTP `/status` handler sorts before rendering so the snapshot is deterministic.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.cids.iter().map(String::as_str)
    }
}

/// Decide whether to honor a request for `action` on `cid`.
///
/// - A **read** of a CID in `public` is always allowed (no capability needed) — that is the whole
///   point of a public CDN edge.
/// - Otherwise the caller must present a chain the `authorize` closure accepts for `action`.
///
/// `authorize(action) -> Result<(), String>` wraps `ce_cap::authorize` with the edge's identity,
/// accepted roots, tags, clock, the requester NodeId, and revocation set already bound in. Keeping
/// it a closure makes `decide` pure and trivially testable: pass a closure that returns `Ok`/`Err`.
pub fn decide(
    action: &str,
    cid: &str,
    public: &PublicSet,
    authorize: impl Fn(&str) -> Result<(), String>,
) -> (Decision, Option<String>) {
    if action == proto::ABILITY_READ && public.is_public(cid) {
        return (Decision::Allow, None);
    }
    match authorize(action) {
        Ok(()) => (Decision::Allow, None),
        Err(reason) => (Decision::Deny, Some(reason)),
    }
}

/// Shared, mutable edge state guarded for the async loop. The cache is the hot store; `public` is
/// the set of openly-served CIDs.
#[derive(Clone)]
pub struct EdgeState {
    pub cache: Arc<Mutex<EdgeCache>>,
    pub public: Arc<Mutex<PublicSet>>,
}

impl EdgeState {
    /// New edge state with a cache of `max_bytes` and `default_ttl_secs`.
    pub fn new(max_bytes: u64, default_ttl_secs: u64) -> Self {
        EdgeState {
            cache: Arc::new(Mutex::new(EdgeCache::new(max_bytes, default_ttl_secs))),
            public: Arc::new(Mutex::new(PublicSet::new())),
        }
    }

    /// Fetch `cid` from the origin (the blob store / mesh) and store it in the cache with `ttl_secs`.
    /// Returns the stored byte length. The fetch is trustless (`get_object` verifies chunks); a
    /// failure leaves the cache unchanged and propagates the error.
    pub async fn cache_object(
        &self,
        ce: &CeClient,
        cid: &str,
        ttl_secs: u64,
        now: u64,
    ) -> Result<u64> {
        // Bound the size BEFORE pulling the whole object into memory: refuse to cache something that
        // can never fit (or that exceeds the mesh ceiling) without first materializing every byte.
        let total = self.object_total_size(ce, cid).await?;
        {
            let cache = self.cache.lock().await;
            if total > cache.max_bytes() {
                anyhow::bail!("object {cid} ({total} bytes) exceeds this edge's cache budget");
            }
        }
        let bytes = ce.get_object(cid).await?;
        let len = bytes.len() as u64;
        let mut cache = self.cache.lock().await;
        let ttl = if ttl_secs == 0 { cache.default_ttl_secs() } else { ttl_secs };
        if !cache.insert_with_ttl(cid, bytes, ttl, now) {
            anyhow::bail!("object {cid} ({len} bytes) exceeds this edge's cache budget");
        }
        Ok(len)
    }

    /// Read `cid` from the hot cache at `now`, returning `(bytes, cache_hit)`. On a cold miss it
    /// fetches from the origin, caches it, and returns the bytes with `cache_hit = false`.
    ///
    /// The whole-object size is bounded by [`limits::MAX_MESH_OBJECT_BYTES`]: an object larger than
    /// the mesh reply ceiling is refused (it must be fetched over HTTP or by range), so a single
    /// `cdn/read` can never balloon the reply past the SDK wire limit or OOM either end.
    pub async fn read_object(
        &self,
        ce: &CeClient,
        cid: &str,
        now: u64,
    ) -> Result<(Vec<u8>, bool)> {
        {
            let mut cache = self.cache.lock().await;
            if let Some(bytes) = cache.get(cid, now) {
                return Ok((bytes, true));
            }
        }
        // Cold: peek the manifest to bound the size BEFORE pulling the whole object.
        let total = self.object_total_size(ce, cid).await?;
        if total > limits::MAX_MESH_OBJECT_BYTES {
            anyhow::bail!(
                "object {cid} ({total} bytes) exceeds the mesh read limit ({} bytes); fetch by range or over HTTP",
                limits::MAX_MESH_OBJECT_BYTES
            );
        }
        let bytes = ce.get_object(cid).await?;
        {
            let mut cache = self.cache.lock().await;
            let _ = cache.insert(cid, bytes.clone(), now);
        }
        Ok((bytes, false))
    }

    /// Resolve just an object's total size from its manifest (a single small blob fetch), without
    /// pulling any chunk bytes. Used to bound a read before committing to the full transfer.
    async fn object_total_size(&self, ce: &CeClient, cid: &str) -> Result<u64> {
        let manifest_bytes = ce.get_blob(cid).await?;
        let manifest: ce_rs::data::Manifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| anyhow!("{cid} is not a v1 object manifest: {e}"))?;
        if !manifest.is_v1() {
            anyhow::bail!("unsupported manifest kind: {}", manifest.kind);
        }
        Ok(manifest.total_size)
    }

    /// Read only the bytes covering `range` of `cid` (manifest-aware partial fetch), returning
    /// `(range_bytes, cache_hit)`. If the whole object is already hot-cached, slice from it (a true
    /// cache hit). Otherwise fetch ONLY the covering chunks from the blob store, verify each against
    /// its CID, and slice — so a 1-byte range over a 1 GiB object pulls one chunk, not the whole
    /// object. The covering-chunk byte span is bounded by [`limits::MAX_MESH_RANGE_BYTES`].
    pub async fn read_range(
        &self,
        ce: &CeClient,
        cid: &str,
        range: crate::cidrange::ByteRange,
        now: u64,
    ) -> Result<(Vec<u8>, bool)> {
        // Hot path: if the whole object is cached, slice directly.
        {
            let mut cache = self.cache.lock().await;
            if let Some(bytes) = cache.get(cid, now)
                && (range.end as usize) < bytes.len()
            {
                return Ok((bytes[range.start as usize..=range.end as usize].to_vec(), true));
            }
        }
        // Cold range: pull only covering chunks.
        let manifest_bytes = ce.get_blob(cid).await?;
        let manifest: ce_rs::data::Manifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| anyhow!("{cid} is not a v1 object manifest: {e}"))?;
        if !manifest.is_v1() {
            anyhow::bail!("unsupported manifest kind: {}", manifest.kind);
        }
        let span = crate::cidrange::chunks_for_range(&manifest, range)
            .ok_or_else(|| anyhow!("manifest {cid} has zero chunk_size"))?;
        // Bound the covering-chunk byte span we will materialize.
        let covering_chunks = span.last_chunk.saturating_sub(span.first_chunk).saturating_add(1);
        let covering_bytes = covering_chunks.saturating_mul(manifest.chunk_size);
        if covering_bytes > limits::MAX_MESH_RANGE_BYTES {
            anyhow::bail!(
                "range covers {covering_bytes} bytes, exceeding the mesh range limit ({} bytes)",
                limits::MAX_MESH_RANGE_BYTES
            );
        }
        let joined = self.fetch_chunks(ce, &manifest, span).await?;
        let sliced = crate::cidrange::slice_span(&joined, span)?;
        Ok((sliced, false))
    }

    /// Pull chunks `span.first_chunk..=span.last_chunk` from the blob store, verifying each against
    /// its CID (trustless), and return them concatenated.
    async fn fetch_chunks(
        &self,
        ce: &CeClient,
        manifest: &ce_rs::data::Manifest,
        span: crate::cidrange::ChunkSpan,
    ) -> Result<Vec<u8>> {
        if manifest.chunks.is_empty() {
            return Ok(Vec::new());
        }
        let last = (span.last_chunk as usize).min(manifest.chunks.len() - 1);
        let first = (span.first_chunk as usize).min(last);
        let mut out = Vec::new();
        for chunk_cid in &manifest.chunks[first..=last] {
            let chunk = ce.get_blob(chunk_cid).await?;
            let got = ce_rs::cid(&chunk);
            if got != *chunk_cid {
                anyhow::bail!("chunk verification failed: expected {chunk_cid}, got {got}");
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

/// Current unix seconds — the single clock the host loop threads through the (otherwise pure) cache
/// and edge logic.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A bounded set of mesh reply tokens already handled, for at-most-once request processing. The edge
/// loop sees each gossip request potentially more than once (re-delivery), so it dedups on the reply
/// token. A plain `HashSet` would grow without bound for the life of the process (one entry per
/// distinct request — a slow but unbounded leak); this caps the set at `capacity` and evicts the
/// oldest token (FIFO ring) once full. Eviction can only re-admit a token last seen `capacity`
/// requests ago, which the 500ms poll cadence makes a non-issue in practice.
#[derive(Debug)]
pub struct SeenTokens {
    set: HashSet<u64>,
    order: VecDeque<u64>,
    capacity: usize,
}

impl SeenTokens {
    /// A new bounded seen-set holding at most `capacity` tokens (FIFO eviction once full). A
    /// `capacity` of 0 is treated as 1 so the structure always makes progress.
    pub fn new(capacity: usize) -> Self {
        SeenTokens {
            set: HashSet::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    /// Record `token`; returns `true` if it is newly seen (the caller should process the request),
    /// `false` if it was already present (a duplicate to skip). Evicts the oldest token when full so
    /// memory stays bounded by `capacity` regardless of how many requests arrive.
    pub fn insert(&mut self, token: u64) -> bool {
        if !self.set.insert(token) {
            return false;
        }
        self.order.push_back(token);
        while self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }

    /// The number of tokens currently retained (never exceeds `capacity`).
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

/// How many recently-handled reply tokens an edge retains for dedup before evicting the oldest. Large
/// enough that no realistic in-flight re-delivery window re-admits a duplicate; small enough that the
/// set's memory is a fixed, trivial ceiling (~16K * 8 bytes).
pub const SEEN_TOKENS_CAPACITY: usize = 16_384;

/// Run the edge host loop until the process is killed. The edge advertises `cdn:edge` on the DHT,
/// polls its mesh inbox for `cdn/*` requests, authorizes each (public reads excepted), and serves.
///
/// `roots` are accepted capability root NodeIds (32-byte); a chain rooted at one of them (or at this
/// edge's own key) authorizes private reads / cache / purge. `max_bytes` and `default_ttl_secs`
/// size the cache. `public_cids` are CIDs this edge serves openly (no capability).
pub async fn serve(
    client: &CeClient,
    roots: Vec<[u8; 32]>,
    max_bytes: u64,
    default_ttl_secs: u64,
    public_cids: Vec<String>,
) -> Result<()> {
    let edge_hex = client.status().await?.node_id;
    let edge_id: [u8; 32] = hex::decode(&edge_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("node returned a malformed node id"))?;

    let state = EdgeState::new(max_bytes, default_ttl_secs);
    {
        let mut p = state.public.lock().await;
        for cid in &public_cids {
            p.allow_public(cid);
        }
    }

    if let Err(e) = client.advertise_service(proto::SERVICE_EDGE).await {
        tracing::warn!(error = %e, "could not advertise cdn:edge service (continuing)");
    }
    tracing::info!(
        edge = %&edge_hex[..16.min(edge_hex.len())],
        roots = roots.len(),
        max_bytes,
        default_ttl_secs,
        public = public_cids.len(),
        "ce-cdn edge serving (cdn/cache, cdn/read, cdn/purge, cdn/status)"
    );

    let mut seen = SeenTokens::new(SEEN_TOKENS_CAPACITY);
    let mut revoked: HashSet<([u8; 32], u64)> = HashSet::new();
    let mut tick: u32 = 0;

    loop {
        if tick.is_multiple_of(20) {
            if let Ok(pairs) = client.revoked().await {
                revoked = pairs
                    .into_iter()
                    .filter_map(|(issuer, nonce)| {
                        hex::decode(&issuer)
                            .ok()
                            .and_then(|b| <[u8; 32]>::try_from(b).ok())
                            .map(|i| (i, nonce))
                    })
                    .collect();
            }
            let _ = client.advertise_service(proto::SERVICE_EDGE).await;
            // Re-advertise the CIDs we currently hold so consumers can discover this edge.
            let held: Vec<String> = {
                // Snapshot cache contents by sweeping then listing fresh CIDs is overkill; we just
                // re-advertise public CIDs we were told to serve (the common discoverable case).
                state.public.lock().await.cids.iter().cloned().collect()
            };
            for cid in &held {
                let _ = client.advertise_service(&proto::service_for(cid)).await;
            }
            // Sweep expired entries so dead bytes don't hold the budget hostage.
            state.cache.lock().await.sweep_expired(now_secs());
        }
        tick = tick.wrapping_add(1);

        for m in client.messages().await.unwrap_or_default() {
            let Some(token) = m.reply_token else { continue };
            if !m.topic.starts_with(proto::TOPIC_PREFIX) || !seen.insert(token) {
                continue;
            }
            let reply =
                handle(client, &state, &m.topic, &m.from, &m.payload_hex, &edge_id, &roots, &revoked)
                    .await;
            if let Err(e) = client.reply(token, &reply).await {
                tracing::warn!(error = %e, "failed to send mesh reply");
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Authorize, dispatch, and serialize a reply. Any error becomes a typed negative reply so the
/// requester always gets a structured answer instead of a timeout.
#[allow(clippy::too_many_arguments)]
async fn handle(
    client: &CeClient,
    state: &EdgeState,
    topic: &str,
    from_hex: &str,
    payload_hex: &str,
    edge_id: &[u8; 32],
    roots: &[[u8; 32]],
    revoked: &HashSet<([u8; 32], u64)>,
) -> Vec<u8> {
    match handle_inner(client, state, topic, from_hex, payload_hex, edge_id, roots, revoked).await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::debug!(topic, error = %e, "request denied/failed");
            serde_json::to_vec(&serde_json::json!({
                "cached": false, "ok": false, "held": false, "purged": false,
                "reason": e.to_string(),
            }))
            .unwrap_or_default()
        }
    }
}

/// The capability ability required to honor a request on `topic` (`None` for the status probe,
/// which is gated as a read).
fn ability_for(topic: &str) -> Option<&'static str> {
    match topic {
        proto::TOPIC_CACHE => Some(proto::ABILITY_CACHE),
        proto::TOPIC_READ => Some(proto::ABILITY_READ),
        proto::TOPIC_PURGE => Some(proto::ABILITY_PURGE),
        proto::TOPIC_STATUS => Some(proto::ABILITY_READ),
        _ => None,
    }
}

/// Pull just the `caps` and `cid` fields out of a request payload (all `cdn/*` requests share them)
/// so the host can make the access decision before fully deserializing the action body.
fn caps_and_cid(payload: &[u8]) -> Result<(String, String)> {
    #[derive(serde::Deserialize)]
    struct Head {
        #[serde(default)]
        caps: String,
        cid: String,
    }
    let h: Head = serde_json::from_slice(payload).context("payload missing cid")?;
    Ok((h.caps, h.cid))
}

#[allow(clippy::too_many_arguments)]
async fn handle_inner(
    client: &CeClient,
    state: &EdgeState,
    topic: &str,
    from_hex: &str,
    payload_hex: &str,
    edge_id: &[u8; 32],
    roots: &[[u8; 32]],
    revoked: &HashSet<([u8; 32], u64)>,
) -> Result<Vec<u8>> {
    // Bound the inbound payload BEFORE decoding so a hostile oversized request cannot exhaust memory
    // on decode. The hex on the wire is 2x the decoded size.
    if payload_hex.len() > limits::MAX_REQUEST_BYTES.saturating_mul(2) {
        return Err(anyhow!("request payload too large"));
    }
    let payload = hex::decode(payload_hex).context("payload hex")?;
    if payload.len() > limits::MAX_REQUEST_BYTES {
        return Err(anyhow!("request payload too large"));
    }
    let from: [u8; 32] = hex::decode(from_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("bad sender id"))?;
    let ability = ability_for(topic).ok_or_else(|| anyhow!("unknown cdn topic '{topic}'"))?;
    let (caps, cid) = caps_and_cid(&payload)?;
    // Validate the CID and cap-chain shape up front so malformed keys never reach the cache/origin.
    if !limits::is_valid_cid(&cid) {
        return Err(anyhow!(proto::denied("malformed cid")));
    }
    if caps.len() > limits::MAX_CAPS_HEX_LEN {
        return Err(anyhow!(proto::denied("capability chain too large")));
    }

    // Build the authorizer closure that `decide` consults for non-public actions.
    let is_public = state.public.lock().await.is_public(&cid);
    let authorize_fn = |action: &str| -> Result<(), String> {
        let chain: Vec<SignedCapability> =
            decode_chain(&caps).map_err(|_| "bad capability".to_string())?;
        let is_revoked = |issuer: &[u8; 32], nonce: u64| revoked.contains(&(*issuer, nonce));
        authorize(edge_id, roots, &[], now_secs(), &from, action, &chain, &is_revoked)
    };
    let public = PublicSet {
        cids: if is_public { std::iter::once(cid.clone()).collect() } else { HashSet::new() },
    };
    let (decision, reason) = decide(ability, &cid, &public, authorize_fn);
    if decision == Decision::Deny {
        return Err(anyhow!(proto::denied(reason.unwrap_or_else(|| "unauthorized".into()))));
    }

    let now = now_secs();
    match topic {
        proto::TOPIC_CACHE => {
            let req: proto::CacheReq = serde_json::from_slice(&payload)?;
            let resp = match state.cache_object(client, &req.cid, req.ttl_secs, now).await {
                Ok(len) => {
                    let _ = client.advertise_service(&proto::service_for(&req.cid)).await;
                    let ttl = if req.ttl_secs == 0 {
                        state.cache.lock().await.default_ttl_secs()
                    } else {
                        req.ttl_secs
                    };
                    tracing::info!(cid = %req.cid, bytes = len, "cached object");
                    proto::CacheResp { cached: true, stored_bytes: len, ttl_secs: ttl, reason: None }
                }
                Err(e) => proto::CacheResp {
                    cached: false,
                    stored_bytes: 0,
                    ttl_secs: 0,
                    reason: Some(format!("fetch failed: {e}")),
                },
            };
            Ok(serde_json::to_vec(&resp)?)
        }
        proto::TOPIC_READ => {
            let req: proto::ReadReq = serde_json::from_slice(&payload)?;
            let resp = do_read(client, state, &req, now).await;
            Ok(serde_json::to_vec(&resp)?)
        }
        proto::TOPIC_PURGE => {
            let req: proto::PurgeReq = serde_json::from_slice(&payload)?;
            let purged = state.cache.lock().await.purge(&req.cid);
            Ok(serde_json::to_vec(&proto::PurgeResp { purged, reason: None })?)
        }
        proto::TOPIC_STATUS => {
            let req: proto::StatusReq = serde_json::from_slice(&payload)?;
            let cache = state.cache.lock().await;
            let held = cache.contains_fresh(&req.cid, now);
            // Report the real stored size for a held CID (side-effect free, no `get`); 0 if absent.
            let bytes = if held { cache.byte_len(&req.cid).unwrap_or(0) } else { 0 };
            let ttl_remaining = cache
                .ttl_remaining(&req.cid, now)
                .map(|t| if t == u64::MAX { 0 } else { t })
                .unwrap_or(0);
            Ok(serde_json::to_vec(&proto::StatusResp { held, bytes, ttl_remaining })?)
        }
        _ => unreachable!("topic validated by ability_for"),
    }
}

/// Serve a read (whole object or a range) from the edge, fetching+caching on a cold miss. The bytes
/// are hex-encoded into the reply; the consumer re-verifies against the CID, so this is trustless.
///
/// A whole-object read is bounded by [`limits::MAX_MESH_OBJECT_BYTES`]; a range read fetches ONLY the
/// covering chunks (manifest-aware) and is bounded by [`limits::MAX_MESH_RANGE_BYTES`]. So a range
/// over a huge object pulls one chunk, and no single reply can balloon past the mesh wire ceiling.
async fn do_read(
    client: &CeClient,
    state: &EdgeState,
    req: &proto::ReadReq,
    now: u64,
) -> proto::ReadResp {
    // Resolve the requested range against the object's true total size (a small manifest peek) so a
    // range read never has to materialize the whole object first.
    if let Some(range_hdr) = req.range.as_deref() {
        let total = match state.object_total_size(client, &req.cid).await {
            Ok(t) => t,
            Err(e) => {
                return proto::ReadResp {
                    ok: false,
                    reason: Some(format!("not retrievable: {e}")),
                    ..Default::default()
                };
            }
        };
        match crate::cidrange::parse_range(Some(range_hdr), total) {
            crate::cidrange::RangeOutcome::Full => {} // fall through to whole-object read below
            crate::cidrange::RangeOutcome::Partial(r) => {
                return match state.read_range(client, &req.cid, r, now).await {
                    Ok((bytes, cache_hit)) => proto::ReadResp {
                        ok: true,
                        bytes_hex: hex::encode(&bytes),
                        total_len: total,
                        partial: true,
                        range_start: r.start,
                        range_end: r.end,
                        cache_hit,
                        ..Default::default()
                    },
                    Err(e) => proto::ReadResp {
                        ok: false,
                        total_len: total,
                        reason: Some(format!("range read failed: {e}")),
                        ..Default::default()
                    },
                };
            }
            crate::cidrange::RangeOutcome::Unsatisfiable => {
                return proto::ReadResp {
                    ok: false,
                    total_len: total,
                    reason: Some(format!("range not satisfiable for {total} bytes")),
                    ..Default::default()
                };
            }
        }
    }

    // Whole-object read (no range, or a range that resolved to Full).
    let (bytes, cache_hit) = match state.read_object(client, &req.cid, now).await {
        Ok(v) => v,
        Err(e) => {
            return proto::ReadResp {
                ok: false,
                reason: Some(format!("not retrievable: {e}")),
                ..Default::default()
            };
        }
    };
    let total = bytes.len() as u64;
    proto::ReadResp {
        ok: true,
        bytes_hex: hex::encode(&bytes),
        total_len: total,
        partial: false,
        cache_hit,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow_all(_: &str) -> Result<(), String> {
        Ok(())
    }
    fn deny_all(_: &str) -> Result<(), String> {
        Err("no capability".to_string())
    }

    #[test]
    fn public_read_is_allowed_without_capability() {
        let mut p = PublicSet::new();
        p.allow_public("pubcid");
        // Even with a deny-all authorizer, a public read is allowed.
        let (d, reason) = decide(proto::ABILITY_READ, "pubcid", &p, deny_all);
        assert_eq!(d, Decision::Allow);
        assert!(reason.is_none());
    }

    #[test]
    fn private_read_requires_capability() {
        let p = PublicSet::new(); // nothing public
        let (d, reason) = decide(proto::ABILITY_READ, "privcid", &p, deny_all);
        assert_eq!(d, Decision::Deny);
        assert_eq!(reason.as_deref(), Some("no capability"));
        // With a valid chain it is allowed.
        let (d2, _) = decide(proto::ABILITY_READ, "privcid", &p, allow_all);
        assert_eq!(d2, Decision::Allow);
    }

    #[test]
    fn cache_and_purge_always_need_capability_even_for_public_cid() {
        let mut p = PublicSet::new();
        p.allow_public("c");
        // A public CID does not let an unauthorized caller mutate the edge's cache.
        let (d, _) = decide(proto::ABILITY_CACHE, "c", &p, deny_all);
        assert_eq!(d, Decision::Deny);
        let (d2, _) = decide(proto::ABILITY_PURGE, "c", &p, deny_all);
        assert_eq!(d2, Decision::Deny);
    }

    #[test]
    fn public_set_allow_and_revoke() {
        let mut p = PublicSet::new();
        assert!(!p.is_public("x"));
        p.allow_public("x");
        assert!(p.is_public("x"));
        p.revoke_public("x");
        assert!(!p.is_public("x"));
    }

    #[test]
    fn now_secs_is_nonzero() {
        assert!(now_secs() > 1_600_000_000); // after 2020
    }

    #[test]
    fn seen_tokens_dedups_like_a_hashset() {
        let mut s = SeenTokens::new(8);
        assert!(s.insert(1)); // newly seen
        assert!(!s.insert(1)); // duplicate
        assert!(s.insert(2));
        assert_eq!(s.len(), 2);
        assert!(!s.is_empty());
    }

    #[test]
    fn seen_tokens_stays_bounded_under_many_requests() {
        // REGRESSION (finding H2/MEDIUM): the edge loop's reply-token dedup set must NOT grow without
        // bound. Feed far more distinct tokens than the capacity and assert the retained set never
        // exceeds it. A plain HashSet (the old behavior) would hold all 100_000 entries.
        let cap = 1_000;
        let mut s = SeenTokens::new(cap);
        for token in 0..100_000u64 {
            s.insert(token);
            assert!(s.len() <= cap, "seen-set grew past its bound: {} > {cap}", s.len());
        }
        assert_eq!(s.len(), cap, "a full ring retains exactly `capacity` tokens");
        // The oldest tokens were evicted, so re-inserting one counts as newly seen again...
        assert!(s.insert(0), "evicted token should be re-admittable");
        // ...while the most-recent ones are still deduped.
        assert!(!s.insert(99_999), "the newest token must still be deduped");
    }

    #[test]
    fn seen_tokens_zero_capacity_is_clamped_to_one() {
        let mut s = SeenTokens::new(0);
        assert!(s.insert(7));
        assert_eq!(s.len(), 1);
        // The next distinct token evicts the first (capacity 1).
        assert!(s.insert(8));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn caps_and_cid_extracts_head_fields() {
        let (caps, cid) = caps_and_cid(br#"{"caps":"dead","cid":"beef","range":"bytes=0-1"}"#).unwrap();
        assert_eq!(caps, "dead");
        assert_eq!(cid, "beef");
        // Missing cid is an error, not a panic.
        assert!(caps_and_cid(br#"{"caps":"x"}"#).is_err());
        // Absent caps defaults to empty.
        let (caps2, cid2) = caps_and_cid(br#"{"cid":"abc"}"#).unwrap();
        assert_eq!(caps2, "");
        assert_eq!(cid2, "abc");
    }

    #[test]
    fn ability_for_maps_topics() {
        assert_eq!(ability_for(proto::TOPIC_CACHE), Some(proto::ABILITY_CACHE));
        assert_eq!(ability_for(proto::TOPIC_READ), Some(proto::ABILITY_READ));
        assert_eq!(ability_for(proto::TOPIC_PURGE), Some(proto::ABILITY_PURGE));
        assert_eq!(ability_for(proto::TOPIC_STATUS), Some(proto::ABILITY_READ));
        assert_eq!(ability_for("cdn/unknown"), None);
    }

    #[test]
    fn cid_validation_gates_requests() {
        // The host validates the CID before any cache/origin work; a real CID is 64 lowercase hex.
        assert!(limits::is_valid_cid(&"a".repeat(64)));
        assert!(!limits::is_valid_cid("not-a-real-cid"));
        assert!(!limits::is_valid_cid(&"a".repeat(63)));
    }
}
