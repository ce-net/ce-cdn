//! The publisher / consumer client: put content onto the CDN, get it by CID (whole or by range),
//! purge it, and replicate it across N edges — all over CE primitives via `ce-rs`.
//!
//! - **put**: chunk + store the object in the content-addressed blob store (`put_object`), record it
//!   in the catalog, and advertise the CID on the DHT so edges/consumers can find holders.
//! - **get**: resolve the manifest and pull+verify chunks (`get_object`) — content-addressing makes
//!   the transfer trustless. A range get pulls only the covering chunks and slices them.
//! - **replicate**: ask N ranked edges (`cdn:cache`) to fetch-and-hold the object.
//! - **purge**: drop a CID locally and ask edges to evict it.
//!
//! Money & trust stay on CE rules: rent/payment is via the SDK's payment channels (wired by the
//! CLI incrementally); private content is gated by the `ce-cap` chain the consumer presents.

use anyhow::{Context, Result, anyhow};
use ce_rs::data::Manifest;
use ce_rs::{CeClient, cid as blob_cid};

use crate::cidrange::{ByteRange, ChunkSpan, RangeOutcome, chunks_for_range, parse_range, slice_span};
use crate::proto;
use crate::replication::{EdgeCandidate, select};

/// A handle bundling a `CeClient` plus the CDN-specific operations.
pub struct CdnClient {
    ce: CeClient,
}

/// The result of putting content onto the CDN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutResult {
    /// The object CID (manifest hash) — the stable, content-addressed name.
    pub cid: String,
    /// Total object size in bytes.
    pub bytes_len: u64,
    /// A relative edge URL a consumer can hit to fetch it (`/cdn/<cid>`).
    pub url: String,
}

impl CdnClient {
    /// Wrap a `CeClient` (e.g. `CeClient::local()`).
    pub fn new(ce: CeClient) -> Self {
        CdnClient { ce }
    }

    /// Borrow the underlying SDK client (for the CLI to call atlas/history/discovery directly).
    pub fn ce(&self) -> &CeClient {
        &self.ce
    }

    /// The relative edge URL for a CID (`/cdn/<cid>`). Pure; useful for tests and link generation.
    pub fn url_for(cid: &str) -> String {
        format!("/cdn/{cid}")
    }

    /// Store `bytes` as a content-addressed object and advertise its CID on the DHT. Returns the
    /// CID, size, and the relative edge URL. The object is chunked client-side (1 MiB chunks); the
    /// node stores opaque blobs. Idempotent: putting identical bytes yields the same CID (dedup).
    pub async fn put(&self, bytes: &[u8]) -> Result<PutResult> {
        let cid = self.ce.put_object(bytes).await.context("storing object in blob store")?;
        // Advertise that this node holds the object so consumers/edges can discover it.
        // Best-effort: a discovery failure does not invalidate the stored bytes.
        let _ = self.ce.advertise_service(&proto::service_for(&cid)).await;
        Ok(PutResult { cid: cid.clone(), bytes_len: bytes.len() as u64, url: Self::url_for(&cid) })
    }

    /// Fetch a whole object by CID, verifying every chunk against its CID (trustless).
    pub async fn get(&self, cid: &str) -> Result<Vec<u8>> {
        self.ce.get_object(cid).await.with_context(|| format!("fetching object {cid}"))
    }

    /// Fetch a byte range of an object by CID. Resolves the manifest, pulls only the chunks that
    /// cover the range, verifies each against its CID, concatenates, and slices to the exact span.
    ///
    /// `range_header` is an HTTP-style `Range` value (e.g. `"bytes=0-1023"`); `None` fetches the
    /// whole object. Returns the bytes plus the resolved [`ByteRange`] and total object size (so a
    /// caller can render `Content-Range`). An unsatisfiable range is an error.
    pub async fn get_range(
        &self,
        cid: &str,
        range_header: Option<&str>,
    ) -> Result<(Vec<u8>, ByteRange, u64)> {
        let manifest = self.fetch_manifest(cid).await?;
        let total = manifest.total_size;
        match parse_range(range_header, total) {
            RangeOutcome::Full => {
                let bytes = self.reassemble_span(
                    &manifest,
                    ChunkSpan {
                        first_chunk: 0,
                        last_chunk: manifest.chunks.len().saturating_sub(1) as u64,
                        head_skip: 0,
                        out_len: total,
                    },
                )
                .await?;
                Ok((bytes, ByteRange { start: 0, end: total.saturating_sub(1) }, total))
            }
            RangeOutcome::Partial(range) => {
                let span = chunks_for_range(&manifest, range)
                    .ok_or_else(|| anyhow!("manifest {cid} has zero chunk_size"))?;
                let joined = self.reassemble_span(&manifest, span).await?;
                let bytes = slice_span(&joined, span)?;
                Ok((bytes, range, total))
            }
            RangeOutcome::Unsatisfiable => {
                Err(anyhow!("range {:?} not satisfiable for object of {total} bytes", range_header))
            }
        }
    }

    /// Resolve and parse an object's manifest blob.
    async fn fetch_manifest(&self, cid: &str) -> Result<Manifest> {
        let manifest_bytes =
            self.ce.get_blob(cid).await.with_context(|| format!("fetching manifest {cid}"))?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| anyhow!("{cid} is not a v1 object manifest: {e}"))?;
        if !manifest.is_v1() {
            return Err(anyhow!("unsupported manifest kind: {}", manifest.kind));
        }
        Ok(manifest)
    }

    /// Pull chunks `span.first_chunk..=span.last_chunk` from the blob store, verify each against its
    /// CID, and return them concatenated (the caller slices to the exact range). An empty object
    /// yields empty bytes.
    async fn reassemble_span(&self, manifest: &Manifest, span: ChunkSpan) -> Result<Vec<u8>> {
        if manifest.chunks.is_empty() {
            return Ok(Vec::new());
        }
        let last = (span.last_chunk as usize).min(manifest.chunks.len() - 1);
        let first = span.first_chunk as usize;
        let mut out = Vec::new();
        for chunk_cid in &manifest.chunks[first..=last] {
            let chunk = self
                .ce
                .get_blob(chunk_cid)
                .await
                .with_context(|| format!("fetching chunk {chunk_cid}"))?;
            let got = blob_cid(&chunk);
            if got != *chunk_cid {
                return Err(anyhow!(
                    "chunk verification failed: expected {chunk_cid}, got {got}"
                ));
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    /// Discover candidate edges from the DHT + atlas + on-chain history, ranked best-first, and
    /// return up to `n` distinct edge NodeIds to replicate to (excluding `exclude`).
    ///
    /// Best-effort discovery: an edge advertised on the DHT but absent from the atlas is still a
    /// candidate (with zero capacity/history signals), so a freshly-joined edge is reachable.
    pub async fn pick_edges(&self, n: usize, exclude: &[String]) -> Result<Vec<String>> {
        let advertised = self.ce.find_service(proto::SERVICE_EDGE).await.unwrap_or_default();
        let atlas = self.ce.atlas().await.unwrap_or_default();
        let mut candidates: Vec<EdgeCandidate> = Vec::new();
        for id in &advertised {
            let entry = atlas.iter().find(|e| &e.node_id == id);
            let delivered_work = self
                .ce
                .history(id)
                .await
                .map(|h| h.delivered_work())
                .unwrap_or(0);
            candidates.push(EdgeCandidate {
                node_id: id.clone(),
                delivered_work,
                last_seen_secs: entry.map(|e| e.last_seen_secs).unwrap_or(u64::MAX),
                mem_mb: entry.map(|e| e.mem_mb).unwrap_or(0),
            });
        }
        Ok(select(&candidates, n, exclude))
    }

    /// Ask `edge` to fetch-and-cache `cid` (the `cdn:cache` action). `caps` is the hex capability
    /// chain (empty for an edge that accepts public replication). Returns the edge's reply.
    pub async fn replicate_to(
        &self,
        edge: &str,
        cid: &str,
        bytes_len: u64,
        ttl_secs: u64,
        caps: &str,
    ) -> Result<proto::CacheResp> {
        let req = proto::CacheReq {
            caps: caps.to_string(),
            cid: cid.to_string(),
            bytes_len,
            ttl_secs,
        };
        let payload = serde_json::to_vec(&req)?;
        let reply = self
            .ce
            .request(edge, proto::TOPIC_CACHE, &payload, 30_000)
            .await
            .with_context(|| format!("cdn/cache request to {edge}"))?;
        serde_json::from_slice(&reply).map_err(|e| anyhow!("bad cdn/cache reply from {edge}: {e}"))
    }

    /// Probe whether `edge` still holds `cid` (the cheap `cdn/status` action).
    pub async fn probe(&self, edge: &str, cid: &str, caps: &str) -> Result<proto::StatusResp> {
        let req = proto::StatusReq { caps: caps.to_string(), cid: cid.to_string() };
        let payload = serde_json::to_vec(&req)?;
        let reply = self
            .ce
            .request(edge, proto::TOPIC_STATUS, &payload, 15_000)
            .await
            .with_context(|| format!("cdn/status request to {edge}"))?;
        serde_json::from_slice(&reply).map_err(|e| anyhow!("bad cdn/status reply from {edge}: {e}"))
    }

    /// Ask `edge` to evict `cid` from its cache (the `cdn:purge` action).
    pub async fn purge_at(&self, edge: &str, cid: &str, caps: &str) -> Result<proto::PurgeResp> {
        let req = proto::PurgeReq { caps: caps.to_string(), cid: cid.to_string() };
        let payload = serde_json::to_vec(&req)?;
        let reply = self
            .ce
            .request(edge, proto::TOPIC_PURGE, &payload, 15_000)
            .await
            .with_context(|| format!("cdn/purge request to {edge}"))?;
        serde_json::from_slice(&reply).map_err(|e| anyhow!("bad cdn/purge reply from {edge}: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_for_is_cid_path() {
        assert_eq!(CdnClient::url_for("abc123"), "/cdn/abc123");
    }

    #[test]
    fn put_result_shape() {
        let r = PutResult {
            cid: "deadbeef".into(),
            bytes_len: 10,
            url: CdnClient::url_for("deadbeef"),
        };
        assert_eq!(r.url, "/cdn/deadbeef");
        assert_eq!(r.bytes_len, 10);
    }
}
