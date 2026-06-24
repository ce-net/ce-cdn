//! # ce-cdn — content-delivery / edge-cache network over CE
//!
//! ce-cdn is an **application built on CE primitives** (the SDK tier, like `swarm` / `rdev` /
//! `ce-pin`), not a node feature. It turns CE's content-addressed blob layer + ce-pin-style
//! replication into a **CDN**: cache-and-serve content by CID with edge replication, TTL eviction,
//! HTTP range reads, and capability-gated private content. The killer property is that
//! **content-addressing IS the cache key and the integrity proof** — an object's CID is the hash of
//! its manifest, and `get_object` re-verifies every chunk against its CID, so an edge can never
//! serve bytes the publisher did not publish, and a cache cannot be poisoned. Immutable bytes also
//! make cache-control trivial: a CID is `immutable`, so the only reason to drop an entry is TTL or
//! eviction, never staleness.
//!
//! ## Shape
//! - [`cidrange`]    — pure CID/HTTP-range math: parse `Range`, map a byte range onto chunks, slice.
//! - [`cache`]       — the edge cache: TTL + LRU eviction + cache-hit accounting (pure, clock-injected).
//! - [`edge`]        — the HTTP edge handler: shape a response (status, cache headers, range) from cache state.
//! - [`proto`]       — the `cdn/*` mesh wire protocol (cache / read / purge / status) + abilities.
//! - [`replication`] — pure edge-ranking (atlas capacity + on-chain history) + re-replication policy.
//! - [`catalog`]     — the publisher-side index (`cid -> Content + edge replicas`), persisted as JSON.
//! - [`caps`]        — resolving the `ce-cap` chain a client presents to edges.
//! - [`pop`]         — proof-of-possession for the HTTP edge: a short signed challenge proving the
//!   caller holds the requester key, so `X-Ce-Node-Id` is verified, not trusted.
//! - [`client`]      — put / get (+ range) / purge / replicate over `ce-rs`.
//! - [`host`]        — the capability-gated edge serve loop (caches + serves, public or cap-gated).
//! - [`server`]      — the HTTP front-end: a `hyper` server exposing `GET /cdn/<cid>` (+ `/status`,
//!   `/health`) mapped onto the pure [`edge::serve`] handler.
//!
//! ## Trust & money (honoring CE rules)
//! Authorization is the one CE primitive: an edge verifies a signed, attenuating `ce-cap` chain
//! (rooted at its own key or a configured org root) before serving *private* content or honoring a
//! cache/purge. Public content needs no chain. Money is integer base units (1 credit = 10^18 base
//! units) carried as decimal strings — never floats; edge rent is priced/paid via CE payment
//! channels, which the CLI wires up incrementally.

pub mod cache;
pub mod caps;
pub mod catalog;
pub mod cidrange;
pub mod client;
pub mod edge;
pub mod host;
pub mod limits;
pub mod maintain;
pub mod pop;
pub mod presign;
pub mod proto;
pub mod replication;
pub mod server;

/// Load accepted capability root keys for an edge: 64-hex NodeIds, one per line, `#` comments
/// allowed. Looked up at `$CE_CDN_ROOTS`, else `$CE_DATA_DIR/roots`, else
/// `~/.local/share/ce/roots` — mirroring the node's and ce-pin's `<data_dir>/roots`. An edge opts
/// into an org/fleet by listing that org's root key here; with no file, only self-issued chains are
/// honored.
pub fn load_roots() -> Vec<[u8; 32]> {
    use std::path::PathBuf;
    let path = std::env::var_os("CE_CDN_ROOTS")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("CE_DATA_DIR").map(|d| PathBuf::from(d).join("roots")))
        .or_else(|| {
            directories::ProjectDirs::from("", "", "ce").map(|p| p.data_dir().join("roots"))
        })
        .unwrap_or_else(|| PathBuf::from("roots"));
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .filter_map(|h| hex::decode(h).ok().and_then(|b| b.try_into().ok()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Both tests mutate `CE_CDN_ROOTS`; serialize them so parallel cargo runs don't interleave.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn load_roots_parses_hex_lines_and_skips_comments() {
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("ce-cdn-roots-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let roots = tmp.join("roots");
        let key = "11".repeat(32); // 32-byte hex
        std::fs::write(&roots, format!("# a comment\n{key}  # inline\n\n")).unwrap();
        unsafe {
            std::env::set_var("CE_CDN_ROOTS", &roots);
        }
        let loaded = load_roots();
        unsafe {
            std::env::remove_var("CE_CDN_ROOTS");
        }
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], [0x11u8; 32]);
    }

    #[test]
    fn load_roots_missing_file_is_empty() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("CE_CDN_ROOTS", "/nonexistent-ce-cdn-roots-xyz");
        }
        let loaded = load_roots();
        unsafe {
            std::env::remove_var("CE_CDN_ROOTS");
        }
        assert!(loaded.is_empty());
    }
}
