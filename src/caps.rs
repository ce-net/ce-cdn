//! Capability loading for the client side.
//!
//! ce-cdn does not mint trust — it presents a signed, attenuating `ce-cap` chain that an edge host
//! authorizes (rooted at the edge's own key or a configured org root) before serving *private*
//! content or accepting a cache/purge request. The chain is produced out-of-band (e.g.
//! `ce grant <holder> --can cdn:read,cdn:cache …` on the edge or an org root, then handed to the
//! consumer's wallet). The client reads the hex-encoded chain from, in order:
//!   1. the explicit `--caps <hex>` flag (highest precedence);
//!   2. the `$CE_CDN_CAPS` environment variable;
//!   3. `<config dir>/ce-cdn/caps` (a file containing the hex chain).
//!
//! Public content needs no chain — an absent chain resolves to the empty string, which an edge
//! serving public CIDs accepts. For private content the edge's `authorize` rejects the empty chain,
//! surfacing a clear "denied" rather than guessing.

use std::path::PathBuf;

/// Resolve the capability chain hex the client should present. `explicit` is the `--caps` flag.
pub fn resolve(explicit: Option<&str>) -> String {
    if let Some(c) = explicit.map(str::trim).filter(|c| !c.is_empty()) {
        return c.to_string();
    }
    if let Ok(c) = std::env::var("CE_CDN_CAPS") {
        let c = c.trim().to_string();
        if !c.is_empty() {
            return c;
        }
    }
    if let Some(p) = caps_file()
        && let Ok(c) = std::fs::read_to_string(&p)
    {
        let c = c.trim().to_string();
        if !c.is_empty() {
            return c;
        }
    }
    String::new()
}

fn caps_file() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("CE_CDN_DIR") {
        return Some(PathBuf::from(d).join("caps"));
    }
    directories::ProjectDirs::from("", "", "ce-cdn").map(|p| p.config_dir().join("caps"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Tests in this module mutate process-global env vars (`CE_CDN_CAPS` / `CE_CDN_DIR`); cargo runs
    // them in parallel within one process, so they must not interleave. Serialize them on one lock.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn explicit_takes_precedence() {
        // Does not touch env, but the explicit branch returns before any env read regardless.
        assert_eq!(resolve(Some("deadbeef")), "deadbeef");
        assert_eq!(resolve(Some("  abc  ")), "abc");
    }

    #[test]
    fn empty_explicit_falls_through_to_none_when_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("CE_CDN_CAPS");
            std::env::set_var("CE_CDN_DIR", "/nonexistent-ce-cdn-dir-xyz");
        }
        assert_eq!(resolve(Some("  ")), "");
        unsafe {
            std::env::remove_var("CE_CDN_DIR");
        }
    }

    #[test]
    fn env_var_is_used_when_no_explicit() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("CE_CDN_CAPS", "  envchain  ");
        }
        assert_eq!(resolve(None), "envchain");
        unsafe {
            std::env::remove_var("CE_CDN_CAPS");
        }
    }
}
