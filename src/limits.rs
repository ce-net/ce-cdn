//! Resource limits and input validation — the DoS / memory-amplification guard rails.
//!
//! Every byte an edge accepts from an untrusted peer (a mesh `cdn/*` request, an HTTP header, a CID
//! in a path) is bounded here so a single malicious caller cannot OOM the edge or push it past the
//! SDK's wire ceiling. The constants are deliberately conservative and centralised so the policy is
//! one place, documented, and testable.

/// Largest object an edge will hex-encode into a single `cdn/read` mesh reply. The SDK's
/// request/reply transport carries one hex-encoded JSON payload; hex doubles the size, and the
/// whole thing is held in memory on both ends. Objects larger than this must be fetched over HTTP
/// (range-streamed) or by a chunk-aware path, never shipped whole over one AppRequest. 8 MiB of raw
/// bytes -> ~16 MiB of hex -> a bounded, safe single message.
pub const MAX_MESH_OBJECT_BYTES: u64 = 8 * 1024 * 1024;

/// Largest range (in bytes) an edge will serve in a single `cdn/read` reply. A range read is also
/// hex-encoded into one reply, so it is bounded by the same ceiling as a whole-object read.
pub const MAX_MESH_RANGE_BYTES: u64 = MAX_MESH_OBJECT_BYTES;

/// Largest decoded `cdn/*` request payload (JSON) an edge will accept. Requests are tiny (a CID, a
/// hex cap chain, a range string); anything beyond this is malformed or hostile. The hex on the
/// wire is twice this. 256 KiB comfortably fits a long delegated capability chain while refusing a
/// payload crafted to exhaust memory on decode.
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;

/// Largest capability-chain hex string accepted (before decode). A real attenuating chain is a few
/// hundred bytes per link; 128 KiB of hex (~64 KiB of chain) bounds the decode work an unauthorized
/// caller can force.
pub const MAX_CAPS_HEX_LEN: usize = 128 * 1024;

/// Largest CID string accepted in any path/field. CE object CIDs are 64 lowercase hex chars; we
/// allow a little slack for forward-compatible encodings but refuse anything that is obviously not
/// a content id (a cache-key-confusion / unbounded-key vector).
pub const MAX_CID_LEN: usize = 128;

/// A CE content id is a sha256 hex digest: exactly 64 lowercase hex characters. Returns `true` only
/// for a well-formed CID, so callers can reject a malformed/percent-encoded/overlong segment before
/// it ever reaches the cache or origin as a key.
///
/// ```
/// use ce_cdn::limits::is_valid_cid;
/// assert!(is_valid_cid(&"a".repeat(64)));
/// assert!(!is_valid_cid("not-a-cid"));
/// assert!(!is_valid_cid(&"A".repeat(64))); // uppercase rejected
/// ```
pub fn is_valid_cid(cid: &str) -> bool {
    cid.len() == 64 && cid.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A lenient CID check for path routing: non-empty, within [`MAX_CID_LEN`], and made only of
/// URL-safe content-id characters (hex plus the separators a future multibase/manifest scheme might
/// use). Stricter validation ([`is_valid_cid`]) is applied where the value is used as a real CID;
/// this is the first-line filter that keeps obviously-bad keys out of the system.
pub fn is_acceptable_cid_charset(cid: &str) -> bool {
    !cid.is_empty()
        && cid.len() <= MAX_CID_LEN
        && cid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_cid_is_64_lowercase_hex() {
        let good = "a".repeat(64);
        assert!(is_valid_cid(&good));
        assert!(is_valid_cid(&"0123456789abcdef".repeat(4)));
    }

    #[test]
    fn invalid_cid_rejected() {
        assert!(!is_valid_cid("")); // empty
        assert!(!is_valid_cid(&"a".repeat(63))); // too short
        assert!(!is_valid_cid(&"a".repeat(65))); // too long
        assert!(!is_valid_cid(&"A".repeat(64))); // uppercase not allowed
        assert!(!is_valid_cid(&"g".repeat(64))); // non-hex
        assert!(!is_valid_cid(&format!("{}/", "a".repeat(63)))); // slash
    }

    #[test]
    fn acceptable_charset_filters_bad_paths() {
        assert!(is_acceptable_cid_charset(&"a".repeat(64)));
        assert!(is_acceptable_cid_charset("obj-1.bin"));
        assert!(!is_acceptable_cid_charset("")); // empty
        assert!(!is_acceptable_cid_charset("has space"));
        assert!(!is_acceptable_cid_charset("a/b")); // slash
        assert!(!is_acceptable_cid_charset("%2e%2e")); // percent
        assert!(!is_acceptable_cid_charset(&"x".repeat(MAX_CID_LEN + 1))); // overlong
    }

    #[test]
    fn limits_are_coherent() {
        // Hex doubling must keep a max-object reply under a sane single-message ceiling. Read the
        // constants through local bindings so clippy does not flag a compile-time-constant assertion.
        let obj = MAX_MESH_OBJECT_BYTES;
        let range = MAX_MESH_RANGE_BYTES;
        let caps = MAX_CAPS_HEX_LEN;
        let req = MAX_REQUEST_BYTES;
        assert!(obj.saturating_mul(2) < 64 * 1024 * 1024);
        assert_eq!(range, obj);
        assert!(caps <= req.saturating_mul(2));
    }
}
