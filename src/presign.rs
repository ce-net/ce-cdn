//! Presigned, time-limited public links — the Cloud CDN "signed URL" analog.
//!
//! Proof-of-possession ([`crate::pop`]) is the strongest gate: it requires the caller to hold a
//! private key and mint a per-request signature. But sometimes a publisher wants to hand a *plain
//! URL* to a consumer who holds no CE key at all (an email link, a `<video src>` tag, a download
//! button) and still keep the content otherwise private and the access time-bounded. That is a
//! **presigned link**: the publisher signs `(cid, expires)` once with a key the edge trusts, and
//! embeds the signature in the URL query string. Anyone with the link can fetch until it expires;
//! no client key is needed.
//!
//! ## Wire format
//! `GET /cdn/<cid>?exp=<unix_secs>&sig=<sig_hex>` where `sig_hex` is the 64-byte Ed25519 signature
//! (128 hex chars) of [`presign_challenge`] over `(cid, expires)`, produced by a *signer key* the
//! edge accepts (its own key or a configured presign root). The signature is bound to the exact CID
//! and an expiry, so a link cannot be retargeted to another object or used after it lapses.
//!
//! ## Trust
//! An edge accepts presigned links only for signer keys it is configured to trust (`presign_keys`),
//! exactly mirroring the `roots` model for capability chains. With no configured presign key, the
//! feature is off and every private fetch must use proof-of-possession + a capability chain.

use ce_identity::NodeId;

/// Domain separation tag for presigned-link signatures — distinct from the PoP domain and every
/// other signed message, so a presign signature can never be replayed as a different proof.
const PRESIGN_DOMAIN: &[u8] = b"ce-cdn-presign-v1";

/// Maximum lifetime an edge will honor for a presigned link, regardless of the embedded `exp`. A
/// generous 7 days (presigned links are meant to be shareable for a while) while still bounding a
/// leaked link's blast radius.
pub const MAX_PRESIGN_TTL_SECS: u64 = 7 * 24 * 3600;

/// The exact bytes a publisher signs (and the edge re-derives and verifies) for a presigned link:
/// domain-separated, then the CID (length-prefixed) and the expiry.
pub fn presign_challenge(cid: &str, expires: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(PRESIGN_DOMAIN.len() + 8 + cid.len() + 8);
    m.extend_from_slice(PRESIGN_DOMAIN);
    m.extend_from_slice(&(cid.len() as u64).to_le_bytes());
    m.extend_from_slice(cid.as_bytes());
    m.extend_from_slice(&expires.to_le_bytes());
    m
}

/// A parsed presign query: the claimed expiry and the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presign {
    /// Unix seconds after which the link is invalid.
    pub expires: u64,
    /// The Ed25519 signature over [`presign_challenge`].
    pub sig: [u8; 64],
}

/// Why a presigned-link check failed (logging/diagnostics only; the edge maps all to a single
/// denial so it never reveals which factor failed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresignError {
    /// No `exp`/`sig` query parameters present.
    Missing,
    /// The query could not be parsed (bad shape / hex / lengths).
    Malformed,
    /// The link's `exp` is in the past.
    Expired,
    /// The link's `exp` is further out than [`MAX_PRESIGN_TTL_SECS`] allows.
    TooFarFuture,
    /// The signature did not verify against any trusted signer key.
    BadSignature,
}

/// Parse the `exp` and `sig` parameters out of a raw URL query string (the part after `?`). Returns
/// `None` if either is absent or malformed.
pub fn parse_query(query: &str) -> Option<Presign> {
    let mut exp: Option<u64> = None;
    let mut sig: Option<[u8; 64]> = None;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=')?;
        match k {
            "exp" => exp = v.trim().parse().ok(),
            "sig" => sig = hex::decode(v.trim()).ok().and_then(|b| b.try_into().ok()),
            _ => {}
        }
    }
    Some(Presign { expires: exp?, sig: sig? })
}

/// Verify a presigned link for `cid` against the set of `trusted` signer keys at `now`. Succeeds
/// only if the query parses, is unexpired and within [`MAX_PRESIGN_TTL_SECS`], and its signature
/// verifies against at least one trusted key. `query` is the raw query string (may be empty).
pub fn verify_presign(
    query: &str,
    cid: &str,
    trusted: &[NodeId],
    now: u64,
) -> Result<(), PresignError> {
    if query.trim().is_empty() || trusted.is_empty() {
        return Err(PresignError::Missing);
    }
    let p = parse_query(query).ok_or(PresignError::Malformed)?;
    if p.expires < now {
        return Err(PresignError::Expired);
    }
    if p.expires > now.saturating_add(MAX_PRESIGN_TTL_SECS) {
        return Err(PresignError::TooFarFuture);
    }
    let msg = presign_challenge(cid, p.expires);
    for key in trusted {
        if ce_identity::verify(key, &msg, &p.sig).is_ok() {
            return Ok(());
        }
    }
    Err(PresignError::BadSignature)
}

/// Mint a presigned link's query string `exp=<expires>&sig=<sig_hex>` by signing
/// [`presign_challenge`] for `(cid, expires)` with `sign`. Append it to `/cdn/<cid>?` to form the
/// shareable URL.
pub fn presign_query(sign: impl FnOnce(&[u8]) -> [u8; 64], cid: &str, expires: u64) -> String {
    let sig = sign(&presign_challenge(cid, expires));
    format!("exp={expires}&sig={}", hex::encode(sig))
}

/// Convenience: the full relative presigned URL `"/cdn/<cid>?exp=...&sig=..."`.
pub fn presign_url(sign: impl FnOnce(&[u8]) -> [u8; 64], cid: &str, expires: u64) -> String {
    format!("/cdn/{cid}?{}", presign_query(sign, cid, expires))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ce_identity::Identity;

    fn ident(tag: &str) -> Identity {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ce-cdn-presign-{}-{n}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    #[test]
    fn valid_presign_verifies() {
        let signer = ident("signer");
        let q = presign_query(|m| signer.sign(m), "cidA", 1000);
        assert_eq!(verify_presign(&q, "cidA", &[signer.node_id()], 900), Ok(()));
    }

    #[test]
    fn presign_url_is_well_formed_and_verifies() {
        let signer = ident("url");
        let url = presign_url(|m| signer.sign(m), "cidB", 2000);
        let (path, query) = url.split_once('?').unwrap();
        assert_eq!(path, "/cdn/cidB");
        assert_eq!(verify_presign(query, "cidB", &[signer.node_id()], 1900), Ok(()));
    }

    #[test]
    fn presign_for_wrong_cid_is_rejected() {
        let signer = ident("wrongcid");
        let q = presign_query(|m| signer.sign(m), "cidA", 1000);
        assert_eq!(
            verify_presign(&q, "cidB", &[signer.node_id()], 900),
            Err(PresignError::BadSignature)
        );
    }

    #[test]
    fn presign_signed_by_untrusted_key_is_rejected() {
        let signer = ident("untrusted");
        let other = ident("other");
        let q = presign_query(|m| signer.sign(m), "c", 1000);
        assert_eq!(verify_presign(&q, "c", &[other.node_id()], 900), Err(PresignError::BadSignature));
    }

    #[test]
    fn expired_and_far_future_are_rejected() {
        let signer = ident("times");
        let q = presign_query(|m| signer.sign(m), "c", 1000);
        assert_eq!(verify_presign(&q, "c", &[signer.node_id()], 1001), Err(PresignError::Expired));
        let far = presign_query(|m| signer.sign(m), "c", 100 + MAX_PRESIGN_TTL_SECS + 10_000);
        assert_eq!(
            verify_presign(&far, "c", &[signer.node_id()], 100),
            Err(PresignError::TooFarFuture)
        );
    }

    #[test]
    fn missing_or_malformed_query_is_rejected() {
        let signer = ident("missing");
        let trusted = [signer.node_id()];
        assert_eq!(verify_presign("", "c", &trusted, 0), Err(PresignError::Missing));
        assert_eq!(verify_presign("exp=1000", "c", &trusted, 0), Err(PresignError::Malformed));
        assert_eq!(verify_presign("sig=zz", "c", &trusted, 0), Err(PresignError::Malformed));
        // No trusted keys configured -> feature off -> Missing (treated as no presign offered).
        let q = presign_query(|m| signer.sign(m), "c", 1000);
        assert_eq!(verify_presign(&q, "c", &[], 900), Err(PresignError::Missing));
    }
}
