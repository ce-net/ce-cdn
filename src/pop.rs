//! Proof-of-possession for the HTTP edge.
//!
//! On the mesh path the requester `NodeId` is the cryptographically authenticated libp2p sender, so
//! holding a capability chain that names that node as its audience already proves possession of the
//! node's key. The HTTP path has no such transport-level authentication: anyone can set an
//! `X-Ce-Node-Id` header. Without a second factor, a leaked capability chain (it travels in a header,
//! so it can leak via logs / proxies / referrers) would let any caller set `X-Ce-Node-Id` to the
//! audience and read private content — silently downgrading the audience-bound capability to a
//! bearer token.
//!
//! This module closes that hole. The requester signs a short, expiring, request-bound challenge with
//! its node key; the edge verifies that signature against the claimed `X-Ce-Node-Id` *before* it is
//! ever treated as identity. So `X-Ce-Node-Id` is no longer trusted — it is proven. A leaked
//! capability chain is useless without the requester's private key, restoring the holder-binding
//! guarantee the mesh path has by construction. This mirrors ce-storage's presigned links: a short,
//! expiring, signed token bound to the exact request.
//!
//! ## Wire format
//! Header `X-Ce-Proof: <expires_unix_secs>.<sig_hex>`, where `sig_hex` is the 64-byte Ed25519
//! signature (128 hex chars) of [`challenge`] over `(requester_node_id, cid, ability, expires)`. The
//! signature is bound to the requester key, the CID, the ability, and an expiry, so it cannot be
//! replayed for a different object, a different ability, or after it expires.

use ce_identity::NodeId;

/// Domain separation tag — distinguishes a CDN HTTP proof-of-possession from every other signed
/// message in the system, so a signature minted for one purpose can never be reused as another.
const POP_DOMAIN: &[u8] = b"ce-cdn-http-pop-v1";

/// The maximum lifetime an edge will honor for a proof, regardless of the requester's claimed
/// `expires`. Bounds the replay window even if a client mints a far-future token. 5 minutes is ample
/// clock-skew slack while keeping a leaked proof short-lived.
pub const MAX_PROOF_TTL_SECS: u64 = 300;

/// The exact bytes a requester signs (and the edge re-derives and verifies) to prove possession of
/// its key for this specific request. Domain-separated, then the requester id, CID, ability, and
/// expiry, each length-prefixed so no two distinct tuples can ever collide into the same message.
pub fn challenge(requester: &NodeId, cid: &str, ability: &str, expires: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(POP_DOMAIN.len() + 32 + cid.len() + ability.len() + 24);
    m.extend_from_slice(POP_DOMAIN);
    m.extend_from_slice(requester);
    m.extend_from_slice(&(cid.len() as u64).to_le_bytes());
    m.extend_from_slice(cid.as_bytes());
    m.extend_from_slice(&(ability.len() as u64).to_le_bytes());
    m.extend_from_slice(ability.as_bytes());
    m.extend_from_slice(&expires.to_le_bytes());
    m
}

/// A parsed `X-Ce-Proof` header: the claimed expiry plus the 64-byte signature.
#[derive(Debug, Clone)]
pub struct Proof {
    /// Unix seconds after which the proof is no longer valid.
    pub expires: u64,
    /// The Ed25519 signature over [`challenge`].
    pub sig: [u8; 64],
}

/// Parse an `X-Ce-Proof` header value of the form `<expires>.<sig_hex>`. Returns `None` on any
/// malformation (missing separator, non-numeric expiry, bad hex, wrong signature length) so a
/// garbled proof is a clean denial rather than a panic.
pub fn parse_proof(header: &str) -> Option<Proof> {
    let (exp_str, sig_hex) = header.trim().split_once('.')?;
    let expires: u64 = exp_str.trim().parse().ok()?;
    let raw = hex::decode(sig_hex.trim()).ok()?;
    let sig: [u8; 64] = raw.try_into().ok()?;
    Some(Proof { expires, sig })
}

/// Why a proof-of-possession check failed. Carried only for logging/diagnostics; the HTTP edge maps
/// every variant to the same 403 so it never tells an attacker which factor was missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopError {
    /// No `X-Ce-Proof` header was presented.
    Missing,
    /// The header could not be parsed (bad shape / hex / lengths).
    Malformed,
    /// The proof's `expires` is in the past (relative to `now`).
    Expired,
    /// The proof's `expires` is further in the future than [`MAX_PROOF_TTL_SECS`] allows.
    TooFarFuture,
    /// The signature did not verify against the claimed requester key.
    BadSignature,
}

/// Verify a presented proof binds the caller to `requester` for `(cid, ability)` at `now`.
///
/// `proof_header` is the raw `X-Ce-Proof` value (`None`/empty when absent). Succeeds only if the
/// header parses, is unexpired and within [`MAX_PROOF_TTL_SECS`], and its signature verifies against
/// `requester`'s key over [`challenge`]. On success the caller has proven possession of
/// `requester`'s private key for this exact request, so `requester` may be trusted as identity.
pub fn verify_pop(
    proof_header: Option<&str>,
    requester: &NodeId,
    cid: &str,
    ability: &str,
    now: u64,
) -> Result<(), PopError> {
    let header = proof_header.map(str::trim).filter(|h| !h.is_empty()).ok_or(PopError::Missing)?;
    let proof = parse_proof(header).ok_or(PopError::Malformed)?;
    if proof.expires < now {
        return Err(PopError::Expired);
    }
    if proof.expires > now.saturating_add(MAX_PROOF_TTL_SECS) {
        return Err(PopError::TooFarFuture);
    }
    let msg = challenge(requester, cid, ability, proof.expires);
    ce_identity::verify(requester, &msg, &proof.sig).map_err(|_| PopError::BadSignature)
}

/// Mint an `X-Ce-Proof` header value: sign the [`challenge`] for `(cid, ability, expires)` with
/// `signer` and format `<expires>.<sig_hex>`. The requester's key is `requester` (the signer's own
/// node id). Used by the CDN client and by tests; kept in the library so producers and the verifier
/// share one canonical encoding.
pub fn mint_proof(
    requester: &NodeId,
    sign: impl FnOnce(&[u8]) -> [u8; 64],
    cid: &str,
    ability: &str,
    expires: u64,
) -> String {
    let msg = challenge(requester, cid, ability, expires);
    let sig = sign(&msg);
    format!("{expires}.{}", hex::encode(sig))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ce_identity::Identity;

    fn ident(tag: &str) -> Identity {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("ce-cdn-pop-{}-{n}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    #[test]
    fn valid_proof_verifies() {
        let who = ident("ok");
        let id = who.node_id();
        let hdr = mint_proof(&id, |m| who.sign(m), "cidA", "cdn:read", 1000);
        assert_eq!(verify_pop(Some(&hdr), &id, "cidA", "cdn:read", 900), Ok(()));
    }

    #[test]
    fn missing_proof_is_rejected() {
        let who = ident("missing");
        assert_eq!(
            verify_pop(None, &who.node_id(), "cidA", "cdn:read", 900),
            Err(PopError::Missing)
        );
        assert_eq!(
            verify_pop(Some("   "), &who.node_id(), "cidA", "cdn:read", 900),
            Err(PopError::Missing)
        );
    }

    #[test]
    fn malformed_proof_is_rejected() {
        let who = ident("malformed");
        let id = who.node_id();
        assert_eq!(verify_pop(Some("nodot"), &id, "c", "cdn:read", 0), Err(PopError::Malformed));
        assert_eq!(verify_pop(Some("xx.zz"), &id, "c", "cdn:read", 0), Err(PopError::Malformed));
        // Right shape, wrong-length signature.
        assert_eq!(verify_pop(Some("1000.dead"), &id, "c", "cdn:read", 0), Err(PopError::Malformed));
    }

    #[test]
    fn expired_proof_is_rejected() {
        let who = ident("expired");
        let id = who.node_id();
        let hdr = mint_proof(&id, |m| who.sign(m), "c", "cdn:read", 1000);
        assert_eq!(verify_pop(Some(&hdr), &id, "c", "cdn:read", 1001), Err(PopError::Expired));
    }

    #[test]
    fn far_future_proof_is_rejected() {
        let who = ident("future");
        let id = who.node_id();
        let hdr = mint_proof(&id, |m| who.sign(m), "c", "cdn:read", 10_000);
        // now=1000, expires=10000 -> 9000s > MAX_PROOF_TTL_SECS.
        assert_eq!(verify_pop(Some(&hdr), &id, "c", "cdn:read", 1000), Err(PopError::TooFarFuture));
    }

    #[test]
    fn proof_for_wrong_cid_is_rejected() {
        let who = ident("wrongcid");
        let id = who.node_id();
        let hdr = mint_proof(&id, |m| who.sign(m), "cidA", "cdn:read", 1000);
        assert_eq!(
            verify_pop(Some(&hdr), &id, "cidB", "cdn:read", 900),
            Err(PopError::BadSignature)
        );
    }

    #[test]
    fn proof_for_wrong_ability_is_rejected() {
        let who = ident("wrongability");
        let id = who.node_id();
        let hdr = mint_proof(&id, |m| who.sign(m), "c", "cdn:read", 1000);
        assert_eq!(
            verify_pop(Some(&hdr), &id, "c", "cdn:cache", 900),
            Err(PopError::BadSignature)
        );
    }

    #[test]
    fn proof_signed_by_other_key_is_rejected() {
        // The core leak: a chain audience-bound to `victim` cannot be used by `attacker`, because the
        // attacker cannot produce a proof that verifies against the victim's key.
        let victim = ident("victim");
        let attacker = ident("attacker");
        let victim_id = victim.node_id();
        // Attacker signs the challenge for the victim's id with the ATTACKER's key.
        let hdr = mint_proof(&victim_id, |m| attacker.sign(m), "c", "cdn:read", 1000);
        assert_eq!(
            verify_pop(Some(&hdr), &victim_id, "c", "cdn:read", 900),
            Err(PopError::BadSignature)
        );
    }
}
