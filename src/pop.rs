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
//! Header `X-Ce-Proof: <expires_unix_secs>.<nonce_hex>.<sig_hex>`, where `sig_hex` is the 64-byte
//! Ed25519 signature (128 hex chars) of [`challenge`] over
//! `(requester_node_id, cid, ability, nonce, expires)` and `nonce` is a 16-byte random value
//! (32 hex chars). The signature is bound to the requester key, the CID, the ability, a fresh nonce,
//! and an expiry, so it cannot be replayed for a different object, a different ability, or after it
//! expires. The nonce additionally lets an edge reject a *captured* proof reused within its (≤5min)
//! validity window via a bounded seen-nonce set ([`ReplayGuard`]).

use std::collections::VecDeque;
use std::collections::HashSet;

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
pub fn challenge(
    requester: &NodeId,
    cid: &str,
    ability: &str,
    nonce: &[u8; 16],
    expires: u64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(POP_DOMAIN.len() + 32 + cid.len() + ability.len() + 16 + 24);
    m.extend_from_slice(POP_DOMAIN);
    m.extend_from_slice(requester);
    m.extend_from_slice(&(cid.len() as u64).to_le_bytes());
    m.extend_from_slice(cid.as_bytes());
    m.extend_from_slice(&(ability.len() as u64).to_le_bytes());
    m.extend_from_slice(ability.as_bytes());
    m.extend_from_slice(nonce);
    m.extend_from_slice(&expires.to_le_bytes());
    m
}

/// A parsed `X-Ce-Proof` header: the claimed expiry, the nonce, and the 64-byte signature.
#[derive(Debug, Clone)]
pub struct Proof {
    /// Unix seconds after which the proof is no longer valid.
    pub expires: u64,
    /// The 16-byte anti-replay nonce.
    pub nonce: [u8; 16],
    /// The Ed25519 signature over [`challenge`].
    pub sig: [u8; 64],
}

/// Parse an `X-Ce-Proof` header value of the form `<expires>.<nonce_hex>.<sig_hex>`. Returns `None`
/// on any malformation (missing separators, non-numeric expiry, bad hex, wrong nonce/signature
/// length) so a garbled proof is a clean denial rather than a panic.
pub fn parse_proof(header: &str) -> Option<Proof> {
    let mut parts = header.trim().splitn(3, '.');
    let exp_str = parts.next()?;
    let nonce_hex = parts.next()?;
    let sig_hex = parts.next()?;
    let expires: u64 = exp_str.trim().parse().ok()?;
    let nonce: [u8; 16] = hex::decode(nonce_hex.trim()).ok()?.try_into().ok()?;
    let sig: [u8; 64] = hex::decode(sig_hex.trim()).ok()?.try_into().ok()?;
    Some(Proof { expires, nonce, sig })
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
    /// The proof's nonce was already seen within its validity window (a replay).
    Replay,
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
    let msg = challenge(requester, cid, ability, &proof.nonce, proof.expires);
    ce_identity::verify(requester, &msg, &proof.sig).map_err(|_| PopError::BadSignature)
}

/// Like [`verify_pop`], but additionally rejects a proof whose `(requester, nonce)` was already
/// accepted within its validity window — defeating replay of a captured proof inside the ≤5-minute
/// window. The `guard` is mutated only on an otherwise-valid proof, so an invalid proof never
/// pollutes the seen set. Bounded memory: the guard is a FIFO ring.
pub fn verify_pop_once(
    guard: &mut ReplayGuard,
    proof_header: Option<&str>,
    requester: &NodeId,
    cid: &str,
    ability: &str,
    now: u64,
) -> Result<(), PopError> {
    verify_pop(proof_header, requester, cid, ability, now)?;
    // The proof verified; bind it to its nonce to make it single-use within its window.
    let proof = parse_proof(proof_header.unwrap_or("").trim()).ok_or(PopError::Malformed)?;
    if !guard.accept(requester, &proof.nonce) {
        return Err(PopError::Replay);
    }
    Ok(())
}

/// A bounded anti-replay set over `(requester, nonce)` pairs. Each accepted proof's nonce is
/// remembered so a captured proof cannot be reused within its validity window; the set is a FIFO
/// ring capped at `capacity`, so memory is fixed regardless of request volume (eviction can only
/// re-admit a nonce older than `capacity` accepted proofs, which the short proof TTL makes a
/// non-issue).
#[derive(Debug)]
pub struct ReplayGuard {
    seen: HashSet<[u8; 48]>,
    order: VecDeque<[u8; 48]>,
    capacity: usize,
}

impl ReplayGuard {
    /// A new guard retaining at most `capacity` recent `(requester, nonce)` pairs (`0` -> `1`).
    pub fn new(capacity: usize) -> Self {
        ReplayGuard { seen: HashSet::new(), order: VecDeque::new(), capacity: capacity.max(1) }
    }

    /// Record `(requester, nonce)`. Returns `true` if it is newly seen (accept the proof), `false`
    /// if it was already present within the retained window (a replay — reject).
    pub fn accept(&mut self, requester: &NodeId, nonce: &[u8; 16]) -> bool {
        let mut key = [0u8; 48];
        key[..32].copy_from_slice(requester);
        key[32..].copy_from_slice(nonce);
        if !self.seen.insert(key) {
            return false;
        }
        self.order.push_back(key);
        while self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }

    /// The number of retained pairs (never exceeds `capacity`).
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether the guard is empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Default capacity for an edge's [`ReplayGuard`]: large enough that no realistic in-window proof
/// volume re-admits a nonce, small enough that the memory ceiling is trivial (~16K * 48 bytes).
pub const REPLAY_GUARD_CAPACITY: usize = 16_384;

/// Generate a fresh 16-byte anti-replay nonce. Uniqueness (not secrecy) is what matters: we hash a
/// monotonic process counter, the wall clock (nanoseconds), and the process id, so two proofs minted
/// back-to-back in the same process carry distinct nonces. Uses `sha2` (already a dependency) to
/// avoid pulling in a CSPRNG for a value that only needs to be unique.
pub fn gen_nonce() -> [u8; 16] {
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut h = Sha256::new();
    h.update(seq.to_le_bytes());
    h.update(nanos.to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    let digest = h.finalize();
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&digest[..16]);
    nonce
}

/// Mint an `X-Ce-Proof` header value: sign the [`challenge`] for `(cid, ability, nonce, expires)`
/// with `signer` and format `<expires>.<nonce_hex>.<sig_hex>`. A fresh nonce is generated so the
/// proof is single-use (replay-rejectable). The requester's key is `requester` (the signer's own
/// node id). Used by the CDN client and by tests; kept in the library so producers and the verifier
/// share one canonical encoding.
pub fn mint_proof(
    requester: &NodeId,
    sign: impl FnOnce(&[u8]) -> [u8; 64],
    cid: &str,
    ability: &str,
    expires: u64,
) -> String {
    mint_proof_with_nonce(requester, sign, cid, ability, &gen_nonce(), expires)
}

/// Like [`mint_proof`] but with a caller-supplied nonce (used by tests to assert replay rejection).
pub fn mint_proof_with_nonce(
    requester: &NodeId,
    sign: impl FnOnce(&[u8]) -> [u8; 64],
    cid: &str,
    ability: &str,
    nonce: &[u8; 16],
    expires: u64,
) -> String {
    let msg = challenge(requester, cid, ability, nonce, expires);
    let sig = sign(&msg);
    format!("{expires}.{}.{}", hex::encode(nonce), hex::encode(sig))
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
        assert_eq!(verify_pop(Some("xx.zz.qq"), &id, "c", "cdn:read", 0), Err(PopError::Malformed));
        // Two parts only (missing the nonce field) -> malformed.
        assert_eq!(verify_pop(Some("1000.dead"), &id, "c", "cdn:read", 0), Err(PopError::Malformed));
        // Right shape, wrong-length nonce.
        let bad_nonce = format!("1000.{}.{}", "ab", "cd".repeat(64));
        assert_eq!(verify_pop(Some(&bad_nonce), &id, "c", "cdn:read", 0), Err(PopError::Malformed));
        // Right shape, wrong-length signature.
        let bad_sig = format!("1000.{}.dead", hex::encode([0u8; 16]));
        assert_eq!(verify_pop(Some(&bad_sig), &id, "c", "cdn:read", 0), Err(PopError::Malformed));
    }

    #[test]
    fn replay_guard_rejects_reused_proof_but_accepts_fresh() {
        let who = ident("replay");
        let id = who.node_id();
        let nonce = [7u8; 16];
        let hdr = mint_proof_with_nonce(&id, |m| who.sign(m), "c", "cdn:read", &nonce, 1000);
        let mut guard = ReplayGuard::new(64);
        // First use of this nonce: accepted.
        assert_eq!(verify_pop_once(&mut guard, Some(&hdr), &id, "c", "cdn:read", 900), Ok(()));
        // Replay of the SAME proof: rejected.
        assert_eq!(
            verify_pop_once(&mut guard, Some(&hdr), &id, "c", "cdn:read", 900),
            Err(PopError::Replay)
        );
        // A fresh nonce (different proof) is still accepted.
        let hdr2 = mint_proof(&id, |m| who.sign(m), "c", "cdn:read", 1000);
        assert_eq!(verify_pop_once(&mut guard, Some(&hdr2), &id, "c", "cdn:read", 900), Ok(()));
    }

    #[test]
    fn replay_guard_does_not_record_invalid_proofs() {
        let who = ident("replay-invalid");
        let id = who.node_id();
        let mut guard = ReplayGuard::new(64);
        // An expired proof is rejected and must not consume guard space.
        let hdr = mint_proof(&id, |m| who.sign(m), "c", "cdn:read", 1000);
        assert_eq!(
            verify_pop_once(&mut guard, Some(&hdr), &id, "c", "cdn:read", 2000),
            Err(PopError::Expired)
        );
        assert!(guard.is_empty(), "an invalid proof must not pollute the replay set");
    }

    #[test]
    fn replay_guard_stays_bounded() {
        let mut g = ReplayGuard::new(100);
        let req = [1u8; 32];
        for i in 0..10_000u64 {
            let mut nonce = [0u8; 16];
            nonce[..8].copy_from_slice(&i.to_le_bytes());
            g.accept(&req, &nonce);
            assert!(g.len() <= 100);
        }
        assert_eq!(g.len(), 100);
    }

    #[test]
    fn gen_nonce_is_distinct() {
        let a = gen_nonce();
        let b = gen_nonce();
        assert_ne!(a, b, "consecutive nonces must differ");
    }

    #[test]
    fn expired_proof_is_rejected() {
        let who = ident("expired");
        let id = who.node_id();
        let hdr = mint_proof(&id, |m| who.sign(m), "c", "cdn:read", 1000);
        assert_eq!(verify_pop(Some(&hdr), &id, "c", "cdn:read", 1001), Err(PopError::Expired));
    }

    #[test]
    fn clock_skew_boundaries_are_inclusive() {
        let who = ident("boundary");
        let id = who.node_id();
        // expires == now: still valid (expiry is the last valid instant).
        let at_now = mint_proof(&id, |m| who.sign(m), "c", "cdn:read", 1000);
        assert_eq!(verify_pop(Some(&at_now), &id, "c", "cdn:read", 1000), Ok(()));
        // expires == now + MAX_PROOF_TTL_SECS: the furthest-future proof still accepted.
        let max_future = mint_proof(&id, |m| who.sign(m), "c", "cdn:read", 1000 + MAX_PROOF_TTL_SECS);
        assert_eq!(verify_pop(Some(&max_future), &id, "c", "cdn:read", 1000), Ok(()));
        // One second further out: rejected.
        let too_far =
            mint_proof(&id, |m| who.sign(m), "c", "cdn:read", 1000 + MAX_PROOF_TTL_SECS + 1);
        assert_eq!(
            verify_pop(Some(&too_far), &id, "c", "cdn:read", 1000),
            Err(PopError::TooFarFuture)
        );
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
