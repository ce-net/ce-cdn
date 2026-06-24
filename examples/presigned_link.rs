//! Mint and verify a **presigned, time-limited public link** — fully offline (no CE node needed).
//!
//! A presigned link lets a publisher share otherwise-private content as a plain URL: the publisher
//! signs `(cid, expires)` with a key the serving edge trusts, and anyone with the link can fetch
//! until it expires — no client key required. This is the Cloud-CDN signed-URL analog.
//!
//! Run with: `cargo run --example presigned_link`

use ce_cdn::presign;
use ce_identity::Identity;

fn main() -> anyhow::Result<()> {
    // The publisher's key (in production this is the node's CE identity; here a throwaway key).
    let dir = std::env::temp_dir().join("ce-cdn-example-presign");
    std::fs::create_dir_all(&dir)?;
    let publisher = Identity::load_or_generate(&dir)?;

    let cid = "a".repeat(64); // a content id (64 hex chars)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let expires = now + 3600; // valid for one hour

    // Mint the link.
    let url = presign::presign_url(|m| publisher.sign(m), &cid, expires);
    println!("presigned link (share this):");
    println!("  /cdn/{cid}?{}", url.split_once('?').map(|(_, q)| q).unwrap_or(""));

    // The serving edge is configured to trust the publisher's key (`--presign-key <node-id>`).
    let trusted = [publisher.node_id()];
    let query = url.split_once('?').map(|(_, q)| q).unwrap_or("");

    // A valid, unexpired link verifies.
    presign::verify_presign(query, &cid, &trusted, now)
        .map_err(|e| anyhow::anyhow!("expected the link to verify, got {e:?}"))?;
    println!("link verifies against the publisher's key (within its window): OK");

    // The same link is rejected once it expires.
    match presign::verify_presign(query, &cid, &trusted, expires + 1) {
        Err(presign::PresignError::Expired) => println!("link correctly rejected after expiry: OK"),
        other => anyhow::bail!("expected Expired after the window, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
