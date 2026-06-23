//! End-to-end CDN flow against a **local CE node** (`ce start` must be running on :8844):
//! store an object, fetch it whole, then fetch a byte range — all CID-verified and trustless.
//!
//! Run with: `cargo run --example put_get_range`

use ce_cdn::client::CdnClient;
use ce_rs::CeClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ce = CeClient::local();
    if !ce.health().await.unwrap_or(false) {
        eprintln!("no CE node at {} — start one with `ce start`", ce.base_url());
        return Ok(());
    }
    let cdn = CdnClient::new(ce);

    // A 3 MiB object (chunked into three 1 MiB content-addressed blocks).
    let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 256) as u8).collect();
    let put = cdn.put(&data).await?;
    println!("put {} bytes -> cid {}  url {}", put.bytes_len, put.cid, put.url);

    // Fetch the whole object back (every chunk re-verified against its CID).
    let whole = cdn.get(&put.cid).await?;
    assert_eq!(whole, data, "round-trip mismatch");
    println!("got {} bytes back (verified)", whole.len());

    // Fetch a byte range that straddles a chunk boundary — only the covering chunks are pulled.
    let (range_bytes, range, total) = cdn.get_range(&put.cid, Some("bytes=1048570-1048580")).await?;
    println!(
        "ranged fetch bytes {}-{}/{} -> {} bytes",
        range.start,
        range.end,
        total,
        range_bytes.len()
    );
    assert_eq!(range_bytes, &data[1_048_570..=1_048_580]);
    println!("range verified");

    Ok(())
}
