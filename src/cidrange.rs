//! Content-id helpers and HTTP-range math — the pure core of range / partial fetch.
//!
//! A CDN must serve `Range: bytes=...` requests (video seek, resumable downloads, parallel
//! segment fetch). Content is content-addressed: an object's CID is the hash of its [`Manifest`]
//! (from `ce-rs`), and the manifest lists fixed-size chunk CIDs. So a byte range maps onto a
//! *contiguous span of chunks*, each of which can be fetched-and-verified independently. This
//! module is pure (no network, no I/O) so the math is exhaustively unit/property-tested.
//!
//! Two layers:
//!   - [`parse_range`] / [`ByteRange`] — parse and resolve an HTTP `Range` header against a known
//!     total size, following RFC 7233 (single range only; CDNs reject multipart ranges).
//!   - [`chunks_for_range`] — given a manifest's `chunk_size`, compute which chunk indices cover a
//!     byte range, plus the in-first-chunk / in-last-chunk offsets needed to slice the edges.

use ce_rs::Manifest;

/// A resolved, satisfiable byte range over an object of known `total` size. Both bounds are
/// **inclusive**, matching HTTP `Content-Range` semantics. Invariants (guaranteed by construction):
/// `start <= end < total` and `total > 0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// First byte index (inclusive).
    pub start: u64,
    /// Last byte index (inclusive).
    pub end: u64,
}

impl ByteRange {
    /// Number of bytes in the range (`end - start + 1`).
    pub fn len(&self) -> u64 {
        self.end - self.start + 1
    }

    /// A range is never empty by construction (start <= end), but this keeps clippy and callers
    /// honest when they branch on emptiness.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The `Content-Range: bytes start-end/total` header value for a response of `total` size.
    pub fn content_range_header(&self, total: u64) -> String {
        format!("bytes {}-{}/{}", self.start, self.end, total)
    }
}

/// Outcome of parsing/resolving a `Range` header against a total object size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeOutcome {
    /// No `Range` header (or `None` was passed) — serve the whole object (HTTP 200).
    Full,
    /// A satisfiable single range — serve `206 Partial Content` with this span.
    Partial(ByteRange),
    /// A syntactically valid but unsatisfiable range (e.g. start beyond EOF) — the caller must
    /// answer `416 Range Not Satisfiable` with `Content-Range: bytes */total`.
    Unsatisfiable,
}

/// Parse an HTTP `Range` header value against an object of `total` bytes.
///
/// Accepts the common forms of a *single* byte range (RFC 7233 §2.1):
///   - `bytes=START-END`  — explicit inclusive span; END is clamped to `total-1`.
///   - `bytes=START-`     — from START to the end of the object.
///   - `bytes=-SUFFIX`    — the final SUFFIX bytes (a suffix-length range).
///
/// Returns:
///   - `Full` when `header` is `None` (no Range requested).
///   - `Partial(range)` for a satisfiable range.
///   - `Unsatisfiable` for a syntactically-valid range that cannot be served (START >= total, or a
///     zero-length suffix), or `Full` is *not* returned for malformed input — a malformed header is
///     ignored per RFC 7233 and the whole object is served (`Full`).
///
/// Multipart ranges (`bytes=0-1,5-6`) are intentionally not supported: a CDN serving content-
/// addressed chunks answers a single contiguous span. They resolve to `Full` (ignored), which is a
/// spec-compliant fallback.
pub fn parse_range(header: Option<&str>, total: u64) -> RangeOutcome {
    let Some(h) = header else {
        return RangeOutcome::Full;
    };
    let h = h.trim();
    // Only the `bytes` unit is supported.
    let Some(spec) = h.strip_prefix("bytes=") else {
        return RangeOutcome::Full; // unknown unit -> ignore, serve full
    };
    let spec = spec.trim();
    // Reject multipart (comma) — fall back to full.
    if spec.contains(',') {
        return RangeOutcome::Full;
    }
    // An empty object can satisfy no range.
    if total == 0 {
        return RangeOutcome::Unsatisfiable;
    }
    let Some((lhs, rhs)) = spec.split_once('-') else {
        return RangeOutcome::Full; // malformed -> ignore
    };
    let lhs = lhs.trim();
    let rhs = rhs.trim();

    match (lhs.is_empty(), rhs.is_empty()) {
        // `-SUFFIX`: the last SUFFIX bytes.
        (true, false) => {
            let Ok(suffix) = rhs.parse::<u64>() else {
                return RangeOutcome::Full;
            };
            if suffix == 0 {
                return RangeOutcome::Unsatisfiable;
            }
            let suffix = suffix.min(total);
            RangeOutcome::Partial(ByteRange { start: total - suffix, end: total - 1 })
        }
        // `START-`: from START to EOF.
        (false, true) => {
            let Ok(start) = lhs.parse::<u64>() else {
                return RangeOutcome::Full;
            };
            if start >= total {
                return RangeOutcome::Unsatisfiable;
            }
            RangeOutcome::Partial(ByteRange { start, end: total - 1 })
        }
        // `START-END`: explicit inclusive span.
        (false, false) => {
            let (Ok(start), Ok(end)) = (lhs.parse::<u64>(), rhs.parse::<u64>()) else {
                return RangeOutcome::Full;
            };
            if start > end || start >= total {
                return RangeOutcome::Unsatisfiable;
            }
            let end = end.min(total - 1);
            RangeOutcome::Partial(ByteRange { start, end })
        }
        // `-` alone is malformed.
        (true, true) => RangeOutcome::Full,
    }
}

/// Which chunks cover a byte range, and how to trim the edges.
///
/// Computed from a manifest's uniform `chunk_size` (the last chunk may be shorter, but only the
/// *count* and edge offsets matter here). The covered chunk indices are `first_chunk..=last_chunk`;
/// after concatenating those chunks, drop `head_skip` bytes from the front and keep `out_len`
/// bytes total to land exactly on the requested range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkSpan {
    /// Index of the first chunk (inclusive) that the range touches.
    pub first_chunk: u64,
    /// Index of the last chunk (inclusive) that the range touches.
    pub last_chunk: u64,
    /// Bytes to drop from the front of the concatenated chunks (the offset of `start` within
    /// `first_chunk`).
    pub head_skip: u64,
    /// Total bytes to keep after `head_skip` — equal to the requested range length.
    pub out_len: u64,
}

/// Map a [`ByteRange`] onto the chunk indices of a [`Manifest`].
///
/// Returns `None` if `chunk_size` is zero (a malformed manifest) — callers treat that as an error
/// rather than panicking. The range is assumed already validated against the manifest's
/// `total_size` (use [`parse_range`] with `manifest.total_size`).
pub fn chunks_for_range(manifest: &Manifest, range: ByteRange) -> Option<ChunkSpan> {
    let cs = manifest.chunk_size;
    if cs == 0 {
        return None;
    }
    let first_chunk = range.start / cs;
    let last_chunk = range.end / cs;
    let head_skip = range.start - first_chunk * cs;
    Some(ChunkSpan { first_chunk, last_chunk, head_skip, out_len: range.len() })
}

/// Slice the exact range bytes out of the concatenation of the covering chunks.
///
/// `joined` must be the bytes of chunks `first_chunk..=last_chunk` concatenated in order. Returns
/// the `out_len` bytes starting at `head_skip`. Errors (rather than panics) if `joined` is too
/// short to satisfy the span — a defense against a host returning truncated chunk bytes.
pub fn slice_span(joined: &[u8], span: ChunkSpan) -> anyhow::Result<Vec<u8>> {
    let start = span.head_skip as usize;
    let end = start
        .checked_add(span.out_len as usize)
        .ok_or_else(|| anyhow::anyhow!("range length overflow"))?;
    if end > joined.len() {
        anyhow::bail!(
            "joined chunk bytes ({}) too short for range [{}, {})",
            joined.len(),
            start,
            end
        );
    }
    Ok(joined[start..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ce_rs::data::MANIFEST_KIND_V1;
    use proptest::prelude::*;

    fn manifest(chunk_size: u64, total: u64) -> Manifest {
        // chunk CIDs are irrelevant to the math here; build a plausible count.
        let n = if chunk_size == 0 { 0 } else { total.div_ceil(chunk_size) };
        Manifest {
            kind: MANIFEST_KIND_V1.to_string(),
            chunk_size,
            total_size: total,
            chunks: (0..n).map(|i| format!("chunk{i}")).collect(),
        }
    }

    // ---- parse_range: happy paths ----

    #[test]
    fn no_header_is_full() {
        assert_eq!(parse_range(None, 100), RangeOutcome::Full);
    }

    #[test]
    fn explicit_span() {
        assert_eq!(
            parse_range(Some("bytes=10-20"), 100),
            RangeOutcome::Partial(ByteRange { start: 10, end: 20 })
        );
    }

    #[test]
    fn open_ended_to_eof() {
        assert_eq!(
            parse_range(Some("bytes=90-"), 100),
            RangeOutcome::Partial(ByteRange { start: 90, end: 99 })
        );
    }

    #[test]
    fn suffix_range() {
        assert_eq!(
            parse_range(Some("bytes=-10"), 100),
            RangeOutcome::Partial(ByteRange { start: 90, end: 99 })
        );
    }

    #[test]
    fn suffix_larger_than_object_clamps_to_whole() {
        assert_eq!(
            parse_range(Some("bytes=-500"), 100),
            RangeOutcome::Partial(ByteRange { start: 0, end: 99 })
        );
    }

    #[test]
    fn end_past_eof_is_clamped() {
        assert_eq!(
            parse_range(Some("bytes=50-9999"), 100),
            RangeOutcome::Partial(ByteRange { start: 50, end: 99 })
        );
    }

    #[test]
    fn whitespace_is_tolerated() {
        assert_eq!(
            parse_range(Some("  bytes= 10 - 20 "), 100),
            RangeOutcome::Partial(ByteRange { start: 10, end: 20 })
        );
    }

    // ---- parse_range: error / edge paths ----

    #[test]
    fn start_at_or_past_eof_is_unsatisfiable() {
        assert_eq!(parse_range(Some("bytes=100-200"), 100), RangeOutcome::Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=100-"), 100), RangeOutcome::Unsatisfiable);
    }

    #[test]
    fn start_after_end_is_unsatisfiable() {
        assert_eq!(parse_range(Some("bytes=30-10"), 100), RangeOutcome::Unsatisfiable);
    }

    #[test]
    fn zero_suffix_is_unsatisfiable() {
        assert_eq!(parse_range(Some("bytes=-0"), 100), RangeOutcome::Unsatisfiable);
    }

    #[test]
    fn empty_object_cannot_satisfy_a_range() {
        assert_eq!(parse_range(Some("bytes=0-0"), 0), RangeOutcome::Unsatisfiable);
    }

    #[test]
    fn malformed_headers_fall_back_to_full() {
        // Per RFC 7233 a malformed Range is ignored -> serve full.
        for h in ["bytes=", "bytes=abc-def", "items=0-1", "bytes=-", "garbage", "bytes=1-2,5-6"] {
            assert_eq!(parse_range(Some(h), 100), RangeOutcome::Full, "header {h:?}");
        }
    }

    #[test]
    fn content_range_header_formats() {
        let r = ByteRange { start: 10, end: 20 };
        assert_eq!(r.content_range_header(100), "bytes 10-20/100");
        assert_eq!(r.len(), 11);
        assert!(!r.is_empty());
    }

    // ---- chunks_for_range ----

    #[test]
    fn single_chunk_range() {
        let m = manifest(1024, 4096);
        let span = chunks_for_range(&m, ByteRange { start: 10, end: 20 }).unwrap();
        assert_eq!(span.first_chunk, 0);
        assert_eq!(span.last_chunk, 0);
        assert_eq!(span.head_skip, 10);
        assert_eq!(span.out_len, 11);
    }

    #[test]
    fn range_spanning_chunk_boundary() {
        let m = manifest(1000, 5000);
        // bytes 1500..=2500 -> chunks 1 and 2; head_skip 500 within chunk 1.
        let span = chunks_for_range(&m, ByteRange { start: 1500, end: 2500 }).unwrap();
        assert_eq!(span.first_chunk, 1);
        assert_eq!(span.last_chunk, 2);
        assert_eq!(span.head_skip, 500);
        assert_eq!(span.out_len, 1001);
    }

    #[test]
    fn zero_chunk_size_is_none() {
        let m = manifest(0, 0);
        assert!(chunks_for_range(&m, ByteRange { start: 0, end: 0 }).is_none());
    }

    // ---- slice_span ----

    #[test]
    fn slice_extracts_exact_bytes() {
        let joined: Vec<u8> = (0..100u8).collect();
        let span = ChunkSpan { first_chunk: 0, last_chunk: 0, head_skip: 10, out_len: 5 };
        assert_eq!(slice_span(&joined, span).unwrap(), vec![10, 11, 12, 13, 14]);
    }

    #[test]
    fn slice_rejects_truncated_input() {
        let joined = vec![0u8; 8];
        let span = ChunkSpan { first_chunk: 0, last_chunk: 0, head_skip: 4, out_len: 10 };
        let err = slice_span(&joined, span).unwrap_err();
        assert!(err.to_string().contains("too short"), "{err}");
    }

    // ---- property: a resolved partial range is always in-bounds and round-trips through chunks ----

    proptest! {
        #[test]
        fn partial_range_is_always_in_bounds(total in 1u64..100_000, a in 0u64..200_000, b in 0u64..200_000) {
            let header = format!("bytes={}-{}", a.min(b), a.max(b));
            if let RangeOutcome::Partial(r) = parse_range(Some(&header), total) {
                prop_assert!(r.start <= r.end);
                prop_assert!(r.end < total);
                prop_assert_eq!(r.len(), r.end - r.start + 1);
            }
        }

        #[test]
        fn chunk_span_covers_and_slices_back_to_range(
            chunk_size in 1u64..4096,
            total in 1u64..50_000,
            ra in 0u64..50_000,
            rb in 0u64..50_000,
        ) {
            prop_assume!(ra < total && rb < total);
            let (start, end) = (ra.min(rb), ra.max(rb));
            let m = manifest(chunk_size, total);
            let range = ByteRange { start, end };
            let span = chunks_for_range(&m, range).unwrap();
            // The covering chunks form a contiguous span that contains the range.
            prop_assert!(span.first_chunk <= span.last_chunk);
            prop_assert!(span.first_chunk * chunk_size <= start);
            prop_assert!((span.last_chunk + 1) * chunk_size > end);
            // Build the joined chunk bytes as the canonical object would, then slice.
            let object: Vec<u8> = (0..total).map(|i| (i % 256) as u8).collect();
            let first_byte = (span.first_chunk * chunk_size) as usize;
            let last_byte = (((span.last_chunk + 1) * chunk_size).min(total)) as usize;
            let joined = &object[first_byte..last_byte];
            let sliced = slice_span(joined, span).unwrap();
            prop_assert_eq!(&sliced[..], &object[start as usize..=end as usize]);
        }
    }
}
