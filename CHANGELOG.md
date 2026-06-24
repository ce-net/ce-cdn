# Changelog

All notable changes to ce-cdn are documented here.

## [Unreleased]

### Added
- **Conditional requests**: `If-None-Match: "<cid>"` (and `*`) yields `304 Not Modified` — immutable
  CIDs make this a free bandwidth win (`edge::if_none_match_matches` / `edge::not_modified`).
- **Negative caching**: a 404/origin-miss is remembered as a short-lived tombstone so a flood of GETs
  for an absent CID cannot amplify onto the origin (`cache::note_absent` / `is_negative`).
- **Single-flight cold fetch**: concurrent HTTP cold misses of the same CID serialize so the origin
  is consulted once, then siblings read the freshly-cached bytes (thundering-herd guard).
- **Presigned links** (`presign` module + `ce-cdn presign`): publisher-signed, time-limited, key-less
  public URLs — the Cloud-CDN signed-URL analog. Edges trust signer keys via `--presign-key`.
- **Re-replication maintenance** (`maintain` module + `ce-cdn maintain [--watch]`): probe each
  object's edges and recruit fresh ranked replicas to restore the target replication factor.
- **Prometheus metrics** (`GET /metrics`) and per-object hit/byte counters in the cache.
- **Tags + bulk invalidation**: `ce-cdn put --tag T`, `ce-cdn purge --tag T`; purge fans out to all
  recorded **and** DHT-advertised edges. `ce-cdn forget <cid>` drops a stale entry locally.
- **`limits` module**: centralized size/charset bounds (`MAX_MESH_OBJECT_BYTES`, `MAX_REQUEST_BYTES`,
  `MAX_CAPS_HEX_LEN`, CID validation) — the DoS/OOM guard rails.
- Architecture and protocol docs (`docs/`), a runnable presigned-link example, and a doctest.

### Changed
- **Mesh read is size-bounded and range-aware**: a whole-object `cdn/read` over the SDK wire ceiling
  is refused with a typed reason; a range read peeks only the manifest and pulls only the covering
  chunks (a 1-byte range over a huge object transfers one chunk, not the whole object).
- **Catalog persistence is crash-safe**: temp-file + fsync + atomic rename, guarded by an advisory
  file lock (`Catalog::update`) so concurrent CLI processes cannot lose each other's writes. A
  `version` field was added with backward-compatible migration.
- **HTTP server hardened**: header-read timeout (slowloris guard), capped header buffer, per-object
  size cap (`413`), CID charset/length validation.

### Security
- **Proof-of-possession replay protection**: proofs now carry a nonce and are single-use within their
  ≤5-minute window via a bounded `ReplayGuard`; the wire format is
  `X-Ce-Proof: <expires>.<nonce_hex>.<sig_hex>`.

## [0.1.0]

- Initial release: content-addressed edge cache, HTTP front-end (`GET /cdn/<cid>`, `/status`,
  `/health`), `cdn/*` mesh protocol, capability-gated private content with proof-of-possession,
  RFC-7233 range reads, reputation-aware replication policy, JSON catalog.
