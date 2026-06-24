# ce-cdn mesh protocol (`cdn/*`)

All messages are JSON, carried hex-encoded by the SDK's `request`/`reply` transport over libp2p. The
requester NodeId is the cryptographically authenticated libp2p sender — the host trusts `from` to
decide what to honor.

## Topics & abilities

| Topic | Ability required | Purpose |
|---|---|---|
| `cdn/cache` | `cdn:cache` | fetch-and-hold an object (replication) |
| `cdn/read` | `cdn:read` (waived for public CIDs) | serve bytes, whole or by range |
| `cdn/purge` | `cdn:purge` | evict an object from the cache |
| `cdn/status` | `cdn:read` | "do you hold this CID?" probe (no bytes) |

DHT services: an edge advertises `cdn:edge` (it is a CDN edge) and `cdn:<cid>` (it holds that CID).

## Authorization

Public CIDs (in the edge's public set) are served to anyone with no chain. Everything else requires a
hex-encoded `ce-cap` chain in the request's `caps` field that `ce_cap::authorize` accepts for the
ability, rooted at the edge's own key or a configured org root, and not revoked/expired. Mutating
actions (`cdn:cache`, `cdn:purge`) are NEVER waived by the public flag.

## Resource bounds (enforced by the host before any work)

| Limit | Value | Why |
|---|---|---|
| `MAX_REQUEST_BYTES` | 256 KiB | reject an oversized request before decoding (OOM guard) |
| `MAX_CAPS_HEX_LEN` | 128 KiB | bound the decode work an unauthorized caller can force |
| `MAX_MESH_OBJECT_BYTES` | 8 MiB | largest whole-object `cdn/read` reply (hex doubles it) |
| `MAX_MESH_RANGE_BYTES` | 8 MiB | largest covering-chunk span a range read materializes |
| CID | 64 lowercase hex | a malformed/overlong key never reaches the cache or origin |

A whole-object read larger than `MAX_MESH_OBJECT_BYTES` is refused with a typed reason (fetch it over
HTTP or by range). A range read peeks only the manifest (one small blob) and pulls only the covering
chunks, so a 1-byte range over a 1 GiB object transfers one chunk, not the whole object.

## Message shapes

`CacheReq { caps, cid, bytes_len, ttl_secs }` → `CacheResp { cached, stored_bytes, ttl_secs, reason }`

`ReadReq { caps, cid, range? }` → `ReadResp { ok, bytes_hex, total_len, partial, range_start,
range_end, cache_hit, reason }` — `bytes_hex` is the whole object or the requested range; the consumer
re-verifies against the CID, so a tampered reply is rejected client-side regardless of `ok`.

`PurgeReq { caps, cid }` → `PurgeResp { purged, reason }`

`StatusReq { caps, cid }` → `StatusResp { held, bytes, ttl_remaining }`

## HTTP front-end auth

The HTTP path has no transport-level sender authentication, so `X-Ce-Node-Id` is **proven, not
trusted**:

- `X-Ce-Proof: <expires>.<nonce_hex>.<sig_hex>` — an Ed25519 signature over
  `(requester, cid, cdn:read, nonce, expires)` proving the caller holds the requester key for THIS
  request. Bound to a fresh nonce so a captured proof is single-use within its (≤5 min) window
  (`ReplayGuard`).
- `X-Ce-Capability: <hex>` (or `Authorization: Capability <hex>`) — the `ce-cap` chain authorizing
  `cdn:read` for that requester.
- **Presigned link** `?exp=<unix>&sig=<hex>` — an alternative for key-less consumers: the publisher
  signs `(cid, expires)` with a key the edge trusts (`--presign-key`), and anyone with the URL can
  fetch until it expires. The signed-URL analog.

A public CID needs none of these. A private fetch needs (PoP + cap) OR a valid presigned link.
