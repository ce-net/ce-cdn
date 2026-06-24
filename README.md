# ce-cdn — content-delivery / edge-cache network over CE

A **CDN** built on CE primitives: cache-and-serve content by **CID** with edge replication, TTL
eviction, HTTP **range** reads, **conditional requests** (304), **negative caching**, **single-flight**
origin protection, **presigned links**, a **re-replication** maintenance loop, Prometheus **metrics**,
and **capability-gated** private content. ce-cdn is an *application* (the SDK tier, like `swarm` /
`rdev` / `ce-pin`) — it composes CE, it is not part of the node. See [`docs/architecture.md`](docs/architecture.md)
and [`docs/protocol.md`](docs/protocol.md).

The thing that makes a content-addressed CDN strictly better than a URL-keyed one:

> **The CID is both the cache key and the integrity proof.** An object's CID is the hash of its
> manifest, and `get_object` re-verifies every chunk against its CID — so an edge can never serve
> bytes the publisher did not publish, and a cache cannot be poisoned. Immutable bytes also make
> cache-control trivial: a CID is `immutable`, so an entry only leaves the cache on **TTL** or
> **eviction**, never staleness.

## What it composes (CE primitives, not reinvented)

| Capability | CE primitive (via `ce-rs` / `ce-cap`) |
|---|---|
| Content store + integrity | blobs / data-layer: `put_object` / `get_object` (1 MiB chunks, CID-verified) |
| Discovery (which edges hold a CID) | DHT: `advertise_service` / `find_service` (`cdn:edge`, `cdn:<cid>`) |
| Replication / serving over the mesh | `request` / `reply` on the `cdn/*` topics |
| Authorization (private content / cache / purge) | `ce-cap`: signed, attenuating capability chains |
| Edge selection (reputation-aware) | atlas (`/atlas`) + on-chain history (`/history/:id`) |
| Payment (edge rent) | payment channels (`channel_open` / `sign_receipt` / `channel_close`) |

No new node endpoints. Mesh-first. Money is integer base units (1 credit = 10^18) carried as
decimal strings — never floats.

## Library shape

| Module | Role |
|---|---|
| `cidrange` | Pure CID / HTTP-`Range` math: parse a range, map it onto chunks, slice exact bytes. |
| `cache` | The edge cache: TTL + LRU eviction + hit/miss accounting (clock-injected, pure). |
| `edge` | The HTTP edge handler: shape a response (status, cache headers, range) from cache state. |
| `proto` | The `cdn/*` mesh wire protocol (cache / read / purge / status) + opaque abilities. |
| `replication` | Pure edge ranking (work + liveness + memory) + re-replication policy. |
| `catalog` | Publisher-side index (`cid -> Content + edge replicas`), persisted as JSON. |
| `caps` | Resolving the `ce-cap` chain a client presents to edges. |
| `pop` | Proof-of-possession: the HTTP `X-Ce-Node-Id` is proven (signed, nonce'd, replay-guarded). |
| `presign` | Presigned, time-limited public links (the Cloud-CDN signed-URL analog). |
| `limits` | Centralized size/charset bounds — the DoS / OOM guard rails. |
| `maintain` | The re-replication loop: probe edges, recruit fresh replicas to hit the target factor. |
| `client` | put / get (+ range) / purge / replicate over `ce-rs`. |
| `host` | The capability-gated mesh edge serve loop (caches + serves, public or cap-gated). |
| `server` | The hyper HTTP front-end: `GET /cdn/<cid>` (+ `/status`, `/health`, `/metrics`). |

## CLI

```
ce-cdn put <file> [--replication N] [--ttl SECS] [--private] [--label L] [--tag T ...] [--caps HEX]
ce-cdn get <cid> [--out PATH] [--range "bytes=0-1023"]
ce-cdn ls
ce-cdn purge [<cid>] [--tag T] [--edge NODE_ID] [--caps HEX] [--keep]
ce-cdn forget <cid>
ce-cdn status <cid> [--caps HEX]
ce-cdn maintain [--caps HEX] [--watch SECS]
ce-cdn presign <cid> [--ttl SECS] [--base URL]
ce-cdn serve [--max-mb MB] [--ttl SECS] [--public CID ...] [--http ADDR] [--presign-key NODE_ID ...]
```

`--api` (default `http://127.0.0.1:8844`) points at your local CE node; `--catalog` overrides the
index path.

### Publish + fetch (public content)

```bash
# Store a file (content-addressed), replicate to the 3 best edges, advertise on the DHT.
ce-cdn put ./video.mp4 --replication 3 --ttl 86400
#   cid: 9f2c…   url: /cdn/9f2c…

# Fetch the whole object from the nearest holder (trustless: every chunk CID-verified).
ce-cdn get 9f2c… --out ./video.mp4

# Fetch a byte range (resumable / video seek) — only the covering chunks are pulled.
ce-cdn get 9f2c… --range "bytes=1048576-2097151" --out ./chunk.bin

# See who currently serves it.
ce-cdn status 9f2c…
```

### Run an edge

```bash
# Cache up to 4 GiB, default TTL 1h; openly serve one public CID.
ce-cdn serve --max-mb 4096 --ttl 3600 --public 9f2c…
```

An edge advertises `cdn:edge` on the DHT, answers `cdn/cache` (fetch-and-hold), `cdn/read` (serve,
whole or by range), `cdn/purge`, and `cdn/status`. **Public** reads need no capability; everything
else (private reads, cache, purge) requires a signed `ce-cap` chain rooted at the edge's own key or
a configured org root.

### Private, capability-gated content

```bash
# Publisher marks content private:
ce-cdn put ./report.pdf --private --replication 2 --caps <chain-granting-cdn:cache>

# A consumer must present a chain granting cdn:read to fetch it:
CE_CDN_CAPS=<chain-granting-cdn:read> ce-cdn get <cid> --out ./report.pdf
```

Capabilities are minted out-of-band (e.g. `ce grant <holder> --can cdn:read,cdn:cache …`). The
edge verifies the chain **offline, in microseconds** before serving; revocation is on-chain
`RevokeCapability` + expiry. Edges opt into an org by listing its root key in
`$CE_CDN_ROOTS` / `$CE_DATA_DIR/roots` / `~/.local/share/ce/roots` (one 64-hex NodeId per line).

## HTTP edge semantics

The `edge` module shapes responses exactly as a CDN should:

- **200** full object + `Cache-Control: public, max-age=<ttl>, immutable`, `ETag: "<cid>"`,
  `Age`, `X-Cache: HIT|MISS`, `Accept-Ranges: bytes`.
- **206** partial range + `Content-Range: bytes start-end/total`.
- **304** `If-None-Match: "<cid>"` matches the immutable CID — validators only, no body.
- **403** private content without a valid capability / proof-of-possession / presigned link.
- **404** a CID the edge does not hold and could not fetch (cached as a short negative tombstone).
- **413** an object larger than the edge's configured size cap.
- **416** unsatisfiable range + `Content-Range: bytes */total`.

A malformed `Range` header degrades to a full 200 (RFC 7233); multipart ranges are not served.

Routes: `GET /cdn/<cid>`, `GET /status` (JSON cache snapshot), `GET /metrics` (Prometheus text), and
`GET /health`. `HEAD` is supported (headers + status, no body). The hyper server has a header-read
timeout (slowloris guard) and a capped header buffer.

### Robustness guarantees

- **Single-flight**: concurrent cold misses for the same CID hit the origin once, then read cache.
- **Negative caching**: a 404 is remembered briefly so a flood of misses can't amplify onto the origin.
- **Size bounds**: every external input (mesh payload, cap chain, CID, object) is bounded (`limits`).
- **Replay protection**: a captured proof-of-possession is single-use within its window.
- **Atomic persistence**: the catalog is written temp-file + fsync + rename, guarded by an advisory lock.

## Configuration (env)

| Var | Effect |
|---|---|
| `CE_CDN_CAPS` | Capability chain (hex) the client presents (overridden by `--caps`). |
| `CE_CDN_DIR` | Override the config dir for the catalog / caps file. |
| `CE_CDN_ROOTS` | Path to the accepted-root-keys file for an edge. |
| `CE_API_TOKEN` | Node API token (auto-discovered from the data dir otherwise). |
| `RUST_LOG` | Tracing level (default `info`). |

## Re-replication maintenance

The publisher records a desired replication factor per object. `ce-cdn maintain` probes each
recorded object's edges, marks them healthy/unhealthy, and recruits fresh edges (ranked by atlas
capacity + on-chain history) to restore the target factor; `--watch SECS` loops forever. The
decision logic (`maintain::plan_entry`) is pure and unit-tested.

## Presigned links

Share otherwise-private content as a plain URL, no client key needed:

```bash
# Mint a 1-hour link signed by your node's key:
ce-cdn presign <cid> --ttl 3600 --base https://edge.example.com
#   https://edge.example.com/cdn/<cid>?exp=...&sig=...

# The serving edge must trust your key:
ce-cdn serve --http 0.0.0.0:8845 --presign-key <your-node-id>
```

## Operational guidance

- **`--max-mb`** sets both the cache budget and the per-object HTTP buffer cap; size it to the box's
  RAM. Whole-object mesh reads are independently capped at 8 MiB (`limits::MAX_MESH_OBJECT_BYTES`) —
  larger objects must be fetched over HTTP or by range.
- **Exposing the HTTP front-end publicly** is safe for public CIDs; private CIDs require PoP + a cap
  chain or a presigned link. The server has a header-read timeout and capped header buffer; put it
  behind a reverse proxy for TLS and connection limits in production.
- **`X-Ce-Proof`** is minted by a client holding the requester key (`pop::mint_proof`); a leaked cap
  chain alone is useless without the key, and a captured proof is single-use within its 5-minute
  window.
- **`/metrics`** exposes Prometheus counters (cache hits/misses/evictions/negative-hits + per-CID
  hit/byte gauges) for scraping.

## Testing

All tests run **offline** (no live CE node): pure cores plus a real `hyper` server over a real
socket with an in-memory origin, and forged `ce-cap` chains for the auth paths.

```bash
cargo test --workspace
cargo clippy --all-targets
```

Coverage includes: **CID integrity** (chunk↔reassemble round-trip, tamper rejection),
**range/partial fetch** (parse, chunk-mapping, exact slicing — property tests assert a resolved
range is always in-bounds and round-trips through chunks), **cache** (hit/miss accounting, TTL
expiry, LRU eviction, purge, sweep, negative tombstones, per-object stats), **conditional requests**
(304), **single-flight** (a concurrent herd hits the origin once), **negative caching** (an absent
CID is served from a tombstone), **presigned links** (valid/tampered/untrusted-key), **proof-of-
possession** (wrong key/cid/ability, expiry boundaries, replay rejection), **metrics**,
**input bounds** (malformed CIDs, oversize payloads), **atomic/locked catalog persistence**
(round-trip, no temp leak, schema migration, lock release), **replication + maintenance planning**,
**capability-gated private content** (valid read allowed, missing/wrong-ability denied, public read
waived, cache/purge never waived), and **failure injection** (denied caps, malformed payloads,
truncated chunk bytes, unsatisfiable ranges → graceful, never a panic).

## Deferred / not yet implemented

These are honestly out of scope for the current slice:

- **Payment-channel edge rent.** The CE payment-channel primitives exist (`channel_open`/
  `sign_receipt`/`channel_close`) but ce-cdn does not yet open a channel or sign per-serve receipts;
  serving is currently free. The hook points are documented in `client`/`host`.
- **Compression variants** (gzip/brotli as distinct CIDs negotiated via `Accept-Encoding`).
- **Multi-range requests** (`bytes=0-1,5-6`) — a single contiguous range is served; multipart
  degrades to a full 200.
- **Disk-backed cache tier** — the cache is in-memory; an edge restart cold-starts (counters and
  bytes are not persisted).
- **Geo/latency-aware edge selection** — placement approximates spread by distinct high-reputation
  edges; there is no region/latency-graph signal feeding placement yet.

## License

MIT.
