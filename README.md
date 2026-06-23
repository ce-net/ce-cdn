# ce-cdn — content-delivery / edge-cache network over CE

A **CDN** built on CE primitives: cache-and-serve content by **CID** with edge replication, TTL
eviction, HTTP **range** reads, cache-hit accounting, and **capability-gated** private content.
ce-cdn is an *application* (the SDK tier, like `swarm` / `rdev` / `ce-pin`) — it composes CE, it is
not part of the node.

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
| `client` | put / get (+ range) / purge / replicate over `ce-rs`. |
| `host` | The capability-gated edge serve loop (caches + serves, public or cap-gated). |

## CLI

```
ce-cdn put <file> [--replication N] [--ttl SECS] [--private] [--label L] [--caps HEX]
ce-cdn get <cid> [--out PATH] [--range "bytes=0-1023"]
ce-cdn ls
ce-cdn purge <cid> [--edge NODE_ID] [--caps HEX] [--keep]
ce-cdn status <cid> [--caps HEX]
ce-cdn serve [--max-mb MB] [--ttl SECS] [--public CID ...]
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
- **416** unsatisfiable range + `Content-Range: bytes */total`.
- **403** private content without a valid capability.
- **404** a CID the edge does not hold and could not fetch.

A malformed `Range` header degrades to a full 200 (RFC 7233); multipart ranges are not served.

## Configuration (env)

| Var | Effect |
|---|---|
| `CE_CDN_CAPS` | Capability chain (hex) the client presents (overridden by `--caps`). |
| `CE_CDN_DIR` | Override the config dir for the catalog / caps file. |
| `CE_CDN_ROOTS` | Path to the accepted-root-keys file for an edge. |
| `CE_API_TOKEN` | Node API token (auto-discovered from the data dir otherwise). |
| `RUST_LOG` | Tracing level (default `info`). |

## Testing

Built test-first; the foundation is validated:

```bash
cargo test          # 72 unit + 17 integration tests
cargo clippy --all-targets
```

Coverage includes: **CID integrity** (chunk↔reassemble round-trip, tamper rejection),
**range/partial fetch** (parse, chunk-mapping, exact slicing — with property tests asserting a
resolved range is always in-bounds and round-trips through chunks), **cache** (hit/miss accounting,
TTL expiry, LRU eviction, purge, sweep), **replication/eviction policy**, **capability-gated private
content** (real forged `ce-cap` chains: valid read allowed, missing/wrong-ability denied, public
read waived, cache/purge never waived by the public flag), and **failure injection** (denied caps,
malformed protocol payloads, truncated chunk bytes, unsatisfiable ranges → graceful errors, never a
panic).

## License

MIT.
