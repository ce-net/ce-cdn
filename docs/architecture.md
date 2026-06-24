# ce-cdn architecture

ce-cdn is an **application built on CE primitives**, not a node feature. It composes the `ce-rs`
SDK (blobs/objects, mesh request/reply, DHT discovery, atlas/history, payment channels), the
`ce-cap` capability verifier, and `ce-identity` (Ed25519 sign/verify) into a content-delivery
network. It adds **no node endpoints**: every device-to-device interaction is a `cdn/*` AppRequest
over libp2p, and every authorization decision is a signed, attenuating `ce-cap` chain.

## The CE-vs-app boundary

| Concern | Who owns it |
|---|---|
| Content storage + chunk integrity | **CE** (blobs/data-layer: `put_object`/`get_object`, CID per chunk) |
| Transport (request/reply, pubsub, stream, relay/NAT) | **CE** (`ce-rs` over libp2p) |
| Discovery (which edges hold a CID) | **CE** (DHT `advertise_service`/`find_service`) |
| Capability verification | **CE** (`ce-cap` crate) |
| Ledger / payment channels | **CE** (economy) |
| Cache policy (TTL, LRU, negative cache) | **app** (`cache`) |
| HTTP/range response shaping | **app** (`edge`, `cidrange`) |
| Edge selection / re-replication policy | **app** (`replication`, `maintain`) |
| Proof-of-possession, presigned links | **app** (`pop`, `presign`) |
| The catalog (publisher index) | **app** (`catalog`) |

The decisive property: **the CID is both the cache key and the integrity proof.** An object's CID is
the hash of its manifest; `get_object` re-verifies every chunk against its CID. So an edge can never
serve bytes the publisher did not publish, a cache cannot be poisoned, and cache-control is trivially
`immutable` — an entry only leaves on TTL or eviction, never staleness.

## Module map

```
cidrange   pure HTTP Range math (RFC 7233): parse, map onto chunks, slice exact bytes
cache      in-memory LRU+TTL edge cache + per-object hit/miss + negative-cache tombstones
edge       pure response shaping (200/206/304/403/404/416 + immutable cache headers)
limits     centralized size/charset bounds (the DoS / OOM guard rails)
proto      the cdn/* mesh wire protocol (cache/read/purge/status) + opaque abilities
caps       resolve the ce-cap chain a client presents
pop        proof-of-possession: the HTTP X-Ce-Node-Id is proven, not trusted (+ replay guard)
presign    presigned time-limited public links (the Cloud-CDN signed-URL analog)
replication pure edge ranking (work + liveness + memory) + re-replication policy
maintain   the re-replication loop: probe -> plan -> recruit, restoring the target replica count
catalog    publisher index (cid -> Content + edges), atomic JSON persistence + advisory lock
client     publisher/consumer ops over ce-rs: put / get (+range) / replicate / probe / purge
host       the mesh edge serve loop: authorize a cdn/* request and cache/serve/purge
server     the HTTP front-end: GET /cdn/<cid> (+ /status, /health, /metrics) over hyper 1.x
```

## Request lifecycle (HTTP read)

```
GET /cdn/<cid>[?exp=..&sig=..]   [X-Ce-Node-Id, X-Ce-Proof, X-Ce-Capability, Range, If-None-Match]
  1. validate CID charset/length                        (limits)
  2. resolve grant: public | presigned | (PoP + cap)    (server::resolve_grant, pop, presign, ce-cap)
  3. if PoP path: enforce single-use replay             (pop::ReplayGuard)
  4. If-None-Match matches "<cid>"? -> 304              (edge::not_modified)
  5. negative tombstone fresh? -> 404                   (cache::is_negative)
  6. cache hit? serve. else single-flight cold fetch:   (cache, single-flight lock)
       origin.fetch -> size-bound -> insert             (limits::MAX_*; cache.insert)
       fetch error -> note_absent (negative cache)      (cache::note_absent)
  7. shape response (full/range, immutable headers)     (edge::serve)
```

## Request lifecycle (mesh read, `cdn/read`)

The mesh path's requester NodeId is the cryptographically authenticated libp2p sender, so
proof-of-possession is unnecessary there — holding a capability whose audience is that node already
proves possession. The host:

```
1. bound the payload size (pre-decode + post-decode)   (limits::MAX_REQUEST_BYTES)
2. validate the CID + cap-chain length                 (limits)
3. decide: public read | authorized (ce-cap)           (host::decide, ce_cap::authorize)
4. read: whole-object (size-bounded) OR range          (host::read_object / read_range)
     a range read peeks the manifest and pulls ONLY     (limits::MAX_MESH_*)
     the covering chunks (manifest-aware partial fetch)
5. reply with hex bytes; consumer re-verifies vs CID    (trustless)
```

## Trust & money

Authorization is the one CE primitive: an edge verifies a signed, attenuating `ce-cap` chain rooted
at its own key or a configured org root (`$CE_CDN_ROOTS`). Public content needs no chain. Revocation
is on-chain `RevokeCapability` + expiry; the host refreshes the revoked set periodically. Money is
integer base units (1 credit = 10^18) carried as decimal strings — never floats. Edge rent via CE
payment channels is **designed but not wired** (see README "Deferred").
