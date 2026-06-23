//! The edge cache: an in-memory, content-addressed, size-bounded store with TTL and LRU eviction,
//! plus cache-hit accounting.
//!
//! An edge node caches object bytes keyed by CID. Because content is content-addressed, the cache
//! is *trustless and immutable*: a CID always maps to the same bytes, so there is no staleness or
//! invalidation problem — an entry only leaves the cache when it **expires** (TTL) or is **evicted**
//! (the cache is over its byte budget; least-recently-used goes first). Reads update recency and
//! the hit/miss counters so the CLI / dashboard can report cache effectiveness.
//!
//! This module is pure (no network, no clock of its own): the caller passes `now` (unix seconds),
//! which makes TTL/eviction behaviour fully deterministic and testable, and lets one logical clock
//! drive both the cache and the rest of the edge handler.

use std::collections::HashMap;

/// A cached object: its bytes plus the bookkeeping for TTL and LRU.
#[derive(Debug, Clone)]
struct CacheEntry {
    bytes: Vec<u8>,
    /// Unix second this entry was inserted.
    inserted_at: u64,
    /// Unix second after which the entry is stale (`inserted_at + ttl_secs`). `u64::MAX` = never.
    expires_at: u64,
    /// Monotonic access tick; the smallest value is the least-recently-used entry.
    last_tick: u64,
}

/// Running counters describing cache effectiveness. Cheap to copy; surfaced by `stats()`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    /// Reads served from cache.
    pub hits: u64,
    /// Reads that found nothing fresh (absent or expired).
    pub misses: u64,
    /// Entries dropped because they were past their TTL when accessed or swept.
    pub expirations: u64,
    /// Entries dropped to stay within the byte budget (LRU).
    pub evictions: u64,
    /// Current number of live entries.
    pub entries: u64,
    /// Current total bytes held across all entries.
    pub bytes: u64,
}

impl CacheStats {
    /// Hit ratio in `[0.0, 1.0]` over all reads (hits / (hits + misses)); `0.0` when no reads yet.
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 { 0.0 } else { self.hits as f64 / total as f64 }
    }
}

/// An LRU + TTL edge cache bounded by a total byte budget.
#[derive(Debug)]
pub struct EdgeCache {
    entries: HashMap<String, CacheEntry>,
    /// Maximum total bytes the cache may hold. Inserts evict LRU entries to stay within it.
    max_bytes: u64,
    /// Default TTL applied when an insert does not specify one. `0` = no expiry.
    default_ttl_secs: u64,
    /// Current total bytes held (maintained incrementally to avoid O(n) sums).
    cur_bytes: u64,
    /// Monotonic counter handing out recency ticks; advances on every read and insert.
    tick: u64,
    hits: u64,
    misses: u64,
    expirations: u64,
    evictions: u64,
}

impl EdgeCache {
    /// Create a cache holding at most `max_bytes`, applying `default_ttl_secs` to inserts that do
    /// not override it (`0` TTL = entries never expire, only evict).
    pub fn new(max_bytes: u64, default_ttl_secs: u64) -> Self {
        EdgeCache {
            entries: HashMap::new(),
            max_bytes,
            default_ttl_secs,
            cur_bytes: 0,
            tick: 0,
            hits: 0,
            misses: 0,
            expirations: 0,
            evictions: 0,
        }
    }

    fn next_tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    /// Default TTL (seconds) applied to inserts that do not override it.
    pub fn default_ttl_secs(&self) -> u64 {
        self.default_ttl_secs
    }

    /// Insert (or replace) `cid -> bytes` using the cache's default TTL, evicting LRU entries as
    /// needed to fit. `now` is the current unix second. A single object larger than the whole
    /// budget is rejected (returns `false`) rather than evicting everything for something that can
    /// never fit.
    pub fn insert(&mut self, cid: &str, bytes: Vec<u8>, now: u64) -> bool {
        let ttl = self.default_ttl_secs;
        self.insert_with_ttl(cid, bytes, ttl, now)
    }

    /// Insert with an explicit `ttl_secs` (`0` = never expire). Returns `false` if `bytes` alone
    /// exceeds `max_bytes` (it cannot be cached without thrashing every other entry).
    pub fn insert_with_ttl(&mut self, cid: &str, bytes: Vec<u8>, ttl_secs: u64, now: u64) -> bool {
        let len = bytes.len() as u64;
        if len > self.max_bytes {
            return false;
        }
        // Remove any prior entry for this CID first (its bytes free up budget).
        self.drop_entry(cid);
        // Evict LRU entries until the newcomer fits.
        while self.cur_bytes + len > self.max_bytes {
            if !self.evict_one() {
                break; // nothing left to evict (cache empty) — len <= max_bytes so it fits now
            }
        }
        let tick = self.next_tick();
        let expires_at = if ttl_secs == 0 { u64::MAX } else { now.saturating_add(ttl_secs) };
        self.cur_bytes += len;
        self.entries.insert(
            cid.to_string(),
            CacheEntry { bytes, inserted_at: now, expires_at, last_tick: tick },
        );
        true
    }

    /// Look up `cid` at time `now`. Returns the bytes on a fresh hit (and bumps recency + the hit
    /// counter); on a miss or an expired entry returns `None` (and bumps the miss counter, dropping
    /// the entry if it had expired). This is the canonical read path for cache-hit accounting.
    pub fn get(&mut self, cid: &str, now: u64) -> Option<Vec<u8>> {
        let tick = self.next_tick();
        match self.entries.get_mut(cid) {
            Some(e) if now <= e.expires_at => {
                e.last_tick = tick;
                self.hits += 1;
                Some(e.bytes.clone())
            }
            Some(_) => {
                // Present but stale: drop it and count a miss + an expiration.
                self.drop_entry(cid);
                self.expirations += 1;
                self.misses += 1;
                None
            }
            None => {
                self.misses += 1;
                None
            }
        }
    }

    /// Is `cid` present and fresh at `now`? Does **not** affect recency or the hit/miss counters —
    /// use it for capacity/inventory checks (e.g. answering a mesh "do you hold this?" probe).
    pub fn contains_fresh(&self, cid: &str, now: u64) -> bool {
        self.entries.get(cid).is_some_and(|e| now <= e.expires_at)
    }

    /// Remove `cid` from the cache regardless of freshness; returns `true` if it was present.
    /// This is the **purge** primitive — explicit invalidation an operator can trigger.
    pub fn purge(&mut self, cid: &str) -> bool {
        self.drop_entry(cid)
    }

    /// Drop every entry whose TTL has passed at `now`; returns how many were swept. A maintenance
    /// pass the host loop calls periodically so dead bytes don't hold budget hostage. Swept entries
    /// count toward `expirations`.
    pub fn sweep_expired(&mut self, now: u64) -> usize {
        let dead: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| now > e.expires_at)
            .map(|(k, _)| k.clone())
            .collect();
        let n = dead.len();
        for k in dead {
            self.drop_entry(&k);
            self.expirations += 1;
        }
        n
    }

    /// A snapshot of the current counters and occupancy.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits,
            misses: self.misses,
            expirations: self.expirations,
            evictions: self.evictions,
            entries: self.entries.len() as u64,
            bytes: self.cur_bytes,
        }
    }

    /// Seconds remaining before `cid` expires at `now` (`None` if absent; `Some(u64::MAX)` if it
    /// never expires). Used to set the `Cache-Control: max-age` / `Age` headers on a hit.
    pub fn ttl_remaining(&self, cid: &str, now: u64) -> Option<u64> {
        self.entries.get(cid).map(|e| {
            if e.expires_at == u64::MAX {
                u64::MAX
            } else {
                e.expires_at.saturating_sub(now)
            }
        })
    }

    /// Seconds since `cid` was inserted at `now` (the HTTP `Age`); `None` if absent.
    pub fn age(&self, cid: &str, now: u64) -> Option<u64> {
        self.entries.get(cid).map(|e| now.saturating_sub(e.inserted_at))
    }

    // ----- internals -----

    /// Remove an entry by key, decrementing the byte total. Returns whether it existed.
    fn drop_entry(&mut self, cid: &str) -> bool {
        if let Some(e) = self.entries.remove(cid) {
            self.cur_bytes -= e.bytes.len() as u64;
            true
        } else {
            false
        }
    }

    /// Evict the single least-recently-used entry. Returns `false` if the cache is empty.
    fn evict_one(&mut self) -> bool {
        let Some(victim) = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_tick)
            .map(|(k, _)| k.clone())
        else {
            return false;
        };
        self.drop_entry(&victim);
        self.evictions += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miss_then_insert_then_hit() {
        let mut c = EdgeCache::new(1024, 60);
        assert!(c.get("a", 0).is_none());
        assert!(c.insert("a", vec![1, 2, 3], 0));
        assert_eq!(c.get("a", 0), Some(vec![1, 2, 3]));
        let s = c.stats();
        assert_eq!(s.hits, 1);
        assert_eq!(s.misses, 1);
        assert_eq!(s.entries, 1);
        assert_eq!(s.bytes, 3);
    }

    #[test]
    fn hit_ratio_accounting() {
        let mut c = EdgeCache::new(1024, 0);
        c.insert("a", vec![0; 4], 0);
        c.get("a", 0); // hit
        c.get("a", 0); // hit
        c.get("b", 0); // miss
        let s = c.stats();
        assert_eq!(s.hits, 2);
        assert_eq!(s.misses, 1);
        assert!((s.hit_ratio() - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn empty_stats_hit_ratio_is_zero() {
        let c = EdgeCache::new(16, 0);
        assert_eq!(c.stats().hit_ratio(), 0.0);
    }

    #[test]
    fn ttl_expiry_is_a_miss_and_drops_entry() {
        let mut c = EdgeCache::new(1024, 10);
        c.insert("a", vec![0; 8], 100); // expires at 110
        assert_eq!(c.get("a", 109), Some(vec![0; 8])); // fresh
        assert!(c.get("a", 111).is_none()); // expired -> miss
        let s = c.stats();
        assert_eq!(s.expirations, 1);
        assert_eq!(s.entries, 0);
        assert_eq!(s.bytes, 0);
        // A second read is a plain miss (entry already gone).
        assert!(c.get("a", 112).is_none());
        assert_eq!(c.stats().misses, 2);
    }

    #[test]
    fn zero_ttl_never_expires() {
        let mut c = EdgeCache::new(1024, 0);
        c.insert("a", vec![0; 8], 100);
        assert!(c.get("a", u64::MAX - 1).is_some());
        assert_eq!(c.ttl_remaining("a", 0), Some(u64::MAX));
    }

    #[test]
    fn lru_eviction_when_over_budget() {
        // budget 10 bytes; three 4-byte objects can't all fit.
        let mut c = EdgeCache::new(10, 0);
        c.insert("a", vec![0; 4], 0);
        c.insert("b", vec![0; 4], 0);
        // touch a so b is the LRU.
        assert!(c.get("a", 0).is_some());
        c.insert("d", vec![0; 4], 0); // needs to evict b (LRU)
        assert!(c.contains_fresh("a", 0));
        assert!(!c.contains_fresh("b", 0)); // b evicted
        assert!(c.contains_fresh("d", 0));
        assert_eq!(c.stats().evictions, 1);
        assert!(c.stats().bytes <= 10);
    }

    #[test]
    fn object_larger_than_budget_is_rejected() {
        let mut c = EdgeCache::new(8, 0);
        assert!(!c.insert("big", vec![0; 16], 0));
        assert_eq!(c.stats().entries, 0);
        // a fitting object still works after the rejection (no state corruption).
        assert!(c.insert("ok", vec![0; 8], 0));
        assert_eq!(c.stats().bytes, 8);
    }

    #[test]
    fn reinsert_replaces_and_frees_old_bytes() {
        let mut c = EdgeCache::new(100, 0);
        c.insert("a", vec![0; 40], 0);
        c.insert("a", vec![0; 10], 0); // replace; old 40 freed
        assert_eq!(c.stats().bytes, 10);
        assert_eq!(c.stats().entries, 1);
    }

    #[test]
    fn purge_removes_regardless_of_freshness() {
        let mut c = EdgeCache::new(100, 0);
        c.insert("a", vec![0; 4], 0);
        assert!(c.purge("a"));
        assert!(!c.purge("a")); // already gone
        assert_eq!(c.stats().entries, 0);
        assert_eq!(c.stats().bytes, 0);
    }

    #[test]
    fn sweep_drops_only_stale_entries() {
        let mut c = EdgeCache::new(100, 0);
        c.insert_with_ttl("fresh", vec![0; 4], 100, 0); // expires at 100
        c.insert_with_ttl("stale", vec![0; 4], 5, 0); // expires at 5
        c.insert_with_ttl("forever", vec![0; 4], 0, 0); // never
        let swept = c.sweep_expired(50);
        assert_eq!(swept, 1); // only "stale"
        assert!(c.contains_fresh("fresh", 50));
        assert!(c.contains_fresh("forever", 50));
        assert!(!c.contains_fresh("stale", 50));
        assert_eq!(c.stats().expirations, 1);
    }

    #[test]
    fn contains_fresh_does_not_touch_counters() {
        let mut c = EdgeCache::new(100, 10);
        c.insert("a", vec![0; 4], 0);
        assert!(c.contains_fresh("a", 5));
        assert!(!c.contains_fresh("a", 20)); // expired but not swept
        let s = c.stats();
        assert_eq!(s.hits, 0);
        assert_eq!(s.misses, 0); // contains_fresh is side-effect free
    }

    #[test]
    fn age_and_ttl_remaining() {
        let mut c = EdgeCache::new(100, 30);
        c.insert("a", vec![0; 4], 100); // inserted at 100, expires 130
        assert_eq!(c.age("a", 115), Some(15));
        assert_eq!(c.ttl_remaining("a", 115), Some(15));
        assert_eq!(c.age("missing", 0), None);
        assert_eq!(c.ttl_remaining("missing", 0), None);
    }
}
