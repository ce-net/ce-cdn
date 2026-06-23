//! Replica placement: choose which edges to push content to, and decide when re-replication is due.
//!
//! Mesh-first and reputation-aware: candidate edges come from the DHT (`find_service("cdn:edge")`)
//! and the capacity atlas; we rank them by proven delivered work (`history(...).delivered_work()`),
//! liveness (`last_seen_secs`), and free memory, preferring edges that have delivered before and
//! were seen recently. A CDN wants geographically/topologically spread replicas; absent a real
//! geo-signal in CE, we approximate spread by picking distinct high-reputation, live edges. The
//! ranking is pure so it is unit-testable without a live mesh.

/// A candidate edge with the signals we rank on. Built from `AtlasEntry` + `NodeHistory` by the
/// client; kept as a small owned struct so the ranking is network-free and testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeCandidate {
    /// 64-hex NodeId.
    pub node_id: String,
    /// Proven delivered work (settled jobs + heartbeats hosted). Higher = more trusted.
    pub delivered_work: u64,
    /// Seconds since this edge was last seen advertising capacity. Lower = fresher / more live.
    pub last_seen_secs: u64,
    /// Free memory advertised (MiB) — a coarse capacity hint to avoid overloaded edges.
    pub mem_mb: u32,
}

/// Rank edge candidates best-first for replication. Ordering, in priority:
///   1. more proven delivered work (descending) — trust the edges that have delivered;
///   2. seen more recently (ascending `last_seen_secs`) — prefer live edges;
///   3. more free memory (descending) — tie-break toward roomier edges;
///   4. node_id (ascending) — final deterministic tie-break so order is stable.
///
/// Returns a new sorted `Vec`; the input is not mutated.
pub fn rank(candidates: &[EdgeCandidate]) -> Vec<EdgeCandidate> {
    let mut v = candidates.to_vec();
    v.sort_by(|a, b| {
        b.delivered_work
            .cmp(&a.delivered_work)
            .then(a.last_seen_secs.cmp(&b.last_seen_secs))
            .then(b.mem_mb.cmp(&a.mem_mb))
            .then(a.node_id.cmp(&b.node_id))
    });
    v
}

/// Pick up to `n` distinct edges for replication, best-first, excluding any in `exclude` (e.g. the
/// publisher itself, or edges that already hold the object during re-replication).
pub fn select(candidates: &[EdgeCandidate], n: usize, exclude: &[String]) -> Vec<String> {
    rank(candidates)
        .into_iter()
        .map(|c| c.node_id)
        .filter(|id| !exclude.iter().any(|e| e == id))
        .take(n)
        .collect()
}

/// How many *new* edges to recruit to restore a target replication factor, given the edges that
/// currently hold a healthy copy. Returns `0` when already at or above target (never negative).
pub fn replicas_needed(target: u8, healthy_now: usize) -> usize {
    (target as usize).saturating_sub(healthy_now)
}

/// Decide whether re-replication is warranted: true when fewer than `target` healthy replicas
/// remain. The audit/maintenance loop calls this after probing current holders.
pub fn needs_rereplication(target: u8, healthy_now: usize) -> bool {
    healthy_now < target as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(id: &str, work: u64, seen: u64, mem: u32) -> EdgeCandidate {
        EdgeCandidate { node_id: id.into(), delivered_work: work, last_seen_secs: seen, mem_mb: mem }
    }

    #[test]
    fn ranks_proven_edges_first() {
        let cs = vec![cand("a", 0, 10, 1000), cand("b", 5, 100, 500), cand("c", 5, 10, 500)];
        let ranked = rank(&cs);
        // b and c both have work 5, but c was seen more recently -> c before b; a (work 0) last.
        assert_eq!(ranked.iter().map(|c| c.node_id.as_str()).collect::<Vec<_>>(), ["c", "b", "a"]);
    }

    #[test]
    fn mem_breaks_ties_after_work_and_liveness() {
        let cs = vec![cand("x", 3, 50, 256), cand("y", 3, 50, 4096)];
        let ranked = rank(&cs);
        assert_eq!(ranked[0].node_id, "y");
    }

    #[test]
    fn node_id_is_final_tiebreak() {
        let cs = vec![cand("z", 1, 1, 1), cand("a", 1, 1, 1)];
        let ranked = rank(&cs);
        assert_eq!(ranked[0].node_id, "a");
    }

    #[test]
    fn select_excludes_and_caps() {
        let cs = vec![cand("a", 9, 1, 1), cand("b", 8, 1, 1), cand("c", 7, 1, 1)];
        let picked = select(&cs, 2, &["a".to_string()]);
        assert_eq!(picked, ["b", "c"]);
    }

    #[test]
    fn select_handles_fewer_candidates_than_requested() {
        let cs = vec![cand("a", 1, 1, 1)];
        assert_eq!(select(&cs, 5, &[]), ["a"]);
    }

    #[test]
    fn select_on_empty_is_empty() {
        assert!(select(&[], 3, &[]).is_empty());
    }

    #[test]
    fn replicas_needed_and_rereplication() {
        assert_eq!(replicas_needed(3, 1), 2);
        assert_eq!(replicas_needed(3, 3), 0);
        assert_eq!(replicas_needed(3, 5), 0); // never negative
        assert!(needs_rereplication(3, 2));
        assert!(!needs_rereplication(3, 3));
        assert!(!needs_rereplication(3, 4));
    }
}
