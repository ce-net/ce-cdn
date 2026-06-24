//! Re-replication / health maintenance — keep each published object at its target replica count.
//!
//! The publisher records a desired replication factor per object ([`crate::catalog::Content`]). Over
//! time edges churn (restart, drop the cache, go offline), so the live replica count drifts below
//! target. This module is the loop that fixes that: for every catalog entry it probes the recorded +
//! DHT-discovered edges, marks each healthy/unhealthy, and — when fewer than `replication` healthy
//! copies remain — recruits fresh edges and asks them to cache the object, restoring the target.
//!
//! The decision logic is factored into the pure [`plan_entry`] function (probe results in →
//! actions out) so the policy is unit-testable without a live mesh; [`run_once`] /
//! [`run_forever`] are the thin async drivers over [`crate::client::CdnClient`].

use std::collections::BTreeSet;

use anyhow::Result;

use crate::catalog::{Catalog, EdgeReplica};
use crate::client::CdnClient;
use crate::replication::replicas_needed;

/// The outcome of reconciling one catalog entry: which recorded edges are healthy now, and how many
/// fresh replicas to recruit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPlan {
    /// The CID being reconciled.
    pub cid: String,
    /// Edges (by NodeId) that passed their probe and still hold the object.
    pub healthy: Vec<String>,
    /// Edges (by NodeId) that failed their probe (no longer hold it / unreachable).
    pub unhealthy: Vec<String>,
    /// How many NEW edges to recruit to restore the target replication factor.
    pub recruit: usize,
}

/// Decide what reconciliation an entry needs, given the probe result for each currently-recorded
/// edge (`true` = the edge still holds a healthy copy). Pure: the same inputs always yield the same
/// plan, so the policy is exhaustively testable.
///
/// `target` is the desired replication factor; `probes` is `(edge_id, healthy)` for each recorded
/// edge. The `recruit` count is `target - healthy_now` (never negative).
pub fn plan_entry(cid: &str, target: u8, probes: &[(String, bool)]) -> EntryPlan {
    let mut healthy = Vec::new();
    let mut unhealthy = Vec::new();
    for (edge, ok) in probes {
        if *ok {
            healthy.push(edge.clone());
        } else {
            unhealthy.push(edge.clone());
        }
    }
    let recruit = replicas_needed(target, healthy.len());
    EntryPlan { cid: cid.to_string(), healthy, unhealthy, recruit }
}

/// A summary of one maintenance pass, for the CLI to report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaintainReport {
    /// CIDs examined this pass.
    pub examined: usize,
    /// New replicas successfully recruited across all entries.
    pub recruited: usize,
    /// Replica targets that could not be fully met (no more candidate edges available).
    pub shortfalls: usize,
}

/// Run a single maintenance pass over `catalog_path`: probe every entry's edges, recruit fresh
/// replicas where short, and persist the updated edge-health back to the catalog atomically (under
/// its lock). `caps_hex` is the capability chain presented to edges for `cdn/status` (probe) and
/// `cdn/cache` (recruit). Returns a [`MaintainReport`].
pub async fn run_once(
    client: &CdnClient,
    catalog_path: &std::path::Path,
    caps_hex: &str,
) -> Result<MaintainReport> {
    // Snapshot the catalog (read), do all the network I/O without holding the lock, then commit the
    // results under the lock in one atomic update.
    let snapshot = Catalog::load(catalog_path)?;
    let mut report = MaintainReport::default();
    // Per-CID resolved results to commit: (cid, healthy_edges, newly_cached_edges).
    let mut results: Vec<(String, Vec<EdgeReplica>)> = Vec::new();

    for (cid, entry) in &snapshot.items {
        report.examined += 1;
        let target = entry.content.replication;

        // Probe each recorded edge for liveness.
        let mut probes: Vec<(String, bool)> = Vec::new();
        for edge in entry.edge_ids() {
            let healthy = matches!(client.probe(&edge, cid, caps_hex).await, Ok(s) if s.held);
            probes.push((edge, healthy));
        }
        let plan = plan_entry(cid, target, &probes);

        // Keep the healthy recorded edges.
        let mut edges: Vec<EdgeReplica> =
            plan.healthy.iter().map(|e| EdgeReplica { edge: e.clone(), healthy: true }).collect();

        // Recruit fresh replicas (excluding edges we already hold or just probed).
        if plan.recruit > 0 {
            let mut exclude: BTreeSet<String> = entry.edge_ids().into_iter().collect();
            let picks = client
                .pick_edges(plan.recruit, &exclude.iter().cloned().collect::<Vec<_>>())
                .await
                .unwrap_or_default();
            let mut got = 0usize;
            for pick in picks {
                if exclude.contains(&pick) {
                    continue;
                }
                match client
                    .replicate_to(&pick, cid, entry.content.bytes_len, entry.content.ttl_secs, caps_hex)
                    .await
                {
                    Ok(r) if r.cached => {
                        edges.push(EdgeReplica { edge: pick.clone(), healthy: true });
                        exclude.insert(pick);
                        got += 1;
                        report.recruited += 1;
                    }
                    _ => {}
                }
            }
            if got < plan.recruit {
                report.shortfalls += 1;
            }
        }

        results.push((cid.clone(), edges));
    }

    // Commit the freshly-measured health + new replicas atomically, only for entries that still
    // exist (a concurrent purge may have removed one between snapshot and commit).
    Catalog::update(catalog_path, |cat| {
        for (cid, edges) in results {
            if let Some(entry) = cat.get_mut(&cid) {
                entry.edges = edges;
            }
        }
        Ok(())
    })?;

    Ok(report)
}

/// Run the maintenance loop forever, sleeping `interval_secs` between passes. Logs each pass. Errors
/// in a single pass are logged and the loop continues (a transient mesh/API blip must not stop
/// maintenance). Runs until the process is killed.
pub async fn run_forever(
    client: &CdnClient,
    catalog_path: &std::path::Path,
    caps_hex: &str,
    interval_secs: u64,
) -> Result<()> {
    let interval = std::time::Duration::from_secs(interval_secs.max(1));
    tracing::info!(interval_secs, "ce-cdn maintenance loop started");
    loop {
        match run_once(client, catalog_path, caps_hex).await {
            Ok(r) => tracing::info!(
                examined = r.examined,
                recruited = r.recruited,
                shortfalls = r.shortfalls,
                "maintenance pass complete"
            ),
            Err(e) => tracing::warn!(error = %e, "maintenance pass failed (continuing)"),
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_keeps_healthy_and_recruits_for_unhealthy() {
        let probes = vec![
            ("a".to_string(), true),
            ("b".to_string(), false),
            ("c".to_string(), true),
        ];
        let plan = plan_entry("cid", 3, &probes);
        assert_eq!(plan.healthy, vec!["a".to_string(), "c".to_string()]);
        assert_eq!(plan.unhealthy, vec!["b".to_string()]);
        // 2 healthy of target 3 -> recruit 1.
        assert_eq!(plan.recruit, 1);
    }

    #[test]
    fn plan_at_target_recruits_nothing() {
        let probes = vec![("a".to_string(), true), ("b".to_string(), true)];
        let plan = plan_entry("cid", 2, &probes);
        assert_eq!(plan.recruit, 0);
        assert!(plan.unhealthy.is_empty());
    }

    #[test]
    fn plan_over_target_never_negative() {
        let probes = vec![("a".to_string(), true), ("b".to_string(), true), ("c".to_string(), true)];
        let plan = plan_entry("cid", 2, &probes);
        assert_eq!(plan.recruit, 0);
        assert_eq!(plan.healthy.len(), 3);
    }

    #[test]
    fn plan_all_dead_recruits_full_target() {
        let probes = vec![("a".to_string(), false), ("b".to_string(), false)];
        let plan = plan_entry("cid", 4, &probes);
        assert!(plan.healthy.is_empty());
        assert_eq!(plan.recruit, 4);
    }

    #[test]
    fn plan_no_recorded_edges_recruits_full_target() {
        let plan = plan_entry("cid", 3, &[]);
        assert_eq!(plan.recruit, 3);
        assert!(plan.healthy.is_empty());
    }
}
