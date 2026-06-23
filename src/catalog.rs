//! The catalog: the publisher-side index of content put onto the CDN and which edges replicate it.
//!
//! Persisted as JSON at `<config dir>/ce-cdn/catalog.json` (human-inspectable; small). Each entry
//! pairs an immutable [`Content`] descriptor (CID, size, access, TTL, desired replication) with the
//! live [`EdgeReplica`] set (which edges currently cache it). The CLI reads/writes this file; the
//! re-replication loop updates edge health in place.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Whether published content is world-readable or capability-gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    /// Any consumer may fetch — no capability required (a public CDN asset).
    Public,
    /// Private — consumers must present a `ce-cap` chain granting `cdn:read`.
    Private,
}

impl Access {
    /// Is this content world-readable?
    pub fn is_public(&self) -> bool {
        matches!(self, Access::Public)
    }
}

/// An immutable description of content published to the CDN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Content {
    /// The object CID (manifest hash from `put_object`).
    pub cid: String,
    /// Total object size in bytes.
    pub bytes_len: u64,
    /// Public or capability-gated.
    pub access: Access,
    /// Desired number of edge replicas. The maintenance loop re-caches to restore this.
    pub replication: u8,
    /// Cache TTL (seconds) edges should apply (`0` = edge default / no expiry).
    pub ttl_secs: u64,
    /// Optional human label for `ce-cdn ls`.
    #[serde(default)]
    pub label: Option<String>,
}

/// A single edge replica: an edge that cached the content, plus its last-known health.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeReplica {
    /// 64-hex NodeId of the edge holding a copy.
    pub edge: String,
    /// Result of the most recent status probe (`true` = the edge still holds it).
    #[serde(default)]
    pub healthy: bool,
}

/// One catalog entry: the content plus its current edge-replica set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub content: Content,
    #[serde(default)]
    pub edges: Vec<EdgeReplica>,
}

impl Entry {
    /// Count of edges whose last probe passed (the live replication factor).
    pub fn healthy_edges(&self) -> usize {
        self.edges.iter().filter(|e| e.healthy).count()
    }

    /// The 64-hex NodeIds of all edges in this entry (for exclude-lists during re-replication).
    pub fn edge_ids(&self) -> Vec<String> {
        self.edges.iter().map(|e| e.edge.clone()).collect()
    }
}

/// The whole catalog, keyed by CID (a `BTreeMap` so `ls` output is stable and the file diffs cleanly).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Catalog {
    #[serde(default)]
    pub items: BTreeMap<String, Entry>,
}

impl Catalog {
    /// Default on-disk location: `<config dir>/ce-cdn/catalog.json`, overridable via `$CE_CDN_DIR`.
    pub fn default_path() -> PathBuf {
        if let Some(d) = std::env::var_os("CE_CDN_DIR") {
            return PathBuf::from(d).join("catalog.json");
        }
        let base = directories::ProjectDirs::from("", "", "ce-cdn")
            .map(|p| p.config_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".ce-cdn"));
        base.join("catalog.json")
    }

    /// Load the catalog from `path`, returning an empty catalog if the file does not exist.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Catalog::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Persist the catalog to `path`, creating parent directories as needed (pretty-printed).
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    /// Insert or replace an entry by CID.
    pub fn upsert(&mut self, entry: Entry) {
        self.items.insert(entry.content.cid.clone(), entry);
    }

    /// Remove an entry by CID, returning it if present.
    pub fn remove(&mut self, cid: &str) -> Option<Entry> {
        self.items.remove(cid)
    }

    /// Look up an entry by CID.
    pub fn get(&self, cid: &str) -> Option<&Entry> {
        self.items.get(cid)
    }

    /// Mutable lookup by CID (for the maintenance loop to update edge health in place).
    pub fn get_mut(&mut self, cid: &str) -> Option<&mut Entry> {
        self.items.get_mut(cid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(cid: &str, access: Access) -> Entry {
        Entry {
            content: Content {
                cid: cid.into(),
                bytes_len: 2048,
                access,
                replication: 3,
                ttl_secs: 3600,
                label: Some("video.mp4".into()),
            },
            edges: vec![
                EdgeReplica { edge: "edge-a".into(), healthy: true },
                EdgeReplica { edge: "edge-b".into(), healthy: false },
            ],
        }
    }

    #[test]
    fn roundtrips_through_disk() {
        let tmp = std::env::temp_dir().join(format!("ce-cdn-test-{}", std::process::id()));
        let path = tmp.join("catalog.json");
        let mut cat = Catalog::default();
        cat.upsert(sample("cid-1", Access::Public));
        cat.save(&path).unwrap();

        let loaded = Catalog::load(&path).unwrap();
        assert_eq!(loaded.get("cid-1"), cat.get("cid-1"));
        assert_eq!(loaded.get("cid-1").unwrap().content.access, Access::Public);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn missing_file_is_empty_catalog() {
        let path = std::env::temp_dir().join("ce-cdn-nope-xyz/catalog.json");
        assert!(Catalog::load(&path).unwrap().items.is_empty());
    }

    #[test]
    fn healthy_edges_and_ids() {
        let e = sample("c", Access::Private);
        assert_eq!(e.healthy_edges(), 1);
        assert_eq!(e.edge_ids(), vec!["edge-a".to_string(), "edge-b".to_string()]);
    }

    #[test]
    fn access_serializes_lowercase() {
        let v = serde_json::to_string(&Access::Public).unwrap();
        assert_eq!(v, "\"public\"");
        let p: Access = serde_json::from_str("\"private\"").unwrap();
        assert_eq!(p, Access::Private);
        assert!(Access::Public.is_public());
        assert!(!Access::Private.is_public());
    }

    #[test]
    fn upsert_replaces_and_remove_works() {
        let mut cat = Catalog::default();
        cat.upsert(sample("c", Access::Public));
        let mut updated = sample("c", Access::Public);
        updated.content.replication = 9;
        cat.upsert(updated);
        assert_eq!(cat.get("c").unwrap().content.replication, 9);
        assert!(cat.remove("c").is_some());
        assert!(cat.get("c").is_none());
    }
}
