use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use super::{MerkleTree, PoseidonHasher};
use crate::db::{DB, EventId, get_active_leaf_count, get_total_event_count};

/// Get the metadata file path for a given cache path.
/// Cache file: `/path/to/tree.mmap` → Metadata: `/path/to/tree.mmap.meta`
pub fn metadata_path(cache_path: &Path) -> PathBuf {
    cache_path.with_extension("mmap.meta")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeCacheMetadata {
    /// Root hash of the tree when cache was written
    pub root_hash: String,

    /// Last block number included in this cache
    pub last_block_number: u64,

    /// Last log index included in this cache
    pub last_log_index: u64,

    /// Number of non-zero leaves in the tree
    pub active_leaf_count: u64,

    /// Tree depth configuration
    pub tree_depth: usize,

    /// Dense prefix depth configuration
    pub dense_prefix_depth: usize,

    /// Unix timestamp when cache was created
    pub created_at: i64,

    /// Cache format version (for future compatibility)
    pub cache_version: u8,
}

/// Database state information for validation
#[derive(Debug)]
pub struct DbState {
    pub last_event_id: Option<EventId>,
    #[allow(dead_code)]
    pub total_events: u64,
    #[allow(dead_code)]
    pub active_leaf_count: u64,
}

/// Read metadata from .meta file
pub fn read_metadata(cache_path: &Path) -> anyhow::Result<TreeCacheMetadata> {
    let meta_path = metadata_path(cache_path);

    if !meta_path.exists() {
        anyhow::bail!("Metadata file does not exist: {}", meta_path.display());
    }

    let meta_json = fs::read_to_string(&meta_path)
        .with_context(|| format!("Failed to read metadata file: {}", meta_path.display()))?;

    let metadata: TreeCacheMetadata = serde_json::from_str(&meta_json)
        .with_context(|| format!("Failed to parse metadata file: {}", meta_path.display()))?;

    Ok(metadata)
}

/// Write metadata atomically (write to .tmp, then rename)
pub async fn write_metadata(
    cache_path: &Path,
    tree: &MerkleTree<PoseidonHasher, semaphore_rs_trees::lazy::Canonical>,
    db: &DB,
    last_event_id: EventId,
    tree_depth: usize,
    dense_prefix_depth: usize,
) -> anyhow::Result<()> {
    // Get current database state
    let active_leaf_count = get_active_leaf_count(db.pool()).await?;

    // Create metadata
    let metadata = TreeCacheMetadata {
        root_hash: format!("0x{:x}", tree.root()),
        last_block_number: last_event_id.block_number,
        last_log_index: last_event_id.log_index,
        active_leaf_count,
        tree_depth,
        dense_prefix_depth,
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        cache_version: 1,
    };

    // Write to temporary file
    let meta_path = metadata_path(cache_path);
    let temp_path = cache_path.with_extension("mmap.meta.tmp");

    let meta_json =
        serde_json::to_string_pretty(&metadata).context("Failed to serialize metadata")?;

    fs::write(&temp_path, meta_json).with_context(|| {
        format!(
            "Failed to write temporary metadata file: {}",
            temp_path.display()
        )
    })?;

    // Atomic rename
    fs::rename(&temp_path, &meta_path).with_context(|| {
        format!(
            "Failed to rename {} to {}",
            temp_path.display(),
            meta_path.display()
        )
    })?;

    tracing::debug!(
        event_id = ?last_event_id,
        root = %metadata.root_hash,
        "Wrote metadata to disk"
    );

    Ok(())
}

/// Get current database state (for validation)
pub async fn get_db_state(db: &DB) -> anyhow::Result<DbState> {
    let last_event_id = db.world_id_events().get_latest_id().await?;
    let total_events = get_total_event_count(db.pool()).await?;
    let active_leaf_count = get_active_leaf_count(db.pool()).await?;

    Ok(DbState {
        last_event_id,
        total_events,
        active_leaf_count,
    })
}
