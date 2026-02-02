use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use super::{MerkleTree, PoseidonHasher, TreeError, TreeResult};
use crate::db::{DB, WorldTreeEventId, get_active_leaf_count, get_total_event_count};

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
    pub last_event_id: Option<WorldTreeEventId>,
    #[allow(dead_code)]
    pub total_events: u64,
    #[allow(dead_code)]
    pub active_leaf_count: u64,
}

/// Read metadata from .meta file
pub fn read_metadata(cache_path: &Path) -> TreeResult<TreeCacheMetadata> {
    let meta_path = metadata_path(cache_path);

    if !meta_path.exists() {
        return Err(TreeError::MetadataMissing(meta_path.display().to_string()));
    }

    let meta_json = fs::read_to_string(&meta_path)
        .map_err(|err| TreeError::MetadataRead(format!("{}: {}", meta_path.display(), err)))?;

    let metadata: TreeCacheMetadata = serde_json::from_str(&meta_json)
        .map_err(|err| TreeError::MetadataParse(format!("{}: {}", meta_path.display(), err)))?;

    Ok(metadata)
}

/// Write metadata atomically (write to .tmp, then rename)
pub async fn write_metadata(
    cache_path: &Path,
    tree: &MerkleTree<PoseidonHasher, semaphore_rs_trees::lazy::Canonical>,
    db: &DB,
    last_event_id: WorldTreeEventId,
    tree_depth: usize,
    dense_prefix_depth: usize,
) -> TreeResult<()> {
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

    let meta_json = serde_json::to_string_pretty(&metadata)
        .map_err(|err| TreeError::MetadataSerialize(err.to_string()))?;

    fs::write(&temp_path, meta_json)
        .map_err(|err| TreeError::MetadataWrite(format!("{}: {}", temp_path.display(), err)))?;

    // Atomic rename
    fs::rename(&temp_path, &meta_path).map_err(|err| {
        TreeError::MetadataRename(format!(
            "{} -> {}: {}",
            temp_path.display(),
            meta_path.display(),
            err
        ))
    })?;

    tracing::debug!(
        event_id = ?last_event_id,
        root = %metadata.root_hash,
        "Wrote metadata to disk"
    );

    Ok(())
}

/// Get current database state (for validation)
pub async fn get_db_state(db: &DB) -> TreeResult<DbState> {
    let last_event_id = db.world_tree_events().get_latest_id().await?;
    let total_events = get_total_event_count(db.pool()).await?;
    let active_leaf_count = get_active_leaf_count(db.pool()).await?;

    Ok(DbState {
        last_event_id,
        total_events,
        active_leaf_count,
    })
}
