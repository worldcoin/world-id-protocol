use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use super::{MerkleTree, PoseidonHasher};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeCacheMetadata {
    /// Root hash of the tree when cache was written
    pub root_hash: String,

    /// Last block number included in this cache
    pub last_block_number: u64,

    /// Last event ID processed (safety check)
    pub last_event_id: i64,

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
    pub max_block_number: u64,
    #[allow(dead_code)]
    pub total_events: u64,
    #[allow(dead_code)]
    pub active_leaf_count: u64,
}

/// Read metadata from .meta file
pub fn read_metadata(cache_path: &Path) -> anyhow::Result<TreeCacheMetadata> {
    let meta_path = cache_path.with_extension("mmap.meta");

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
    pool: &PgPool,
    last_block_number: u64,
) -> anyhow::Result<()> {
    // Get current database state
    let last_event_id = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT MAX(id) FROM commitment_update_events WHERE block_number <= $1",
    )
    .bind(last_block_number as i64)
    .fetch_one(pool)
    .await?
    .unwrap_or(0);

    let active_leaf_count =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM accounts WHERE leaf_index != '0'")
            .fetch_one(pool)
            .await?;

    // Create metadata
    let metadata = TreeCacheMetadata {
        root_hash: format!("0x{:x}", tree.root()),
        last_block_number,
        last_event_id,
        active_leaf_count: active_leaf_count as u64,
        tree_depth: crate::TREE_DEPTH,
        dense_prefix_depth: 20, // This will be provided by config in later steps
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        cache_version: 1,
    };

    // Write to temporary file
    let meta_path = cache_path.with_extension("mmap.meta");
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
        block_number = last_block_number,
        root = %metadata.root_hash,
        "Wrote metadata to disk"
    );

    Ok(())
}

/// Get current database state (for validation)
pub async fn get_db_state(pool: &PgPool) -> anyhow::Result<DbState> {
    let max_block_number = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT COALESCE(MAX(block_number), 0) FROM commitment_update_events",
    )
    .fetch_one(pool)
    .await?
    .unwrap_or(0) as u64;

    let total_events =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM commitment_update_events")
            .fetch_one(pool)
            .await?;

    let active_leaf_count =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM accounts WHERE leaf_index != '0'")
            .fetch_one(pool)
            .await?;

    Ok(DbState {
        max_block_number,
        total_events: total_events as u64,
        active_leaf_count: active_leaf_count as u64,
    })
}
