use std::fmt;
use std::path::PathBuf;
use std::time::Instant;

use alloy::primitives::U256;
use semaphore_rs_trees::lazy::{Canonical, LazyMerkleTree as MerkleTree};
use sqlx::PgPool;
use tracing::{info, warn};

use super::PoseidonHasher;

use super::{builder::TreeBuilder, metadata};
use crate::db::get_max_event_id;

/// State of cache files on disk
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheState {
    /// Both mmap and metadata files exist
    Valid,
    /// Mmap file exists but metadata is missing
    MetadataMissing,
    /// Metadata file exists but mmap is missing
    MmapMissing,
    /// Neither file exists (fresh start)
    BothMissing,
}

impl fmt::Display for CacheState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CacheState::Valid => write!(f, "cache is valid"),
            CacheState::MetadataMissing => write!(f, "metadata file missing"),
            CacheState::MmapMissing => write!(f, "mmap file missing"),
            CacheState::BothMissing => write!(f, "no cache files found"),
        }
    }
}

impl CacheState {
    pub fn is_valid(&self) -> bool {
        matches!(self, CacheState::Valid)
    }
}

pub struct TreeInitializer {
    builder: TreeBuilder,
    cache_path: PathBuf,
    tree_depth: usize,
    dense_prefix_depth: usize,
}

impl TreeInitializer {
    pub fn new(
        cache_file_path: String,
        tree_depth: usize,
        dense_prefix_depth: usize,
        empty_value: U256,
    ) -> Self {
        Self {
            builder: TreeBuilder::new(tree_depth, dense_prefix_depth, empty_value),
            cache_path: PathBuf::from(cache_file_path),
            tree_depth,
            dense_prefix_depth,
        }
    }

    /// Check the state of cache files on disk
    pub fn check_cache_files(&self) -> CacheState {
        let meta_exists = metadata::metadata_path(&self.cache_path).exists();
        let mmap_exists = self.cache_path.exists();

        match (meta_exists, mmap_exists) {
            (true, true) => CacheState::Valid,
            (false, true) => CacheState::MetadataMissing,
            (true, false) => CacheState::MmapMissing,
            (false, false) => CacheState::BothMissing,
        }
    }

    /// Initialize tree: try restore + replay, fallback to full rebuild
    pub async fn initialize(
        &self,
        pool: &PgPool,
    ) -> anyhow::Result<MerkleTree<PoseidonHasher, Canonical>> {
        let start = Instant::now();

        let cache_state = self.check_cache_files();
        info!(?cache_state, "Checking cache files");

        // If either file is missing, skip restore attempt and do full rebuild
        let tree = if cache_state.is_valid() {
            match self.try_restore_and_replay(pool).await {
                Ok(tree) => {
                    info!("Successfully restored and updated tree from cache");
                    tree
                }
                Err(e) => {
                    warn!("Cache restore failed ({}), doing full rebuild", e);
                    self.full_rebuild_with_cache(pool).await?
                }
            }
        } else {
            info!("{}, building tree from scratch", cache_state);
            self.full_rebuild_with_cache(pool).await?
        };

        info!("Tree initialization took {:?}", start.elapsed());
        Ok(tree)
    }

    /// Try to restore from cache and replay missed events
    async fn try_restore_and_replay(
        &self,
        pool: &PgPool,
    ) -> anyhow::Result<MerkleTree<PoseidonHasher, Canonical>> {
        // 1. Read metadata
        let metadata = metadata::read_metadata(&self.cache_path)?;

        info!(
            cache_block = metadata.last_block_number,
            cache_event_id = metadata.last_event_id,
            cache_root = %metadata.root_hash,
            "Found cache metadata"
        );

        // 2. Get current DB state
        let db_state = metadata::get_db_state(pool).await?;
        let current_event_id = get_max_event_id(pool).await?;

        let blocks_behind = db_state
            .max_block_number
            .saturating_sub(metadata.last_block_number);
        let events_behind = current_event_id.saturating_sub(metadata.last_event_id);

        info!(
            current_block = db_state.max_block_number,
            current_event_id,
            blocks_behind,
            events_behind,
            "Cache is {} blocks / {} events behind",
            blocks_behind,
            events_behind
        );

        // 3. Restore tree from mmap
        let tree = self.builder.restore_from_cache(&self.cache_path)?;

        // 4. Verify restored root matches metadata
        let restored_root = format!("0x{:x}", tree.root());
        if restored_root != metadata.root_hash {
            anyhow::bail!(
                "Root mismatch: expected {}, got {}",
                metadata.root_hash,
                restored_root
            );
        }

        // 5. Replay events if needed (based on event ID, not block number)
        if events_behind == 0 {
            info!("Cache is up-to-date, no replay needed");
            return Ok(tree);
        }

        // Use event ID as the replay cursor (not block number)
        let (updated_tree, new_block, new_event_id) = self
            .builder
            .replay_events(tree, pool, metadata.last_event_id)
            .await?;

        // 6. Update metadata with new event ID
        metadata::write_metadata(
            &self.cache_path,
            &updated_tree,
            pool,
            new_block,
            new_event_id,
            self.tree_depth,
            self.dense_prefix_depth,
        )
        .await?;

        info!(
            replayed_to_block = new_block,
            replayed_to_event_id = new_event_id,
            new_root = %format!("0x{:x}", updated_tree.root()),
            "Replay complete"
        );

        Ok(updated_tree)
    }

    /// Full rebuild from database with cache
    async fn full_rebuild_with_cache(
        &self,
        pool: &PgPool,
    ) -> anyhow::Result<MerkleTree<PoseidonHasher, Canonical>> {
        info!("Starting full tree rebuild with cache");

        let (tree, last_block, last_event_id) = self
            .builder
            .build_from_db_with_cache(pool, &self.cache_path)
            .await?;

        // Write metadata with event ID
        metadata::write_metadata(
            &self.cache_path,
            &tree,
            pool,
            last_block,
            last_event_id,
            self.tree_depth,
            self.dense_prefix_depth,
        )
        .await?;

        info!(
            root = %format!("0x{:x}", tree.root()),
            last_block,
            last_event_id,
            "Full rebuild complete"
        );

        Ok(tree)
    }
}
