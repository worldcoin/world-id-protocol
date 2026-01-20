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

    /// Sync the in-memory GLOBAL_TREE with database events without full reconstruction.
    /// This is more efficient than full initialization when only catching up with new events.
    ///
    /// Returns the number of events applied to the tree.
    pub async fn sync_with_db(&self, pool: &PgPool) -> anyhow::Result<u64> {
        use crate::tree::GLOBAL_TREE;

        // 1. Read current metadata to get last_event_id
        let metadata = metadata::read_metadata(&self.cache_path)?;

        info!(
            cache_event_id = metadata.last_event_id,
            cache_block = metadata.last_block_number,
            "Starting tree sync from cache metadata"
        );

        // 2. Check if there are new events
        let current_event_id = get_max_event_id(pool).await?;
        let events_behind = current_event_id.saturating_sub(metadata.last_event_id);

        if events_behind == 0 {
            info!("Tree is up-to-date, no sync needed");
            return Ok(0);
        }

        info!(
            current_event_id,
            events_behind,
            "Tree is {} events behind, syncing",
            events_behind
        );

        // 3. Take the current GLOBAL_TREE, replay events, and replace it
        // We need to extract the tree, do async replay, then put it back
        let current_tree = {
            let mut tree_guard = GLOBAL_TREE.write().await;
            let temp_tree = MerkleTree::<PoseidonHasher>::new(self.tree_depth, U256::ZERO);
            std::mem::replace(&mut *tree_guard, temp_tree)
        };

        let (updated_tree, new_block, new_event_id) = self
            .builder
            .replay_events(current_tree, pool, metadata.last_event_id)
            .await?;

        // 4. Put the updated tree back into GLOBAL_TREE
        let new_root = {
            let mut tree_guard = GLOBAL_TREE.write().await;
            *tree_guard = updated_tree;
            format!("0x{:x}", tree_guard.root())
        };

        // 5. Update metadata on disk (read tree again to get reference)
        let tree_for_metadata = GLOBAL_TREE.read().await;
        metadata::write_metadata(
            &self.cache_path,
            &*tree_for_metadata,
            pool,
            new_block,
            new_event_id,
            self.tree_depth,
            self.dense_prefix_depth,
        )
        .await?;

        info!(
            synced_to_block = new_block,
            synced_to_event_id = new_event_id,
            new_root = %new_root,
            events_applied = events_behind,
            "Tree sync complete"
        );

        Ok(events_behind as u64)
    }
}
