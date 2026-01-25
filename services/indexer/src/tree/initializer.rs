use std::{fmt, path::PathBuf, time::Instant};

use alloy::primitives::U256;
use sqlx::PgPool;
use tracing::{info, warn};

use super::{builder::TreeBuilder, metadata};
use crate::db::{fetch_sparse_leaves, get_max_event_id};

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

    /// Initialize tree: try restore + replay, fallback to full rebuild.
    /// Updates GLOBAL_TREE atomically and returns nothing.
    pub async fn initialize(&self, pool: &PgPool) -> anyhow::Result<()> {
        let start = Instant::now();

        let cache_state = self.check_cache_files();
        info!(?cache_state, "Checking cache files");

        // If either file is missing, skip restore attempt and do full rebuild
        if cache_state.is_valid() {
            match self.try_restore_and_replay(pool).await {
                Ok(()) => {
                    info!("Successfully restored and updated tree from cache");
                }
                Err(e) => {
                    warn!("Cache restore failed ({}), doing full rebuild", e);
                    self.full_rebuild_and_update_global_tree(pool).await?;
                }
            }
        } else {
            info!("{}, building tree from scratch", cache_state);
            self.full_rebuild_and_update_global_tree(pool).await?;
        };

        info!("Tree initialization took {:?}", start.elapsed());
        Ok(())
    }

    /// Try to restore from cache and replay missed events.
    /// Updates GLOBAL_TREE atomically.
    ///
    /// The mmap file only stores the dense prefix of the tree. Sparse leaves
    /// (beyond the dense prefix) are stored in memory only and need to be
    /// restored from the database after loading the mmap.
    async fn try_restore_and_replay(&self, pool: &PgPool) -> anyhow::Result<()> {
        use crate::tree::GLOBAL_TREE;

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

        // 3. Restore tree from mmap (only gets dense prefix)
        let mut tree = self.builder.restore_from_cache(&self.cache_path)?;

        // 4. Restore sparse leaves from database
        //    The mmap only stores leaves in the dense prefix (indices 0 to 2^dense_prefix_depth - 1).
        //    Sparse leaves (beyond the dense prefix) must be restored from DB.
        let dense_prefix_size = 1usize << self.dense_prefix_depth;
        let sparse_leaves = fetch_sparse_leaves(pool, dense_prefix_size).await?;

        if !sparse_leaves.is_empty() {
            info!(
                sparse_count = sparse_leaves.len(),
                dense_prefix_size,
                "Restoring {} sparse leaves from database",
                sparse_leaves.len()
            );

            for (leaf_index, commitment_str) in &sparse_leaves {
                let commitment = commitment_str
                    .parse::<U256>()
                    .map_err(|e| anyhow::anyhow!("Failed to parse commitment: {}", e))?;
                tree = tree.update_with_mutation(*leaf_index, &commitment);
            }

            info!("Sparse leaves restored");
        }

        // 5. Verify restored root matches metadata (now including sparse leaves)
        let restored_root = format!("0x{:x}", tree.root());
        if restored_root != metadata.root_hash {
            anyhow::bail!(
                "Root mismatch after sparse restore: expected {}, got {}",
                metadata.root_hash,
                restored_root
            );
        }

        // 6. Replay new events if needed (based on event ID, not block number)
        let final_tree = if events_behind == 0 {
            info!("Cache is up-to-date, no replay needed");
            tree
        } else {
            // Use event ID as the replay cursor (not block number)
            let (updated_tree, new_block, new_event_id) = self
                .builder
                .replay_events(tree, pool, metadata.last_event_id)
                .await?;

            info!(
                replayed_to_block = new_block,
                replayed_to_event_id = new_event_id,
                new_root = %format!("0x{:x}", updated_tree.root()),
                "Replay complete"
            );

            // Update metadata with new event ID
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

            updated_tree
        };

        // 7. Replace GLOBAL_TREE atomically
        {
            let mut tree_guard = GLOBAL_TREE.write().await;
            *tree_guard = final_tree;
        }

        Ok(())
    }

    /// Full rebuild from database and atomically replace GLOBAL_TREE.
    /// Used during initialization and for recovery when cache is corrupted.
    async fn full_rebuild_and_update_global_tree(&self, pool: &PgPool) -> anyhow::Result<()> {
        use crate::tree::GLOBAL_TREE;

        info!("Starting full tree rebuild with cache");

        let (tree, last_block, last_event_id) = self
            .builder
            .build_from_db_with_cache(pool, &self.cache_path)
            .await?;

        // Replace GLOBAL_TREE atomically
        {
            let mut tree_guard = GLOBAL_TREE.write().await;
            *tree_guard = tree;
        }

        // Write metadata with event ID (read from GLOBAL_TREE for consistency)
        let tree_for_metadata = GLOBAL_TREE.read().await;
        metadata::write_metadata(
            &self.cache_path,
            &tree_for_metadata,
            pool,
            last_block,
            last_event_id,
            self.tree_depth,
            self.dense_prefix_depth,
        )
        .await?;

        info!(
            root = %format!("0x{:x}", tree_for_metadata.root()),
            last_block,
            last_event_id,
            "Full rebuild and GLOBAL_TREE update complete"
        );

        Ok(())
    }

    /// Sync the in-memory GLOBAL_TREE with database events without full reconstruction.
    ///
    /// This method efficiently syncs the tree by:
    /// 1. Restoring tree from mmap (separate instance - GLOBAL_TREE continues serving requests)
    /// 2. Restoring sparse leaves from database (mmap only stores dense prefix)
    /// 3. Validating restored root matches metadata
    /// 4. Replaying only new events since last sync
    /// 5. Atomically replacing GLOBAL_TREE with the updated tree
    ///
    /// Note: Mmap restore is fast due to OS-level page cache optimization.
    /// Most pages are already in memory if the tree was recently used.
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
            events_behind, "Tree is {} events behind, syncing", events_behind
        );

        // 3. Restore tree from mmap (creates separate instance, doesn't touch GLOBAL_TREE)
        //    IMPORTANT: GLOBAL_TREE continues serving requests during this operation
        let mut tree = self.builder.restore_from_cache(&self.cache_path)?;

        // 4. Restore sparse leaves from database
        //    The mmap only stores leaves in the dense prefix. Sparse leaves must be restored from DB.
        let dense_prefix_size = 1usize << self.dense_prefix_depth;
        let sparse_leaves = fetch_sparse_leaves(pool, dense_prefix_size).await?;

        if !sparse_leaves.is_empty() {
            info!(
                sparse_count = sparse_leaves.len(),
                "Restoring {} sparse leaves from database",
                sparse_leaves.len()
            );

            for (leaf_index, commitment_str) in &sparse_leaves {
                let commitment = commitment_str
                    .parse::<U256>()
                    .map_err(|e| anyhow::anyhow!("Failed to parse commitment: {}", e))?;
                tree = tree.update_with_mutation(*leaf_index, &commitment);
            }
        }

        // 5. Verify restored root matches metadata (now including sparse leaves)
        let restored_root = format!("0x{:x}", tree.root());
        if restored_root != metadata.root_hash {
            warn!(
                expected = %metadata.root_hash,
                actual = %restored_root,
                "Root mismatch detected after sparse restore! Cache corrupted, triggering full rebuild"
            );

            // Trigger full rebuild instead of failing
            return self
                .full_rebuild_and_update_global_tree(pool)
                .await
                .map(|_| 0);
        }

        info!(
            restored_root = %restored_root,
            "Restored tree root matches metadata"
        );

        // 6. Replay events on the restored tree (GLOBAL_TREE still serves requests)
        let (updated_tree, new_block, new_event_id) = self
            .builder
            .replay_events(tree, pool, metadata.last_event_id)
            .await?;

        // 7. Replace GLOBAL_TREE atomically (one brief write lock)
        {
            let mut tree_guard = GLOBAL_TREE.write().await;
            *tree_guard = updated_tree;
        }

        // 8. Update metadata on disk
        let tree_for_metadata = GLOBAL_TREE.read().await;
        metadata::write_metadata(
            &self.cache_path,
            &tree_for_metadata,
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
            events_applied = events_behind,
            "Tree sync complete"
        );

        Ok(events_behind as u64)
    }
}
