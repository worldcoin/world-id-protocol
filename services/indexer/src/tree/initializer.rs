use std::{fmt, path::PathBuf, time::Instant};

use alloy::primitives::U256;
use tracing::{info, warn};

use super::{builder::TreeBuilder, metadata};
use crate::db::{DB, WorldTreeEventId};

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
    pub async fn initialize(&self, db: &DB) -> anyhow::Result<()> {
        let start = Instant::now();

        let cache_state = self.check_cache_files();
        info!(?cache_state, "Checking cache files");

        // If either file is missing, skip restore attempt and do full rebuild
        if cache_state.is_valid() {
            match self.try_restore_and_replay(db).await {
                Ok(()) => {
                    info!("Successfully restored and updated tree from cache");
                }
                Err(e) => {
                    warn!("Cache restore failed ({}), doing full rebuild", e);
                    self.full_rebuild_and_update_global_tree(db).await?;
                }
            }
        } else {
            info!("{}, building tree from scratch", cache_state);
            self.full_rebuild_and_update_global_tree(db).await?;
        };

        info!("Tree initialization took {:?}", start.elapsed());
        Ok(())
    }

    /// Try to restore from cache and replay missed events.
    /// Updates GLOBAL_TREE atomically.
    async fn try_restore_and_replay(&self, db: &DB) -> anyhow::Result<()> {
        use crate::tree::GLOBAL_TREE;

        // 1. Read metadata
        let metadata = metadata::read_metadata(&self.cache_path)?;

        info!(
            cache_block_number = metadata.last_block_number,
            cache_log_index = metadata.last_log_index,
            cache_root = %metadata.root_hash,
            "Found cache metadata"
        );

        // 2. Get current DB state
        let db_state = metadata::get_db_state(db).await?;

        let last_event_id = db_state.last_event_id.unwrap_or_default();

        let blocks_behind = last_event_id
            .block_number
            .saturating_sub(metadata.last_block_number);

        let logs_behind = last_event_id
            .log_index
            .saturating_sub(metadata.last_log_index);

        info!(
            current_block_number = last_event_id.block_number,
            current_log_index = last_event_id.log_index,
            blocks_behind,
            logs_behind,
            "Cache is {} blocks / {} logsbehind",
            blocks_behind,
            logs_behind
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
        let final_tree = if metadata.last_block_number == last_event_id.block_number
            && metadata.last_log_index == last_event_id.log_index
        {
            info!("Cache is up-to-date, no replay needed");
            tree
        } else {
            // Use event ID as the replay cursor (not block number)
            let (updated_tree, new_event_id) = self
                .builder
                .replay_events(
                    tree,
                    db,
                    crate::db::WorldTreeEventId {
                        block_number: metadata.last_block_number,
                        log_index: metadata.last_log_index,
                    },
                )
                .await?;

            info!(
                replayed_to_block_number = new_event_id.block_number,
                replayed_to_log_index = new_event_id.log_index,
                new_root = %format!("0x{:x}", updated_tree.root()),
                "Replay complete"
            );

            // Update metadata with new event ID
            metadata::write_metadata(
                &self.cache_path,
                &updated_tree,
                db,
                new_event_id,
                self.tree_depth,
                self.dense_prefix_depth,
            )
            .await?;

            updated_tree
        };

        // 6. Replace GLOBAL_TREE atomically
        {
            let mut tree_guard = GLOBAL_TREE.write().await;
            *tree_guard = final_tree;
        }

        Ok(())
    }

    /// Full rebuild from database and atomically replace GLOBAL_TREE.
    /// Used during initialization and for recovery when cache is corrupted.
    async fn full_rebuild_and_update_global_tree(&self, db: &DB) -> anyhow::Result<()> {
        use crate::tree::GLOBAL_TREE;

        info!("Starting full tree rebuild with cache");

        let (tree, last_event_id) = self
            .builder
            .build_from_db_with_cache(db, &self.cache_path)
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
            db,
            last_event_id,
            self.tree_depth,
            self.dense_prefix_depth,
        )
        .await?;

        info!(
            root = %format!("0x{:x}", tree_for_metadata.root()),
            last_block_number = last_event_id.block_number,
            last_log_index = last_event_id.log_index,
            "Full rebuild and GLOBAL_TREE update complete"
        );

        Ok(())
    }

    /// Sync the in-memory GLOBAL_TREE with database events without full reconstruction.
    ///
    /// This method efficiently syncs the tree by:
    /// 1. Restoring tree from mmap (separate instance - GLOBAL_TREE continues serving requests)
    /// 2. Validating restored root matches metadata (fails if cache is corrupted)
    /// 3. Replaying only new events since last sync
    /// 4. Atomically replacing GLOBAL_TREE with the updated tree
    ///
    /// Note: Mmap restore is fast due to OS-level page cache optimization.
    /// Most pages are already in memory if the tree was recently used.
    ///
    /// Returns the number of events applied to the tree.
    pub async fn sync_with_db(&self, db: &DB) -> anyhow::Result<(u64, u64)> {
        use crate::tree::GLOBAL_TREE;

        // 1. Read current metadata to get last_event_id
        let metadata = metadata::read_metadata(&self.cache_path)?;

        info!(
            cache_block_number = metadata.last_block_number,
            cache_log_index = metadata.last_log_index,
            "Starting tree sync from cache metadata"
        );

        // 2. Check if there are new events
        let db_state = metadata::get_db_state(db).await?;

        let last_event_id = db_state.last_event_id.unwrap_or_default();

        if metadata.last_block_number == last_event_id.block_number
            && metadata.last_log_index == last_event_id.log_index
        {
            info!("Tree is up-to-date, no sync needed");
            return Ok((0, 0));
        }

        let blocks_behind = last_event_id
            .block_number
            .saturating_sub(metadata.last_block_number);

        let logs_behind = last_event_id
            .log_index
            .saturating_sub(metadata.last_log_index);

        info!(
            ?last_event_id,
            blocks_behind, "Tree is {} blocks behind, syncing", blocks_behind
        );

        // 3. Restore tree from mmap (creates separate instance, doesn't touch GLOBAL_TREE)
        //    IMPORTANT: GLOBAL_TREE continues serving requests during this operation
        let tree = self.builder.restore_from_cache(&self.cache_path)?;

        // 4. Verify restored root matches metadata
        let restored_root = format!("0x{:x}", tree.root());
        if restored_root != metadata.root_hash {
            warn!(
                expected = %metadata.root_hash,
                actual = %restored_root,
                "Root mismatch detected! Cache corrupted, triggering full rebuild"
            );

            // Trigger full rebuild instead of failing
            return self
                .full_rebuild_and_update_global_tree(db)
                .await
                .map(|_| (0, 0));
        }

        info!(
            restored_root = %restored_root,
            "Restored tree root matches metadata"
        );

        // 5. Replay events on the restored tree (GLOBAL_TREE still serves requests)
        let (updated_tree, new_event_id) = self
            .builder
            .replay_events(
                tree,
                db,
                WorldTreeEventId {
                    block_number: metadata.last_block_number,
                    log_index: metadata.last_log_index,
                },
            )
            .await?;

        // 6. Replace GLOBAL_TREE atomically (one brief write lock)
        {
            let mut tree_guard = GLOBAL_TREE.write().await;
            *tree_guard = updated_tree;
        }

        // 7. Update metadata on disk
        let tree_for_metadata = GLOBAL_TREE.read().await;
        metadata::write_metadata(
            &self.cache_path,
            &tree_for_metadata,
            db,
            new_event_id,
            self.tree_depth,
            self.dense_prefix_depth,
        )
        .await?;

        info!(
            synced_to_block_number = new_event_id.block_number,
            synced_to_log_index = new_event_id.log_index,
            blocks_applied = blocks_behind,
            "Tree sync complete"
        );

        Ok((blocks_behind as u64, logs_behind as u64))
    }
}
