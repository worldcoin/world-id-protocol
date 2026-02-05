use std::{fmt, path::PathBuf, time::Instant};

use alloy::primitives::U256;
use semaphore_rs_trees::lazy::Canonical;
use tracing::{info, warn};

use super::{
    MerkleTree, PoseidonHasher, TreeError, TreeResult, TreeState, builder::TreeBuilder, metadata,
};
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
    /// Returns a TreeState wrapping the initialized tree.
    pub async fn initialize(&self, db: &DB) -> TreeResult<TreeState> {
        let start = Instant::now();

        let cache_state = self.check_cache_files();
        info!(?cache_state, "Checking cache files");

        // If either file is missing, skip restore attempt and do full rebuild
        let tree = if cache_state.is_valid() {
            match self.try_restore_and_replay(db).await {
                Ok(tree) => {
                    info!("Successfully restored and updated tree from cache");
                    tree
                }
                Err(e) => {
                    warn!("Cache restore failed ({}), doing full rebuild", e);
                    self.full_rebuild(db).await?
                }
            }
        } else {
            info!("{}, building tree from scratch", cache_state);
            self.full_rebuild(db).await?
        };

        info!("Tree initialization took {:?}", start.elapsed());
        Ok(TreeState::new(tree, self.tree_depth))
    }

    /// Try to restore from cache and replay missed events.
    /// Returns the initialized tree.
    async fn try_restore_and_replay(
        &self,
        db: &DB,
    ) -> TreeResult<MerkleTree<PoseidonHasher, Canonical>> {
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
            return Err(TreeError::RootMismatch {
                actual: restored_root,
                expected: metadata.root_hash,
            });
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
                    WorldTreeEventId {
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

        Ok(final_tree)
    }

    /// Full rebuild from database.
    /// Returns the built tree.
    async fn full_rebuild(&self, db: &DB) -> TreeResult<MerkleTree<PoseidonHasher, Canonical>> {
        info!("Starting full tree rebuild with cache");

        let (tree, last_event_id) = self
            .builder
            .build_from_db_with_cache(db, &self.cache_path)
            .await?;

        // Write metadata
        metadata::write_metadata(
            &self.cache_path,
            &tree,
            db,
            last_event_id,
            self.tree_depth,
            self.dense_prefix_depth,
        )
        .await?;

        info!(
            root = %format!("0x{:x}", tree.root()),
            last_block_number = last_event_id.block_number,
            last_log_index = last_event_id.log_index,
            "Full rebuild complete"
        );

        Ok(tree)
    }

    /// Sync the TreeState with database events without full reconstruction.
    ///
    /// This method efficiently syncs the tree by:
    /// 1. Restoring tree from mmap (separate instance - TreeState continues serving requests)
    /// 2. Validating restored root matches metadata (fails if cache is corrupted)
    /// 3. Replaying only new events since last sync
    /// 4. Atomically replacing the tree in TreeState
    ///
    /// Note: Mmap restore is fast due to OS-level page cache optimization.
    /// Most pages are already in memory if the tree was recently used.
    ///
    /// Returns the number of blocks and logs synced.
    pub async fn sync_with_db(&self, db: &DB, tree_state: &TreeState) -> TreeResult<(u64, u64)> {
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

        // 3. Restore tree from mmap (creates separate instance, doesn't touch tree_state)
        //    IMPORTANT: tree_state continues serving requests during this operation
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
            let rebuilt_tree = self.full_rebuild(db).await?;
            tree_state.replace(rebuilt_tree).await;
            return Ok((0, 0));
        }

        info!(
            restored_root = %restored_root,
            "Restored tree root matches metadata"
        );

        // 5. Replay events on the restored tree (tree_state still serves requests)
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

        // 6. Replace tree in TreeState atomically (one brief write lock)
        tree_state.replace(updated_tree).await;

        // 7. Update metadata on disk
        let tree_guard = tree_state.read().await;
        metadata::write_metadata(
            &self.cache_path,
            &tree_guard,
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
