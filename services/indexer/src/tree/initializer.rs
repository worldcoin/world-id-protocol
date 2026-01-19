use std::path::PathBuf;
use std::time::Instant;

use alloy::primitives::U256;
use semaphore_rs_trees::lazy::{Canonical, LazyMerkleTree as MerkleTree};
use sqlx::PgPool;
use tracing::{info, warn};

use super::PoseidonHasher;

use super::{builder::TreeBuilder, metadata};

pub struct TreeInitializer {
    builder: TreeBuilder,
    cache_path: PathBuf,
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
        }
    }

    /// Initialize tree: try restore + replay, fallback to full rebuild
    pub async fn initialize(
        &self,
        pool: &PgPool,
    ) -> anyhow::Result<MerkleTree<PoseidonHasher, Canonical>> {
        let start = Instant::now();

        // Try to use cached tree with replay
        let tree = match self.try_restore_and_replay(pool).await {
            Ok(tree) => {
                info!("Successfully restored and updated tree from cache");
                tree
            }
            Err(e) => {
                warn!("Cache restore failed ({}), doing full rebuild", e);
                self.full_rebuild_with_cache(pool).await?
            }
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
            cache_root = %metadata.root_hash,
            "Found cache metadata"
        );

        // 2. Get current DB state
        let db_state = metadata::get_db_state(pool).await?;
        let blocks_behind = db_state
            .max_block_number
            .saturating_sub(metadata.last_block_number);

        info!(
            current_block = db_state.max_block_number,
            blocks_behind, "Cache is {} blocks behind", blocks_behind
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

        // 5. Replay events if needed
        if blocks_behind == 0 {
            info!("Cache is up-to-date, no replay needed");
            return Ok(tree);
        }

        let (updated_tree, new_block) = self
            .builder
            .replay_events(tree, pool, metadata.last_block_number)
            .await?;

        // 6. Update metadata
        metadata::write_metadata(&self.cache_path, &updated_tree, pool, new_block).await?;

        info!(
            replayed_to_block = new_block,
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

        let (tree, last_block) = self
            .builder
            .build_from_db_with_cache(pool, &self.cache_path)
            .await?;

        // Write metadata
        metadata::write_metadata(&self.cache_path, &tree, pool, last_block).await?;

        info!(
            root = %format!("0x{:x}", tree.root()),
            last_block,
            "Full rebuild complete"
        );

        Ok(tree)
    }
}
