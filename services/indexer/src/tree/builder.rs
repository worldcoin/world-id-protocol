use std::path::Path;

use alloy::primitives::U256;
use anyhow::Context;
use semaphore_rs_trees::lazy::{Canonical, LazyMerkleTree as MerkleTree};
use sqlx::PgPool;
use tracing::info;

use super::PoseidonHasher;
use crate::db::{fetch_all_leaves, fetch_events_for_replay, get_max_event_block, get_max_event_id};

pub struct TreeBuilder {
    tree_depth: usize,
    dense_prefix_depth: usize,
    empty_value: U256,
}

impl TreeBuilder {
    pub fn new(tree_depth: usize, dense_prefix_depth: usize, empty_value: U256) -> Self {
        Self {
            tree_depth,
            dense_prefix_depth,
            empty_value,
        }
    }

    /// Restore tree from mmap file (no validation)
    pub fn restore_from_cache(
        &self,
        cache_path: &Path,
    ) -> anyhow::Result<MerkleTree<PoseidonHasher, Canonical>> {
        let cache_path_str = cache_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid cache file path"))?;

        let tree = MerkleTree::<PoseidonHasher, Canonical>::attempt_dense_mmap_restore(
            self.tree_depth,
            self.dense_prefix_depth,
            &self.empty_value,
            cache_path_str,
        )
        .map_err(|e| anyhow::anyhow!("Failed to restore tree from cache: {:?}", e))?;

        info!(
            cache_file = %cache_path.display(),
            root = %format!("0x{:x}", tree.root()),
            "Restored tree from cache"
        );

        Ok(tree)
    }

    /// Build tree from DB with mmap backing
    /// Returns (tree, last_block_number, last_event_id)
    pub async fn build_from_db_with_cache(
        &self,
        pool: &PgPool,
        cache_path: &Path,
    ) -> anyhow::Result<(MerkleTree<PoseidonHasher, Canonical>, u64, i64)> {
        info!("Building tree from database with mmap cache");

        let leaves = self.process_leaves_from_db(pool).await?;

        let cache_path_str = cache_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid cache file path"))?;

        let tree = MerkleTree::<PoseidonHasher, Canonical>::new_mmapped_with_dense_prefix_with_init_values(
            self.tree_depth,
            self.dense_prefix_depth,
            &self.empty_value,
            &leaves,
            cache_path_str,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create mmap tree: {:?}", e))?;

        // Get the last block number and event ID from DB
        let last_block_number = get_max_event_block(pool).await?;
        let last_event_id = get_max_event_id(pool).await?;

        info!(
            root = %format!("0x{:x}", tree.root()),
            last_block = last_block_number,
            last_event_id,
            "Tree built from database with mmap cache"
        );

        Ok((tree, last_block_number, last_event_id))
    }

    /// Replay events onto an existing tree with deduplication
    /// Uses event ID-based pagination to efficiently handle large replays
    /// Deduplicates updates to the same leaf for optimal performance
    ///
    /// IMPORTANT: Uses event ID (not block number) as the cursor to handle reorgs correctly.
    /// Events can be inserted with older block numbers after newer ones (during reorgs),
    /// but event IDs always increase. This ensures all events are replayed.
    pub async fn replay_events(
        &self,
        mut tree: MerkleTree<PoseidonHasher, Canonical>,
        pool: &PgPool,
        from_event_id: i64,
    ) -> anyhow::Result<(MerkleTree<PoseidonHasher, Canonical>, u64, i64)> {
        use std::collections::HashMap;

        const BATCH_SIZE: i64 = 10_000;

        let mut last_event_id = from_event_id;
        let mut total_events = 0;

        // HashMap to track final state of each leaf (deduplication)
        let mut leaf_final_states: HashMap<usize, U256> = HashMap::new();
        let mut final_block = 0u64;
        let mut final_event_id = from_event_id;

        info!(
            from_event_id = from_event_id + 1,
            "Starting replay from event ID {} (events after this ID will be replayed)",
            from_event_id
        );

        loop {
            // Event ID-based pagination: fetch events with id > last_event_id
            let events = fetch_events_for_replay(pool, last_event_id, BATCH_SIZE).await?;

            if events.is_empty() {
                break;
            }

            let batch_count = events.len();
            total_events += batch_count;

            // Process events into final states (in memory, deduplicated)
            for event in &events {
                let leaf_index: U256 = event
                    .leaf_index
                    .parse()
                    .with_context(|| format!("Failed to parse leaf_index: {}", event.leaf_index))?;
                let leaf_index = leaf_index.as_limbs()[0] as usize;

                let new_value = event.new_commitment.parse::<U256>().with_context(|| {
                    format!("Failed to parse new_commitment: {}", event.new_commitment)
                })?;

                // Store final state (overwrites previous updates to same leaf)
                leaf_final_states.insert(leaf_index, new_value);

                // Track the highest block number seen (for metadata)
                if event.block_number as u64 > final_block {
                    final_block = event.block_number as u64;
                }
            }

            // Update cursor to last event ID in this batch
            let last = events.last().unwrap();
            last_event_id = last.id;
            final_event_id = last.id;

            info!(
                batch_events = batch_count,
                total_events,
                unique_leaves = leaf_final_states.len(),
                last_event_id,
                "Processed batch into memory"
            );

            // If we got fewer than BATCH_SIZE, we're at the end
            if batch_count < BATCH_SIZE as usize {
                break;
            }
        }

        if total_events == 0 {
            info!("No events to replay, cache is up-to-date");
            // Get the current max block number for metadata
            final_block = get_max_event_block(pool).await?;
            return Ok((tree, final_block, from_event_id));
        }

        // Now apply deduplicated updates to tree
        info!(
            unique_leaves = leaf_final_states.len(),
            total_events,
            "Applying {} deduplicated updates to tree (from {} total events)",
            leaf_final_states.len(),
            total_events
        );

        for (leaf_index, value) in &leaf_final_states {
            tree = tree.update_with_mutation(*leaf_index, value);
        }

        info!(
            total_events,
            unique_updates = leaf_final_states.len(),
            final_block,
            final_event_id,
            new_root = %format!("0x{:x}", tree.root()),
            "Replay complete: {} events deduplicated to {} unique leaf updates",
            total_events,
            leaf_final_states.len()
        );

        Ok((tree, final_block, final_event_id))
    }

    /// Helper: fetch and process all leaves from DB into a tree-ready format
    async fn process_leaves_from_db(&self, pool: &PgPool) -> anyhow::Result<Vec<U256>> {
        let rows = fetch_all_leaves(pool).await?;

        info!("Fetched {} accounts from database", rows.len());

        let capacity = 1usize << self.tree_depth;
        let mut leaves = vec![U256::ZERO; capacity];

        for (leaf_index_str, offchain_str) in rows {
            let leaf_index: U256 = leaf_index_str
                .parse()
                .with_context(|| format!("Failed to parse leaf_index: {}", leaf_index_str))?;

            // Skip leaf index 0 (reserved)
            if leaf_index == U256::ZERO {
                continue;
            }

            let leaf_index = leaf_index.as_limbs()[0] as usize;
            if leaf_index >= capacity {
                anyhow::bail!(
                    "leaf index {} out of range for tree depth {}",
                    leaf_index,
                    self.tree_depth
                );
            }

            let leaf_val = offchain_str.parse::<U256>().with_context(|| {
                format!(
                    "Failed to parse offchain_signer_commitment: {}",
                    offchain_str
                )
            })?;
            leaves[leaf_index] = leaf_val;
        }

        Ok(leaves)
    }
}
