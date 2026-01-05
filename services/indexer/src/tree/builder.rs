use std::path::Path;

use alloy::primitives::U256;
use anyhow::Context;
use semaphore_rs_trees::lazy::{Canonical, LazyMerkleTree as MerkleTree};
use sqlx::{PgPool, Row};
use tracing::{info, warn};

use crate::PoseidonHasher;

pub struct TreeBuilder {
    tree_depth: usize,
    dense_prefix_depth: usize,
    empty_value: U256,
}

#[derive(Debug)]
struct UpdateEvent {
    leaf_index: String,
    event_type: String,
    new_commitment: String,
    block_number: i64,
    log_index: i64,
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
    pub async fn build_from_db_with_cache(
        &self,
        pool: &PgPool,
        cache_path: &Path,
    ) -> anyhow::Result<(MerkleTree<PoseidonHasher, Canonical>, u64)> {
        info!("Building tree from database with mmap cache");

        let leaves = self.fetch_leaves_from_db(pool).await?;

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

        // Get the last block number from DB
        let last_block_number = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT COALESCE(MAX(block_number), 0) FROM commitment_update_events",
        )
        .fetch_one(pool)
        .await?
        .unwrap_or(0) as u64;

        info!(
            root = %format!("0x{:x}", tree.root()),
            last_block = last_block_number,
            "Tree built from database with mmap cache"
        );

        Ok((tree, last_block_number))
    }

    /// Replay events onto an existing tree with deduplication
    /// Uses keyset pagination to efficiently handle large replays
    /// Deduplicates updates to the same leaf for optimal performance
    pub async fn replay_events(
        &self,
        mut tree: MerkleTree<PoseidonHasher, Canonical>,
        pool: &PgPool,
        from_block: u64,
    ) -> anyhow::Result<(MerkleTree<PoseidonHasher, Canonical>, u64)> {
        use std::collections::HashMap;

        const BATCH_SIZE: i64 = 10_000;

        let mut last_block = from_block as i64;
        let mut last_log_index = -1i64; // Start before any valid log_index
        let mut total_events = 0;

        // HashMap to track final state of each leaf (deduplication)
        let mut leaf_final_states: HashMap<usize, U256> = HashMap::new();
        let mut final_block = from_block;

        info!(
            from_block = from_block + 1,
            "Starting replay from block {}",
            from_block + 1
        );

        loop {
            // Keyset pagination: continue from last (block_number, log_index)
            let events = sqlx::query(
                "SELECT leaf_index, event_type, new_commitment, block_number, log_index
                 FROM commitment_update_events
                 WHERE (block_number > $1) OR (block_number = $1 AND log_index > $2)
                 ORDER BY block_number ASC, log_index ASC
                 LIMIT $3",
            )
            .bind(last_block)
            .bind(last_log_index)
            .bind(BATCH_SIZE)
            .fetch_all(pool)
            .await?;

            if events.is_empty() {
                break;
            }

            let batch_count = events.len();
            total_events += batch_count;

            // Process events into final states (in memory, deduplicated)
            for row in &events {
                let leaf_index_str: String = row.get("leaf_index");
                let event_type: String = row.get("event_type");
                let new_commitment_str: String = row.get("new_commitment");

                let leaf_index: U256 = leaf_index_str.parse().with_context(|| {
                    format!("Failed to parse leaf_index: {}", leaf_index_str)
                })?;
                let leaf_index = leaf_index.as_limbs()[0] as usize;

                let new_value = match event_type.as_str() {
                    "created" | "updated" | "inserted" | "recovered" => new_commitment_str
                        .parse::<U256>()
                        .with_context(|| {
                            format!("Failed to parse new_commitment: {}", new_commitment_str)
                        })?,
                    "removed" => U256::ZERO,
                    _ => {
                        warn!("Unknown event type: {}", event_type);
                        continue;
                    }
                };

                // Store final state (overwrites previous updates to same leaf)
                leaf_final_states.insert(leaf_index, new_value);
            }

            // Update cursor to last event in this batch
            let last = events.last().unwrap();
            last_block = last.get("block_number");
            last_log_index = last.get("log_index");
            final_block = last_block as u64;

            info!(
                batch_events = batch_count,
                total_events,
                unique_leaves = leaf_final_states.len(),
                last_block,
                "Processed batch into memory"
            );

            // If we got fewer than BATCH_SIZE, we're at the end
            if batch_count < BATCH_SIZE as usize {
                break;
            }
        }

        if total_events == 0 {
            info!("No events to replay, cache is up-to-date");
            return Ok((tree, from_block));
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
            new_root = %format!("0x{:x}", tree.root()),
            "Replay complete: {} events deduplicated to {} unique leaf updates",
            total_events,
            leaf_final_states.len()
        );

        Ok((tree, final_block))
    }

    /// Helper: fetch all leaves from DB
    async fn fetch_leaves_from_db(&self, pool: &PgPool) -> anyhow::Result<Vec<U256>> {
        let rows = sqlx::query(
            "SELECT leaf_index, offchain_signer_commitment FROM accounts ORDER BY leaf_index ASC",
        )
        .fetch_all(pool)
        .await?;

        info!("Fetched {} accounts from database", rows.len());

        let capacity = 1usize << self.tree_depth;
        let mut leaves = vec![U256::ZERO; capacity];

        for row in rows {
            let leaf_index_str: String = row.get("leaf_index");
            let offchain_str: String = row.get("offchain_signer_commitment");

            let leaf_index: U256 = leaf_index_str.parse().with_context(|| {
                format!("Failed to parse leaf_index: {}", leaf_index_str)
            })?;

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

            let leaf_val = offchain_str
                .parse::<U256>()
                .with_context(|| format!("Failed to parse offchain_signer_commitment: {}", offchain_str))?;
            leaves[leaf_index] = leaf_val;
        }

        Ok(leaves)
    }
}
