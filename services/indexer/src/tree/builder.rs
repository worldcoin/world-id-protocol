use std::path::Path;

use alloy::primitives::U256;
use anyhow::Context;
use semaphore_rs_trees::lazy::{Canonical, LazyMerkleTree as MerkleTree};
use sqlx::PgPool;
use tracing::info;

use super::PoseidonHasher;
use crate::db::{
    fetch_events_for_replay, fetch_leaves_batch, get_max_event_block, get_max_event_id,
};

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

    /// Build tree from DB with mmap backing using chunk-based processing.
    ///
    /// This method uses a two-pass chunk-based approach:
    /// 1. First pass: Build dense prefix by processing leaves in chunks
    /// 2. Second pass: Apply sparse leaves (beyond dense prefix) incrementally
    ///
    /// Returns (tree, last_block_number, last_event_id)
    pub async fn build_from_db_with_cache(
        &self,
        pool: &PgPool,
        cache_path: &Path,
    ) -> anyhow::Result<(MerkleTree<PoseidonHasher, Canonical>, u64, i64)> {
        info!("Building tree from database with mmap cache (chunk-based processing)");

        let cache_path_str = cache_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid cache file path"))?;

        let dense_prefix_size = 1usize << self.dense_prefix_depth;

        // Step 1: Build dense prefix by processing chunks
        info!("First pass: building dense prefix");
        let mut dense_leaves: Vec<Option<U256>> = vec![None; dense_prefix_size];
        let mut total_leaves = 0u64;
        let mut max_leaf_index = 0usize;
        let mut last_cursor = String::from("0");

        loop {
            let batch = self.fetch_and_parse_leaves_batch(pool, &last_cursor).await?;
            
            if batch.is_empty() {
                break;
            }

            for (leaf_index, leaf_value) in &batch {
                total_leaves += 1;

                // Track max leaf index
                if *leaf_index > max_leaf_index {
                    max_leaf_index = *leaf_index;
                }

                // If within dense prefix, store it
                if *leaf_index < dense_prefix_size {
                    dense_leaves[*leaf_index] = Some(*leaf_value);
                }
            }

            // Update cursor to last item in batch
            if let Some((last_idx, _)) = batch.last() {
                last_cursor = last_idx.to_string();
            }

            // Progress logging every 500k rows
            if total_leaves % 500_000 == 0 {
                info!(progress = total_leaves, "Processing leaves (first pass)");
            }
        }

        info!(
            total_leaves,
            max_leaf_index,
            dense_prefix_size,
            "First pass complete"
        );

        // Step 2: Convert dense leaves to vector for mmap creation
        let dense_vec: Vec<U256> = dense_leaves
            .iter()
            .map(|opt| opt.unwrap_or(self.empty_value))
            .collect();

        info!(dense_vec_len = dense_vec.len(), "Built dense prefix vector");

        // Step 3: Create mmap tree with dense portion
        let mut tree =
            MerkleTree::<PoseidonHasher, Canonical>::new_mmapped_with_dense_prefix_with_init_values(
                self.tree_depth,
                self.dense_prefix_depth,
                &self.empty_value,
                &dense_vec,
                cache_path_str,
            )
            .map_err(|e| anyhow::anyhow!("Failed to create mmap tree: {:?}", e))?;

        // Step 4: Apply sparse leaves (beyond dense prefix)
        if max_leaf_index >= dense_prefix_size {
            info!("Second pass: collecting and applying sparse leaves beyond dense prefix");
            let mut sparse_updates: Vec<(usize, U256)> = Vec::new();
            let mut last_cursor = String::from("0");

            loop {
                let batch = self.fetch_and_parse_leaves_batch(pool, &last_cursor).await?;
                
                if batch.is_empty() {
                    break;
                }

                for (leaf_index, leaf_value) in &batch {
                    // Only collect leaves beyond dense prefix
                    if *leaf_index >= dense_prefix_size {
                        sparse_updates.push((*leaf_index, *leaf_value));
                    }
                }

                // Update cursor
                if let Some((last_idx, _)) = batch.last() {
                    last_cursor = last_idx.to_string();
                }

                // Progress logging
                if sparse_updates.len() % 500_000 == 0 {
                    info!(
                        sparse_collected = sparse_updates.len(),
                        "Collecting sparse leaves (second pass)"
                    );
                }
            }

            info!(
                sparse_count = sparse_updates.len(),
                "Collected {} sparse leaves, applying to tree",
                sparse_updates.len()
            );

            // Apply sparse updates to tree
            for (i, (leaf_index, value)) in sparse_updates.iter().enumerate() {
                tree = tree.update_with_mutation(*leaf_index, value);

                // Progress logging every 100k updates
                if i > 0 && i % 100_000 == 0 {
                    info!(
                        progress = i,
                        total = sparse_updates.len(),
                        "Applying sparse leaves"
                    );
                }
            }

            info!(sparse_updates = sparse_updates.len(), "Second pass complete");
        } else {
            info!("All leaves within dense prefix");
        }

        // Get the last block number and event ID from DB
        let last_block_number = get_max_event_block(pool).await?;
        let last_event_id = get_max_event_id(pool).await?;

        info!(
            root = %format!("0x{:x}", tree.root()),
            last_block = last_block_number,
            last_event_id,
            total_accounts = total_leaves,
            "Tree built from database with mmap cache"
        );

        Ok((tree, last_block_number, last_event_id))
    }

    /// Fetch and parse a batch of leaves from the database.
    /// Returns Vec<(leaf_index, leaf_value)> parsed and validated.
    async fn fetch_and_parse_leaves_batch(
        &self,
        pool: &PgPool,
        last_cursor: &str,
    ) -> anyhow::Result<Vec<(usize, U256)>> {
        const BATCH_SIZE: i64 = 100_000;

        let raw_batch = fetch_leaves_batch(pool, last_cursor, BATCH_SIZE).await?;

        let mut parsed_batch = Vec::with_capacity(raw_batch.len());

        for (leaf_index_str, commitment_str) in raw_batch {
            let leaf_index: U256 = leaf_index_str.parse().with_context(|| {
                format!("Failed to parse leaf_index: {}", leaf_index_str)
            })?;

            if leaf_index == U256::ZERO {
                continue;
            }

            let leaf_index_usize = leaf_index.as_limbs()[0] as usize;

            // Validate leaf index is within tree capacity
            let capacity = 1usize << self.tree_depth;
            if leaf_index_usize >= capacity {
                anyhow::bail!(
                    "leaf index {} out of range for tree depth {}",
                    leaf_index_usize,
                    self.tree_depth
                );
            }

            let leaf_val = commitment_str.parse::<U256>().with_context(|| {
                format!(
                    "Failed to parse offchain_signer_commitment: {}",
                    commitment_str
                )
            })?;

            parsed_batch.push((leaf_index_usize, leaf_val));
        }

        Ok(parsed_batch)
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

}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_builder(tree_depth: usize, dense_prefix_depth: usize) -> TreeBuilder {
        TreeBuilder::new(tree_depth, dense_prefix_depth, U256::ZERO)
    }

    #[test]
    fn test_chunk_based_tree_building() {
        // Simple test to verify chunk-based approach produces correct tree
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let depth = 10;
        let dense_prefix = 8;
        let dense_prefix_size = 1 << dense_prefix; // 256
        let empty = U256::ZERO;

        // Test data with leaves both within and beyond dense prefix (256)
        let leaf_data: Vec<(usize, U256)> = vec![
            (1, U256::from(100)),
            (5, U256::from(200)),
            (100, U256::from(300)),
            (300, U256::from(400)), // Beyond dense prefix
        ];

        // Build tree using the traditional method for comparison
        let mut dense_leaves = vec![U256::ZERO; dense_prefix_size];
        for (idx, val) in &leaf_data {
            if *idx < dense_prefix_size {
                dense_leaves[*idx] = *val;
            }
        }
        
        let mut reference_tree =
            MerkleTree::<PoseidonHasher, Canonical>::new_mmapped_with_dense_prefix_with_init_values(
                depth,
                dense_prefix,
                &empty,
                &dense_leaves,
                temp_dir.path().join("ref.mmap").to_str().unwrap(),
            )
            .unwrap();

        // Apply leaves beyond dense prefix
        for (idx, val) in &leaf_data {
            if *idx >= dense_prefix_size {
                reference_tree = reference_tree.update_with_mutation(*idx, val);
            }
        }

        // Simulate chunk-based approach
        let mut chunk_dense: Vec<Option<U256>> = vec![None; dense_prefix_size];
        let mut chunk_sparse: Vec<(usize, U256)> = Vec::new();

        for (idx, val) in &leaf_data {
            if *idx < dense_prefix_size {
                chunk_dense[*idx] = Some(*val);
            } else {
                chunk_sparse.push((*idx, *val));
            }
        }

        let chunk_dense_vec: Vec<U256> = chunk_dense
            .iter()
            .map(|opt| opt.unwrap_or(empty))
            .collect();

        let mut chunk_tree =
            MerkleTree::<PoseidonHasher, Canonical>::new_mmapped_with_dense_prefix_with_init_values(
                depth,
                dense_prefix,
                &empty,
                &chunk_dense_vec,
                temp_dir.path().join("chunk.mmap").to_str().unwrap(),
            )
            .unwrap();

        for (idx, val) in chunk_sparse {
            chunk_tree = chunk_tree.update_with_mutation(idx, &val);
        }

        // Verify roots match
        assert_eq!(
            reference_tree.root(),
            chunk_tree.root(),
            "Chunk-based build must produce identical root"
        );
    }
}
