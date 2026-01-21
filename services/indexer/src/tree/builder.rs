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

    /// Build tree from DB with mmap backing using memory-efficient sparse allocation.
    ///
    /// Instead of allocating a full 2^depth vector (32GB for depth 30), this method:
    /// 1. Allocates a sparse vector only up to max_leaf_index
    /// 2. Splits leaves at the dense_prefix_depth boundary
    /// 3. Creates mmap with only the dense portion (2^dense_prefix_depth leaves)
    /// 4. Applies sparse remainder incrementally via update_with_mutation
    ///
    /// Returns (tree, last_block_number, last_event_id)
    pub async fn build_from_db_with_cache(
        &self,
        pool: &PgPool,
        cache_path: &Path,
    ) -> anyhow::Result<(MerkleTree<PoseidonHasher, Canonical>, u64, i64)> {
        info!("Building tree from database with mmap cache (memory-efficient)");

        let rows = fetch_all_leaves(pool).await?;
        info!("Fetched {} accounts from database", rows.len());

        let cache_path_str = cache_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid cache file path"))?;

        // Step 1: Build sparse vector only up to max_leaf_index (NOT 2^depth)
        // This is the key optimization - we only allocate what we need
        let sparse_leaves = self.build_sparse_leaves(&rows)?;
        let sparse_len = sparse_leaves.len();

        info!(
            sparse_vec_size = sparse_len,
            dense_prefix_size = 1usize << self.dense_prefix_depth,
            "Built sparse leaves vector"
        );

        // Step 2: Split at dense_prefix_depth boundary
        let dense_prefix_size = 1usize << self.dense_prefix_depth;
        let dense_count = std::cmp::min(sparse_len, dense_prefix_size);
        let (dense_leaves, sparse_remainder) = sparse_leaves.split_at(dense_count);

        // Step 3: Build dense vector for mmap creation (only 2^dense_prefix_depth items max)
        // Pad with empty values if we have fewer leaves than dense_prefix_size
        let dense_vec: Vec<U256> = if dense_count < dense_prefix_size {
            // Pad sparse leaves to fill dense prefix
            dense_leaves
                .iter()
                .map(|opt| opt.unwrap_or(self.empty_value))
                .chain(std::iter::repeat_n(self.empty_value, dense_prefix_size - dense_count))
                .collect()
        } else {
            dense_leaves
                .iter()
                .map(|opt| opt.unwrap_or(self.empty_value))
                .collect()
        };

        info!(
            dense_vec_len = dense_vec.len(),
            sparse_remainder_len = sparse_remainder.len(),
            "Split leaves into dense and sparse portions"
        );

        // Step 4: Create mmap tree with dense portion only
        let mut tree =
            MerkleTree::<PoseidonHasher, Canonical>::new_mmapped_with_dense_prefix_with_init_values(
                self.tree_depth,
                self.dense_prefix_depth,
                &self.empty_value,
                &dense_vec,
                cache_path_str,
            )
            .map_err(|e| anyhow::anyhow!("Failed to create mmap tree: {:?}", e))?;

        // Step 5: Apply sparse remainder incrementally
        if !sparse_remainder.is_empty() {
            let sparse_count = sparse_remainder.iter().filter(|opt| opt.is_some()).count();
            info!(
                total_sparse = sparse_remainder.len(),
                non_empty_sparse = sparse_count,
                "Applying sparse leaves beyond dense prefix"
            );

            let base_index = dense_prefix_size;
            for (i, opt_value) in sparse_remainder.iter().enumerate() {
                if let Some(value) = opt_value {
                    let leaf_index = base_index + i;
                    tree = tree.update_with_mutation(leaf_index, value);
                }
                // Progress logging every 100k leaves
                if i > 0 && i % 100_000 == 0 {
                    info!(
                        progress = i,
                        total = sparse_remainder.len(),
                        "Applying sparse leaves"
                    );
                }
            }
        }

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

    /// Helper: build sparse leaves vector from DB rows.
    ///
    /// Key optimization: allocates only up to max_leaf_index + 1, not 2^depth.
    /// For a tree with 1M accounts, this uses ~32MB instead of 32GB.
    fn build_sparse_leaves(&self, rows: &[(String, String)]) -> anyhow::Result<Vec<Option<U256>>> {
        if rows.is_empty() {
            return Ok(vec![]);
        }

        // Find max leaf index to determine sparse vector size
        // Rows are already sorted by leaf_index ASC from the DB query
        let max_leaf_index = self.find_max_leaf_index(rows)?;

        let capacity = 1usize << self.tree_depth;
        if max_leaf_index >= capacity {
            anyhow::bail!(
                "max leaf index {} out of range for tree depth {}",
                max_leaf_index,
                self.tree_depth
            );
        }

        // Allocate sparse vector only up to max_leaf_index (NOT 2^depth)
        let mut sparse_leaves: Vec<Option<U256>> = vec![None; max_leaf_index + 1];

        for (leaf_index_str, offchain_str) in rows {
            let leaf_index: U256 = leaf_index_str
                .parse()
                .with_context(|| format!("Failed to parse leaf_index: {}", leaf_index_str))?;

            // Skip leaf index 0 (reserved)
            if leaf_index == U256::ZERO {
                continue;
            }

            let leaf_index = leaf_index.as_limbs()[0] as usize;

            let leaf_val = offchain_str.parse::<U256>().with_context(|| {
                format!(
                    "Failed to parse offchain_signer_commitment: {}",
                    offchain_str
                )
            })?;
            sparse_leaves[leaf_index] = Some(leaf_val);
        }

        Ok(sparse_leaves)
    }

    /// Find the maximum leaf index from sorted DB rows.
    fn find_max_leaf_index(&self, rows: &[(String, String)]) -> anyhow::Result<usize> {
        // Rows are sorted ASC, so we need to find the actual max
        // (last row should have highest index, but let's be safe)
        let mut max_index: usize = 0;

        for (leaf_index_str, _) in rows {
            let leaf_index: U256 = leaf_index_str
                .parse()
                .with_context(|| format!("Failed to parse leaf_index: {}", leaf_index_str))?;

            if leaf_index == U256::ZERO {
                continue;
            }

            let idx = leaf_index.as_limbs()[0] as usize;
            if idx > max_index {
                max_index = idx;
            }
        }

        Ok(max_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_builder(tree_depth: usize, dense_prefix_depth: usize) -> TreeBuilder {
        TreeBuilder::new(tree_depth, dense_prefix_depth, U256::ZERO)
    }

    #[test]
    fn test_sparse_allocation_bounded_by_max_index_not_tree_depth() {
        // This test verifies the key memory optimization:
        // We allocate O(max_leaf_index), not O(2^tree_depth)
        let builder = create_builder(20, 16); // 2^20 = 1M leaves if fully allocated

        let rows = vec![
            ("1".to_string(), "100".to_string()),
            ("10000".to_string(), "200".to_string()), // max index = 10k
        ];

        let sparse = builder.build_sparse_leaves(&rows).unwrap();

        // Allocation should be max_index + 1, not 2^20
        assert_eq!(sparse.len(), 10_001);
        assert!(
            sparse.len() < 1 << 16,
            "Sparse vec size {} should be less than dense prefix size {}",
            sparse.len(),
            1 << 16
        );
    }

    #[test]
    fn test_sparse_leaves_empty_input() {
        let builder = create_builder(10, 8);
        let rows: Vec<(String, String)> = vec![];

        let sparse = builder.build_sparse_leaves(&rows).unwrap();

        assert!(sparse.is_empty());
    }

    #[test]
    fn test_sparse_leaves_skips_index_zero() {
        let builder = create_builder(10, 8);
        let rows = vec![
            ("0".to_string(), "999".to_string()), // Reserved, should be skipped
            ("5".to_string(), "123".to_string()),
        ];

        let sparse = builder.build_sparse_leaves(&rows).unwrap();

        assert_eq!(sparse.len(), 6); // 0..=5
        assert!(sparse[0].is_none()); // Index 0 not set
        assert_eq!(sparse[5], Some(U256::from(123)));
    }

    #[test]
    fn test_sparse_leaves_rejects_out_of_range() {
        let builder = create_builder(10, 8); // max capacity = 2^10 = 1024

        let rows = vec![("2000".to_string(), "100".to_string())]; // Out of range

        let result = builder.build_sparse_leaves(&rows);
        assert!(result.is_err());
    }

    #[test]
    fn test_sparse_build_produces_same_root_as_dense_allocation() {
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

        // REFERENCE: Dense allocation for prefix + incremental for rest
        // This is how the library is designed to be used
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

        // SPARSE METHOD: Allocate only up to max_index, split at dense boundary
        let max_idx = leaf_data.iter().map(|(i, _)| *i).max().unwrap();
        let mut sparse: Vec<Option<U256>> = vec![None; max_idx + 1];
        for (idx, val) in &leaf_data {
            sparse[*idx] = Some(*val);
        }

        let dense_count = std::cmp::min(sparse.len(), dense_prefix_size);
        let (dense_part, sparse_part) = sparse.split_at(dense_count);

        // Pad dense part to full dense_prefix_size
        let dense_vec: Vec<U256> = dense_part
            .iter()
            .map(|opt| opt.unwrap_or(empty))
            .chain(std::iter::repeat_n(empty, dense_prefix_size - dense_count))
            .collect();

        let mut sparse_tree =
            MerkleTree::<PoseidonHasher, Canonical>::new_mmapped_with_dense_prefix_with_init_values(
                depth,
                dense_prefix,
                &empty,
                &dense_vec,
                temp_dir.path().join("sparse.mmap").to_str().unwrap(),
            )
            .unwrap();

        // Apply sparse remainder incrementally
        for (i, opt) in sparse_part.iter().enumerate() {
            if let Some(val) = opt {
                sparse_tree = sparse_tree.update_with_mutation(dense_prefix_size + i, val);
            }
        }

        // THE KEY INVARIANT: roots must match
        assert_eq!(
            reference_tree.root(),
            sparse_tree.root(),
            "Sparse build must produce identical root to dense allocation"
        );
    }
}
