use std::{collections::HashMap, path::Path};

use alloy::primitives::U256;
use semaphore_rs_trees::lazy::{Canonical, LazyMerkleTree as MerkleTree};
use tracing::info;

use super::{PoseidonHasher, TreeError, TreeResult, TreeState};
use crate::db::{DB, WorldTreeEventId, fetch_leaves_batch};

// =============================================================================
// Public API
// =============================================================================

/// Unified tree initialization.
///
/// 1. If mmap file exists → load it, validate root against DB, replay missed events
/// 2. If mmap missing or validation fails → full rebuild from DB
///
/// Returns a `TreeState` with the sync cursor set so `sync_from_db()` can pick
/// up any future events incrementally.
pub async fn init_tree(
    db: &DB,
    cache_path: &Path,
    tree_depth: usize,
    dense_prefix_depth: usize,
) -> TreeResult<TreeState> {
    let (tree, last_event_id) = if cache_path.exists() {
        match try_restore(db, cache_path, tree_depth, dense_prefix_depth).await {
            Ok(result) => result,
            Err(e) => {
                tracing::warn!(?e, "restore failed, falling back to full rebuild");
                build_from_db_with_cache(db, cache_path, tree_depth, dense_prefix_depth).await?
            }
        }
    } else {
        info!("init_tree: no cache file, building from database");
        build_from_db_with_cache(db, cache_path, tree_depth, dense_prefix_depth).await?
    };

    Ok(TreeState::new(tree, tree_depth, last_event_id))
}

/// Incrementally sync the in-memory tree with events committed to DB
/// since the last sync point.
///
/// Returns the number of raw events processed (before deduplication).
pub async fn sync_from_db(db: &DB, tree_state: &TreeState) -> TreeResult<usize> {
    const BATCH_SIZE: u64 = 10_000;

    let from = tree_state.last_synced_event_id().await;

    // Collect all pending events
    let mut all_events = Vec::new();
    let mut cursor = from;

    loop {
        let batch = db.world_tree_events().get_after(cursor, BATCH_SIZE).await?;

        if batch.is_empty() {
            break;
        }

        let last = batch.last().expect("batch is non-empty");
        cursor = last.id;

        let at_end = (batch.len() as u64) < BATCH_SIZE;
        all_events.extend(batch);

        if at_end {
            break;
        }
    }

    if all_events.is_empty() {
        return Ok(0);
    }

    let total = all_events.len();

    // Deduplicate: keep only the final state per leaf
    let mut leaf_final_states: HashMap<U256, U256> = HashMap::new();
    for event in &all_events {
        leaf_final_states.insert(event.leaf_index, event.offchain_signer_commitment);
    }

    info!(
        total_events = total,
        unique_leaves = leaf_final_states.len(),
        "sync_from_db: applying updates"
    );

    // Apply all under a single write lock
    {
        let mut tree = tree_state.write().await;
        for (leaf_index, value) in &leaf_final_states {
            let idx = leaf_index.as_limbs()[0] as usize;
            take_mut::take(&mut *tree, |t| t.update_with_mutation(idx, value));
        }
    }

    // Advance cursor
    tree_state.set_last_synced_event_id(cursor).await;

    info!(
        total_events = total,
        unique_leaves = leaf_final_states.len(),
        ?cursor,
        "sync_from_db: done"
    );

    Ok(total)
}

// =============================================================================
// Private helpers
// =============================================================================

/// Try to restore from mmap cache + replay missed events.
/// Returns the tree and last event ID on success.
async fn try_restore(
    db: &DB,
    cache_path: &Path,
    tree_depth: usize,
    dense_prefix_depth: usize,
) -> TreeResult<(MerkleTree<PoseidonHasher, Canonical>, WorldTreeEventId)> {
    // 1. Load mmap
    let tree = restore_from_cache(cache_path, tree_depth, dense_prefix_depth)?;
    let restored_root = tree.root();

    info!(
        root = %format!("0x{:x}", restored_root),
        "try_restore: loaded mmap"
    );

    // 2. Validate root exists in world_tree_roots
    let root_entry = db
        .world_tree_roots()
        .get_root_by_value(&restored_root)
        .await?
        .ok_or_else(|| TreeError::StaleCache {
            root: format!("0x{:x}", restored_root),
        })?;

    info!(
        block_number = root_entry.id.block_number,
        log_index = root_entry.id.log_index,
        "try_restore: root found in DB"
    );

    // 3. Replay events after that root's position
    let replay_cursor = WorldTreeEventId {
        block_number: root_entry.id.block_number,
        log_index: root_entry.id.log_index,
    };

    let (tree, last_event_id) = replay_events(tree, db, replay_cursor).await?;

    info!(
        root = %format!("0x{:x}", tree.root()),
        ?last_event_id,
        "try_restore: replay complete"
    );

    Ok((tree, last_event_id))
}

/// Restore tree from mmap file (no validation).
fn restore_from_cache(
    cache_path: &Path,
    tree_depth: usize,
    dense_prefix_depth: usize,
) -> TreeResult<MerkleTree<PoseidonHasher, Canonical>> {
    let cache_path_str = cache_path.to_str().ok_or(TreeError::InvalidCacheFilePath)?;

    let tree = MerkleTree::<PoseidonHasher, Canonical>::attempt_dense_mmap_restore(
        tree_depth,
        dense_prefix_depth,
        &U256::ZERO,
        cache_path_str,
    )
    .map_err(|e| TreeError::CacheRestore(Box::new(e)))?;

    info!(
        cache_file = %cache_path.display(),
        root = %format!("0x{:x}", tree.root()),
        "Restored tree from cache"
    );

    Ok(tree)
}

/// Build tree from DB with mmap backing using chunk-based processing.
///
/// Two-pass approach:
/// 1. First pass: Build dense prefix by processing leaves in chunks
/// 2. Second pass: Apply sparse leaves (beyond dense prefix) incrementally
async fn build_from_db_with_cache(
    db: &DB,
    cache_path: &Path,
    tree_depth: usize,
    dense_prefix_depth: usize,
) -> TreeResult<(MerkleTree<PoseidonHasher, Canonical>, WorldTreeEventId)> {
    info!("Building tree from database with mmap cache (chunk-based processing)");

    let cache_path_str = cache_path.to_str().ok_or(TreeError::InvalidCacheFilePath)?;

    let dense_prefix_size = 1usize << dense_prefix_depth;

    // Step 1: Build dense prefix by processing chunks
    info!("First pass: building dense prefix");
    let mut dense_leaves: Vec<U256> = vec![U256::ZERO; dense_prefix_size];
    let mut total_leaves = 0u64;
    let mut max_leaf_index = 0usize;
    let mut last_cursor = 0usize;

    loop {
        let batch = fetch_and_parse_leaves_batch(db, last_cursor, tree_depth).await?;

        if batch.is_empty() {
            break;
        }

        for (leaf_index, leaf_value) in &batch {
            total_leaves += 1;

            if *leaf_index > max_leaf_index {
                max_leaf_index = *leaf_index;
            }

            if *leaf_index < dense_prefix_size {
                dense_leaves[*leaf_index] = *leaf_value;
            }
        }

        if let Some((last_idx, _)) = batch.last() {
            last_cursor = *last_idx;
        }

        if total_leaves.is_multiple_of(500_000) {
            info!(progress = total_leaves, "Processing leaves (first pass)");
        }
    }

    info!(
        total_leaves,
        max_leaf_index, dense_prefix_size, "First pass complete"
    );

    // Step 2: Create mmap tree with dense portion
    info!(dense_leaves_len = dense_leaves.len(), "Built dense prefix vector");

    let mut tree =
        MerkleTree::<PoseidonHasher, Canonical>::new_mmapped_with_dense_prefix_with_init_values(
            tree_depth,
            dense_prefix_depth,
            &U256::ZERO,
            &dense_leaves,
            cache_path_str,
        )
        .map_err(|e| TreeError::CacheCreate(Box::new(e)))?;

    info!(
        root = %format!("0x{:x}", tree.root()),
        "Tree built from database with mmap cache"
    );

    // Step 4: Apply sparse leaves (beyond dense prefix)
    if max_leaf_index >= dense_prefix_size {
        info!("Second pass: collecting and applying sparse leaves beyond dense prefix");
        let mut sparse_updates: Vec<(usize, U256)> = Vec::new();
        let mut last_cursor = 0usize;

        loop {
            let batch = fetch_and_parse_leaves_batch(db, last_cursor, tree_depth).await?;

            if batch.is_empty() {
                break;
            }

            for (leaf_index, leaf_value) in &batch {
                if *leaf_index >= dense_prefix_size {
                    sparse_updates.push((*leaf_index, *leaf_value));
                }
            }

            if let Some((last_idx, _)) = batch.last() {
                last_cursor = *last_idx;
            }

            if sparse_updates.len().is_multiple_of(500_000) {
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

        for (i, (leaf_index, value)) in sparse_updates.iter().enumerate() {
            tree = tree.update_with_mutation(*leaf_index, value);

            if i > 0 && i % 100_000 == 0 {
                info!(
                    progress = i,
                    total = sparse_updates.len(),
                    "Applying sparse leaves"
                );
            }
        }

        info!(
            sparse_updates = sparse_updates.len(),
            "Second pass complete"
        );
    } else {
        info!("All leaves within dense prefix");
    }

    let last_event_id = db
        .world_tree_events()
        .get_latest_id()
        .await?
        .unwrap_or_default();

    info!(
        root = %format!("0x{:x}", tree.root()),
        ?last_event_id,
        total_accounts = total_leaves,
        "Tree built from database with mmap cache"
    );

    Ok((tree, last_event_id))
}

/// Replay events onto an existing tree with deduplication.
/// Uses event ID-based pagination to efficiently handle large replays.
async fn replay_events(
    mut tree: MerkleTree<PoseidonHasher, Canonical>,
    db: &DB,
    from_event_id: WorldTreeEventId,
) -> TreeResult<(MerkleTree<PoseidonHasher, Canonical>, WorldTreeEventId)> {
    const BATCH_SIZE: u64 = 10_000;

    let mut last_event_id = from_event_id;
    let mut total_events = 0;

    let mut leaf_final_states: HashMap<U256, U256> = HashMap::new();

    info!(
        from_event_id = ?from_event_id,
        "Starting replay from event ID {:?} (events after this ID will be replayed)",
        from_event_id
    );

    loop {
        let events = db
            .world_tree_events()
            .get_after(last_event_id, BATCH_SIZE)
            .await?;

        if events.is_empty() {
            break;
        }

        let batch_count = events.len();
        total_events += batch_count;

        for event in &events {
            leaf_final_states.insert(event.leaf_index, event.offchain_signer_commitment);
        }

        let last = events.last().expect("last item to exist");
        last_event_id = last.id;

        info!(
            batch_events = batch_count,
            total_events,
            unique_leaves = leaf_final_states.len(),
            ?last_event_id,
            "Processed batch into memory"
        );

        if batch_count < BATCH_SIZE as usize {
            break;
        }
    }

    if total_events == 0 {
        info!("No events to replay, cache is up-to-date");
        return Ok((tree, last_event_id));
    }

    info!(
        unique_leaves = leaf_final_states.len(),
        total_events,
        "Applying {} deduplicated updates to tree (from {} total events)",
        leaf_final_states.len(),
        total_events
    );

    for (leaf_index, value) in &leaf_final_states {
        let leaf_index = leaf_index.as_limbs()[0] as usize;
        tree = tree.update_with_mutation(leaf_index, value);
    }

    info!(
        total_events,
        unique_updates = leaf_final_states.len(),
        ?last_event_id,
        new_root = %format!("0x{:x}", tree.root()),
        "Replay complete: {} events deduplicated to {} unique leaf updates",
        total_events,
        leaf_final_states.len()
    );

    Ok((tree, last_event_id))
}

/// Fetch and parse a batch of leaves from the database.
/// Converts U256 leaf indexes to usize, skips zero indexes, validates bounds.
async fn fetch_and_parse_leaves_batch(
    db: &DB,
    last_cursor: usize,
    tree_depth: usize,
) -> TreeResult<Vec<(usize, U256)>> {
    const BATCH_SIZE: i64 = 100_000;

    let raw_batch = fetch_leaves_batch(db.pool(), &U256::from(last_cursor), BATCH_SIZE).await?;

    let mut parsed_batch = Vec::with_capacity(raw_batch.len());

    let capacity = 1usize << tree_depth;
    for (leaf_index, commitment) in raw_batch {
        if leaf_index == U256::ZERO {
            continue;
        }

        let leaf_index_usize = leaf_index.as_limbs()[0] as usize;

        if leaf_index_usize >= capacity {
            return Err(TreeError::LeafIndexOutOfRange {
                leaf_index: leaf_index_usize,
                tree_depth,
            });
        }

        parsed_batch.push((leaf_index_usize, commitment));
    }

    Ok(parsed_batch)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_based_tree_building() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let depth = 10;
        let dense_prefix = 8;
        let dense_prefix_size = 1 << dense_prefix; // 256
        let empty = U256::ZERO;

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

        let chunk_dense_vec: Vec<U256> =
            chunk_dense.iter().map(|opt| opt.unwrap_or(empty)).collect();

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

        assert_eq!(
            reference_tree.root(),
            chunk_tree.root(),
            "Chunk-based build must produce identical root"
        );
    }
}
