use std::{collections::HashMap, path::Path};

use alloy::primitives::U256;
use semaphore_rs_storage::MmapVec;
use tracing::{info, instrument};

use super::{TreeError, TreeResult, TreeState};
use crate::{
    db::{DB, IsolationLevel, RootVerification, SyncLogEntry, SyncLogKind, WorldIdRegistryEventId},
    tree::MerkleTree,
};

// =============================================================================
// Public API
// =============================================================================

/// Unified tree initialization.
///
/// Builds a fresh mmap-backed tree from the reader-facing `sync_log` snapshot.
/// Existing cache files are discarded so stale leaves from pre-rollback cache
/// state cannot survive if they no longer appear in the latest sync projection.
///
/// Returns a `TreeState` with the sync-log cursor set so `sync_from_db()` can
/// pick up future entries incrementally.
///
/// # Safety
///
/// This function is marked unsafe because it performs memory-mapped file operations for the tree cache.
/// The caller must ensure that the cache file is not concurrently accessed or modified
/// by other processes while the tree is using it.
#[instrument(level = "info", skip_all, fields(tree_depth))]
pub async unsafe fn init_tree(
    db: &DB,
    cache_path: &Path,
    tree_depth: usize,
) -> eyre::Result<TreeState> {
    let (tree, last_event_id, last_sync_id) =
        build_from_sync_log_with_cache(db, cache_path, tree_depth).await?;

    let tree_state = TreeState::new_with_sync_id(tree, tree_depth, last_event_id, last_sync_id);
    crate::metrics::set_tree_last_synced_block(last_event_id.block_number);
    crate::metrics::set_chain_processed_block(last_event_id.block_number);

    Ok(tree_state)
}

/// Incrementally sync the in-memory tree with sync_log entries committed to DB
/// since the last sync point. Rows are applied only at root verification
/// checkpoints, so the cursor advances after the resulting root is validated.
///
/// Returns the number of sync_log rows processed through verified checkpoints.
#[instrument(level = "info", skip_all)]
pub async fn sync_from_db(db: &DB, tree_state: &TreeState) -> TreeResult<usize> {
    const BATCH_SIZE: u64 = 10_000;

    let started = std::time::Instant::now();
    let from = tree_state.last_sync_id().await;
    let mut cursor = from;
    let mut pending_leaves: HashMap<u64, (u64, Option<U256>)> = HashMap::new();
    let mut pending_count = 0usize;
    let mut processed_count = 0usize;
    let mut last_verified_sync_id = from;

    loop {
        let batch = db.sync_log().get_after(cursor, BATCH_SIZE).await?;

        if batch.is_empty() {
            break;
        }

        let at_end = (batch.len() as u64) < BATCH_SIZE;
        for entry in batch {
            cursor = entry.sync_id;
            match entry.kind {
                SyncLogKind::LeafUpdate | SyncLogKind::RollbackLeaf => {
                    let leaf_index = entry.leaf_index.ok_or_else(|| {
                        TreeError::InvalidSyncLogRow(
                            "leaf sync row is missing leaf_index".to_string(),
                        )
                    })?;
                    pending_leaves.insert(leaf_index, (entry.sync_id, entry.commitment));
                    pending_count += 1;
                }
                SyncLogKind::RootVerification => {
                    apply_checkpoint(tree_state, &mut pending_leaves, &entry).await?;
                    tree_state.set_last_sync_id(entry.sync_id).await;
                    last_verified_sync_id = entry.sync_id;
                    processed_count += pending_count + 1;
                    pending_count = 0;
                }
            }
        }

        if at_end {
            break;
        }
    }

    let latency_ms = started.elapsed().as_millis() as f64;
    if processed_count == 0 {
        crate::metrics::record_tree_sync(0, latency_ms, 0);
        return Ok(0);
    }

    info!(
        processed_count,
        last_verified_sync_id, "synced tree from sync_log"
    );

    crate::metrics::record_tree_sync(processed_count, latency_ms, 0);

    Ok(processed_count)
}

// =============================================================================
// Private helpers
// =============================================================================

struct SyncLogSnapshot {
    max_sync_id: u64,
    checkpoint: Option<RootVerification>,
    leaves: Vec<(u64, Option<U256>)>,
    last_event_id: WorldIdRegistryEventId,
}

/// Build tree from the sync_log projection with mmap backing.
#[instrument(level = "info", skip_all)]
async fn build_from_sync_log_with_cache(
    db: &DB,
    cache_path: &Path,
    tree_depth: usize,
) -> eyre::Result<(MerkleTree, WorldIdRegistryEventId, u64)> {
    info!("Building tree from sync_log with mmap cache");

    let cache_path_str = cache_path.to_str().ok_or(TreeError::InvalidCacheFilePath)?;
    if cache_path.exists() {
        std::fs::remove_file(cache_path)?;
    }

    let snapshot = load_sync_log_snapshot(db).await?;
    let next_leaf_index = snapshot
        .checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.next_leaf_index)
        .unwrap_or_else(|| {
            snapshot
                .leaves
                .iter()
                .map(|(leaf_index, _)| leaf_index + 1)
                .max()
                .unwrap_or(0)
        });

    ensure_leaf_index_in_range(next_leaf_index, tree_depth)?;
    let mut leaves = vec![U256::ZERO; next_leaf_index as usize];
    for (leaf_index, maybe_commitment) in &snapshot.leaves {
        ensure_leaf_index_in_range(leaf_index + 1, tree_depth)?;
        if (*leaf_index as usize) < leaves.len() {
            leaves[*leaf_index as usize] = maybe_commitment.unwrap_or(U256::ZERO);
        }
    }

    info!(
        len = leaves.len(),
        max_sync_id = snapshot.max_sync_id,
        "Building Tree"
    );

    let storage = unsafe { MmapVec::<U256>::create_from_path(cache_path_str)? };
    let tree = MerkleTree::new_with_leaves(storage, tree_depth, &U256::ZERO, &leaves);

    if let Some(checkpoint) = &snapshot.checkpoint {
        verify_root(tree.root(), checkpoint.expected_root)?;
    }

    info!(
        root = %format!("0x{:x}", tree.root()),
        "Tree built from sync_log with mmap cache"
    );

    Ok((tree, snapshot.last_event_id, snapshot.max_sync_id))
}

async fn load_sync_log_snapshot(db: &DB) -> TreeResult<SyncLogSnapshot> {
    let mut tx = db.transaction(IsolationLevel::RepeatableRead).await?;
    let max_sync_id = tx.sync_log().await?.get_max_sync_id().await?;
    let checkpoint = tx
        .sync_log()
        .await?
        .get_latest_root_verification_at(max_sync_id)
        .await?;
    let leaves = tx
        .sync_log()
        .await?
        .get_latest_leaf_values_at(max_sync_id)
        .await?;
    let last_event_id = tx
        .world_id_registry_events()
        .await?
        .get_latest_id()
        .await?
        .unwrap_or_default();
    tx.commit().await?;

    Ok(SyncLogSnapshot {
        max_sync_id,
        checkpoint,
        leaves,
        last_event_id,
    })
}

async fn apply_checkpoint(
    tree_state: &TreeState,
    pending_leaves: &mut HashMap<u64, (u64, Option<U256>)>,
    checkpoint: &SyncLogEntry,
) -> TreeResult<()> {
    let expected_root = checkpoint.expected_root.ok_or_else(|| {
        TreeError::InvalidSyncLogRow("root verification row is missing expected_root".to_string())
    })?;
    let next_leaf_index = checkpoint.next_leaf_index.ok_or_else(|| {
        TreeError::InvalidSyncLogRow("root verification row is missing next_leaf_index".to_string())
    })?;

    ensure_leaf_index_in_range(next_leaf_index, tree_state.depth())?;

    let mut tree = tree_state.write().await;
    for (&leaf_index, (_, maybe_commitment)) in pending_leaves.iter() {
        ensure_leaf_index_in_range(leaf_index + 1, tree_state.depth())?;
        set_arbitrary_leaf(
            &mut tree,
            leaf_index as usize,
            maybe_commitment.unwrap_or(U256::ZERO),
        );
    }

    if next_leaf_index > 0 && tree.num_leaves() < next_leaf_index as usize {
        set_arbitrary_leaf(&mut tree, next_leaf_index as usize - 1, U256::ZERO);
    }

    verify_root(tree.root(), expected_root)?;
    pending_leaves.clear();

    Ok(())
}

fn ensure_leaf_index_in_range(next_leaf_index: u64, tree_depth: usize) -> TreeResult<()> {
    let capacity = 1u64 << tree_depth;
    if next_leaf_index > capacity {
        return Err(TreeError::LeafIndexOutOfRange {
            leaf_index: next_leaf_index as usize,
            tree_depth,
        });
    }
    Ok(())
}

fn verify_root(actual: U256, expected: U256) -> TreeResult<()> {
    if actual != expected {
        return Err(TreeError::RootMismatch {
            actual: format!("0x{:x}", actual),
            expected: format!("0x{:x}", expected),
        });
    }
    Ok(())
}

/// Set a leaf value at the given index, extending the tree if necessary.
pub(crate) fn set_arbitrary_leaf(tree: &mut MerkleTree, leaf_index: usize, value: U256) {
    let num_leaves = tree.num_leaves();
    if leaf_index >= num_leaves {
        let num_zeros = leaf_index - num_leaves;
        let mut new = Vec::with_capacity(num_zeros + 1);
        new.resize(num_zeros, U256::ZERO);
        new.push(value);
        tree.extend_from_slice(&new);
    } else {
        tree.set_leaf(leaf_index, value);
    }
}
