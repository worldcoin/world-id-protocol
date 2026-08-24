use std::{collections::HashMap, path::Path};

use alloy::primitives::U256;
use futures_util::TryStreamExt as _;
use semaphore_rs_storage::MmapVec;
use tracing::{info, instrument};

use super::{TreeError, TreeResult, TreeState, checkpoint};
use crate::{
    db::{DB, IsolationLevel, WorldIdRegistryEventId},
    tree::MerkleTree,
};

// =============================================================================
// Public API
// =============================================================================

/// Unified tree initialization.
///
/// If the mmap exists: validates root against DB, then replays only events after
/// the local checkpoint cursor (incremental restore) or from genesis (safe fallback).
/// If the mmap is missing or validation fails: full rebuild from DB.
///
/// Persists a fresh checkpoint on completion so the next restart can resume
/// incrementally.
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
    let (tree, last_event_id) = if cache_path.exists() {
        match try_restore(db, cache_path, tree_depth).await {
            Ok(result) => result,
            Err(e) if e.invalidates_cache() => {
                tracing::error!(?e, "cache invalid, deleting and rebuilding from database");
                if let Err(remove_err) = std::fs::remove_file(cache_path) {
                    tracing::error!(?remove_err, "failed to delete cache file");
                }
                checkpoint::delete_checkpoint(cache_path);
                build_from_db_with_cache(db, cache_path, tree_depth).await?
            }
            Err(e) => {
                tracing::error!(
                    ?e,
                    "restore failed for a reason unrelated to the cache; leaving cache on disk and propagating"
                );
                return Err(e.into());
            }
        }
    } else {
        info!("no cache file, building tree from database (full rebuild)");
        checkpoint::delete_checkpoint(cache_path);
        build_from_db_with_cache(db, cache_path, tree_depth).await?
    };

    let tree_state = TreeState::new(
        tree,
        tree_depth,
        last_event_id,
        Some(cache_path.to_path_buf()),
    );
    tree_state.persist_checkpoint(last_event_id).await;

    crate::metrics::set_tree_last_synced_block(last_event_id.block_number);
    crate::metrics::set_chain_processed_block(last_event_id.block_number);

    Ok(tree_state)
}

/// Incrementally sync the in-memory tree with events committed to DB
/// since the last sync point.
///
/// Returns the number of raw events processed (before deduplication).
#[instrument(level = "info", skip_all)]
pub async fn sync_from_db(db: &DB, tree_state: &TreeState) -> TreeResult<usize> {
    const BATCH_SIZE: u64 = 10_000;

    let started = std::time::Instant::now();
    let from = tree_state.last_synced_event_id().await;

    // Collect all pending events
    let mut all_events = Vec::new();
    let mut cursor = from;

    loop {
        let batch = db
            .world_id_registry_events()
            .get_after(cursor, BATCH_SIZE)
            .await?;

        if batch.is_empty() {
            break;
        }

        let last = batch.last().expect("batch is non-empty");
        cursor = WorldIdRegistryEventId {
            block_number: last.block_number,
            log_index: last.log_index,
        };

        let at_end = (batch.len() as u64) < BATCH_SIZE;
        all_events.extend(batch);

        if at_end {
            break;
        }
    }

    if all_events.is_empty() {
        let latency_ms = started.elapsed().as_millis() as f64;
        crate::metrics::record_tree_sync(0, latency_ms, from.block_number);
        return Ok(0);
    }

    let total = all_events.len();

    // Deduplicate: keep only the final state per leaf
    let mut leaf_final_states: HashMap<u64, U256> = HashMap::new();
    for event in &all_events {
        // Extract leaf_index and offchain_signer_commitment from event details
        if let Some((leaf_index, commitment)) = super::extract_leaf_commitment(&event.details) {
            leaf_final_states.insert(leaf_index, commitment);
        }
    }

    info!(
        total_events = total,
        unique_leaves = leaf_final_states.len(),
        "applying updates"
    );

    // Apply all under a single write lock
    {
        let mut tree = tree_state.write().await;
        for (leaf_index, value) in &leaf_final_states {
            set_arbitrary_leaf(&mut tree, *leaf_index as usize, *value);
        }
    }

    tree_state.persist_checkpoint(cursor).await;

    info!(
        total_events = total,
        unique_leaves = leaf_final_states.len(),
        ?cursor,
        "done"
    );

    let latency_ms = started.elapsed().as_millis() as f64;
    crate::metrics::record_tree_sync(total, latency_ms, cursor.block_number);

    Ok(total)
}

// =============================================================================
// Private helpers
// =============================================================================

/// Try to restore from mmap cache + replay missed events.
#[instrument(level = "info", skip_all)]
async fn try_restore(
    db: &DB,
    cache_path: &Path,
    tree_depth: usize,
) -> TreeResult<(MerkleTree, WorldIdRegistryEventId)> {
    let tree = restore_from_cache(cache_path, tree_depth)?;
    let restored_root = tree.root();

    info!(root = %format!("0x{:x}", restored_root), "loaded mmap");

    let root_exists = db
        .world_id_registry_events()
        .root_exists(&restored_root)
        .await?;

    if !root_exists {
        return Err(TreeError::StaleCache {
            root: format!("0x{:x}", restored_root),
        });
    }

    let genesis = WorldIdRegistryEventId {
        block_number: 0,
        log_index: 0,
    };

    // Use the checkpoint cursor if the recorded root matches the mmap (crash-consistency
    // guard: Poseidon root commits to the full leaf set). Any mismatch falls back to a
    // full genesis replay, which is always correct.
    let (replay_cursor, incremental) = match checkpoint::read_checkpoint(cache_path) {
        Some(cp) if cp.root == restored_root => {
            info!(cursor = ?cp.cursor(), "valid checkpoint; incremental replay from cursor");
            (cp.cursor(), true)
        }
        Some(_) => {
            info!("checkpoint root mismatch; falling back to full genesis replay");
            (genesis, false)
        }
        None => {
            info!("no checkpoint; full genesis replay");
            (genesis, false)
        }
    };

    let (tree, last_event_id, replayed_events) = replay_events(tree, db, replay_cursor).await?;

    info!(
        root = %format!("0x{:x}", tree.root()),
        ?last_event_id,
        incremental,
        replayed_events,
        "tree restore complete"
    );

    Ok((tree, last_event_id))
}

/// Restore tree from mmap file (no validation).
fn restore_from_cache(cache_path: &Path, tree_depth: usize) -> TreeResult<MerkleTree> {
    let storage = unsafe {
        MmapVec::<U256>::restore_from_path(cache_path)
            .map_err(|e| TreeError::CacheRestore(e.into()))?
    };
    let tree = MerkleTree::restore(storage, tree_depth, &U256::ZERO)
        .map_err(|e| TreeError::CacheRestore(e.into()))?;
    info!(
        cache_file = %cache_path.display(),
        root = %format!("0x{:x}", tree.root()),
        "Restored tree from cache"
    );

    Ok(tree)
}

/// Build tree from DB with mmap backing.
#[instrument(level = "info", skip_all)]
async fn build_from_db_with_cache(
    db: &DB,
    cache_path: &Path,
    tree_depth: usize,
) -> eyre::Result<(MerkleTree, WorldIdRegistryEventId)> {
    info!("building tree from database");

    let cache_path_str = cache_path.to_str().ok_or(TreeError::InvalidCacheFilePath)?;

    // RepeatableRead keeps the account snapshot and the cursor consistent —
    // a commit between the two reads would otherwise advance the cursor past
    // updates absent from `leaves` and produce an invalid tree.
    let mut tx = db.transaction(IsolationLevel::RepeatableRead).await?;

    info!("Downloading leaves from database");
    let leaves = tx
        .accounts()
        .await?
        .stream_leaf_index_and_offchain_signer_commitment()
        .try_fold(Vec::new(), |mut acc, (index, value)| async move {
            if index == acc.len() as u64 {
                acc.push(value);
            } else if index < acc.len() as u64 {
                acc[index as usize] = value;
            } else {
                acc.resize((index) as usize, U256::ZERO);
                acc.push(value);
            }
            Ok(acc)
        })
        .await?;

    let last_event_id = tx
        .world_id_registry_events()
        .await?
        .get_latest_id()
        .await?
        .unwrap_or_default();

    tx.commit().await?;

    info!(len = leaves.len(), ?last_event_id, "building tree");

    let storage = unsafe { MmapVec::<U256>::create_from_path(cache_path_str)? };
    let tree = MerkleTree::new_with_leaves(storage, tree_depth, &U256::ZERO, &leaves);

    info!(root = %format!("0x{:x}", tree.root()), ?last_event_id, "tree built");

    Ok((tree, last_event_id))
}

/// Replay events onto `tree` starting after `from_event_id`, deduplicating to the
/// last value per leaf. Returns `(updated_tree, last_event_id, total_events_seen)`.
#[instrument(level = "info", skip_all, fields(?from_event_id))]
async fn replay_events(
    mut tree: MerkleTree,
    db: &DB,
    from_event_id: WorldIdRegistryEventId,
) -> TreeResult<(MerkleTree, WorldIdRegistryEventId, usize)> {
    const BATCH_SIZE: u64 = 10_000;

    let mut last_event_id = from_event_id;
    let mut total_events = 0;
    let mut leaf_final_states: HashMap<u64, U256> = HashMap::new();

    loop {
        let events = db
            .world_id_registry_events()
            .get_after(last_event_id, BATCH_SIZE)
            .await?;

        if events.is_empty() {
            break;
        }

        let batch_count = events.len();
        total_events += batch_count;

        for event in &events {
            if let Some((leaf_index, commitment)) = super::extract_leaf_commitment(&event.details) {
                leaf_final_states.insert(leaf_index, commitment);
            }
        }

        let last = events.last().expect("last item to exist");
        last_event_id = WorldIdRegistryEventId {
            block_number: last.block_number,
            log_index: last.log_index,
        };

        if batch_count < BATCH_SIZE as usize {
            break;
        }
    }

    if total_events == 0 {
        return Ok((tree, last_event_id, 0));
    }

    for (leaf_index, value) in &leaf_final_states {
        set_arbitrary_leaf(&mut tree, *leaf_index as usize, *value);
    }

    info!(
        total_events,
        unique_updates = leaf_final_states.len(),
        ?last_event_id,
        new_root = %format!("0x{:x}", tree.root()),
        "replay complete"
    );

    Ok((tree, last_event_id, total_events))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Test 15: Cache file with no read permissions fails with CacheRestore.
    #[test]
    fn test_restore_unreadable_cache_file() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let cache_path =
                std::env::temp_dir().join(format!("test_perms_{}.mmap", uuid::Uuid::new_v4()));
            std::fs::write(&cache_path, b"some data").unwrap();
            std::fs::set_permissions(&cache_path, std::fs::Permissions::from_mode(0o000)).unwrap();

            let result = restore_from_cache(&cache_path, 6);
            assert!(
                result.is_err(),
                "restore should fail on unreadable cache file"
            );

            // Restore permissions for cleanup
            std::fs::set_permissions(&cache_path, std::fs::Permissions::from_mode(0o644)).unwrap();
            std::fs::remove_file(&cache_path).unwrap();
        }
    }
}
