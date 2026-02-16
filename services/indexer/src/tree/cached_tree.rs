use std::{collections::HashMap, path::Path};

use alloy::primitives::U256;
use futures_util::TryStreamExt as _;
use semaphore_rs_storage::MmapVec;
use tracing::{info, instrument};

use super::{TreeError, TreeResult, TreeState};
use crate::{
    db::{DB, WorldTreeEventId},
    tree::MerkleTree,
};

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
            Err(e) => {
                tracing::error!(?e, "restore failed, deleting cache file");
                if let Err(remove_err) = std::fs::remove_file(cache_path) {
                    tracing::error!(?remove_err, "failed to delete cache file");
                }
                return Err(e);
            }
        }
    } else {
        info!("no cache file, building from database");
        build_from_db_with_cache(db, cache_path, tree_depth).await?
    };

    Ok(TreeState::new(tree, tree_depth, last_event_id))
}

/// Incrementally sync the in-memory tree with events committed to DB
/// since the last sync point.
///
/// Returns the number of raw events processed (before deduplication).
#[instrument(level = "info", skip_all)]
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
    let mut leaf_final_states: HashMap<u64, U256> = HashMap::new();
    for event in &all_events {
        leaf_final_states.insert(event.leaf_index, event.offchain_signer_commitment);
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

    // Advance cursor
    tree_state.set_last_synced_event_id(cursor).await;

    info!(
        total_events = total,
        unique_leaves = leaf_final_states.len(),
        ?cursor,
        "done"
    );

    Ok(total)
}

// =============================================================================
// Private helpers
// =============================================================================

/// Try to restore from mmap cache + replay missed events.
/// Returns the tree and last event ID on success.
#[instrument(level = "info", skip_all)]
async fn try_restore(
    db: &DB,
    cache_path: &Path,
    tree_depth: usize,
) -> eyre::Result<(MerkleTree, WorldTreeEventId)> {
    // 1. Load mmap
    let tree = restore_from_cache(cache_path, tree_depth)?;
    let restored_root = tree.root();

    info!(
        root = %format!("0x{:x}", restored_root),
        "loaded mmap"
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
        "root found in DB"
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
        "replay complete"
    );

    Ok((tree, last_event_id))
}

/// Restore tree from mmap file (no validation).
fn restore_from_cache(cache_path: &Path, tree_depth: usize) -> eyre::Result<MerkleTree> {
    let storage = unsafe { MmapVec::<U256>::restore_from_path(cache_path)? };
    let tree = MerkleTree::new(storage, tree_depth, &U256::ZERO);
    info!(
        cache_file = %cache_path.display(),
        root = %format!("0x{:x}", tree.root()),
        "Restored tree from cache"
    );

    Ok(tree)
}

/// Build tree from DB with mmap backing using chunk-based processing.
#[instrument(level = "info", skip_all)]
async fn build_from_db_with_cache(
    db: &DB,
    cache_path: &Path,
    tree_depth: usize,
) -> eyre::Result<(MerkleTree, WorldTreeEventId)> {
    info!("Building tree from database with mmap cache (chunk-based processing)");

    let cache_path_str = cache_path.to_str().ok_or(TreeError::InvalidCacheFilePath)?;

    info!("Downloading leaves from database");
    let leaves = db
        .accounts()
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

    info!(len = leaves.len(), "Building Tree");

    let storage = unsafe { MmapVec::<U256>::create_from_path(cache_path_str)? };

    let tree = MerkleTree::new_with_leaves(storage, tree_depth, &U256::ZERO, &leaves);

    info!(
        root = %format!("0x{:x}", tree.root()),
        "Tree built from database with mmap cache"
    );

    let last_event_id = db
        .world_tree_events()
        .get_latest_id()
        .await?
        .unwrap_or_default();

    Ok((tree, last_event_id))
}

/// Replay events onto an existing tree with deduplication.
/// Uses event ID-based pagination to efficiently handle large replays.
#[instrument(level = "info", skip_all, fields(?from_event_id))]
async fn replay_events(
    mut tree: MerkleTree,
    db: &DB,
    from_event_id: WorldTreeEventId,
) -> TreeResult<(MerkleTree, WorldTreeEventId)> {
    const BATCH_SIZE: u64 = 10_000;

    let mut last_event_id = from_event_id;
    let mut total_events = 0;

    let mut leaf_final_states: HashMap<u64, U256> = HashMap::new();

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
        set_arbitrary_leaf(&mut tree, *leaf_index as usize, *value);
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
