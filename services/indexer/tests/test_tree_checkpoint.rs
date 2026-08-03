//! Tests for the local per-instance tree checkpoint (watermark) restore path.
//!
//! These assert the behavior of the incremental-restore optimization via
//! *observable* effects only (tree roots and the on-disk checkpoint sidecar) — no
//! internal stats/return-type surface is used:
//!   - incremental restore produces an IDENTICAL tree to a full rebuild (the
//!     critical correctness property for a ZK/identity Merkle tree);
//!   - restore actually resumes from the checkpoint cursor rather than replaying
//!     from genesis (probed by inserting a pre-cursor event that a genesis replay
//!     would pick up but an incremental restore must ignore);
//!   - the checkpoint sidecar is written on init and advances across restarts;
//!   - a missing / corrupted / mismatched checkpoint safely falls back to the full
//!     replay (never a crash, never a silently-wrong tree) and is rewritten;
//!   - invalidating the checkpoint (as the reorg/rollback path does) removes the
//!     sidecar and the next boot still restores correctly;
//!   - a stale mmap whose root is not in the DB (e.g. empty fresh deployment)
//!     falls back to a full rebuild rather than propagating the error;
//!   - the checkpoint written by `sync_from_db` (not `init_tree`) is the one used
//!     on the next restart, so events applied during a sync cycle are not replayed;
//!   - after a fallback rebuild the resulting checkpoint enables incremental restore
//!     on the subsequent restart (fix 1 and fix 2 compose correctly);
//!   - two independent "instances" (separate cache + checkpoint file pairs) restore
//!     independently and correctly using only their own local checkpoint.

#![cfg(feature = "integration-tests")]

mod helpers;

use std::{fs, path::PathBuf};

use alloy::primitives::{Address, U256};
use helpers::db_helpers::{
    create_unique_test_db, insert_test_account, insert_test_world_tree_event,
    insert_test_world_tree_root,
};
use world_id_indexer::{
    blockchain::{AccountCreatedEvent, BlockchainEvent, RegistryEvent},
    db::DB,
    tree::{
        TreeState, apply_event_to_tree,
        cached_tree::{init_tree, sync_from_db},
        checkpoint,
    },
};

const DEPTH: usize = 6;

fn temp_cache_path() -> PathBuf {
    std::env::temp_dir().join(format!("test_ckpt_{}.mmap", uuid::Uuid::new_v4()))
}

fn cleanup(path: &PathBuf) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(checkpoint::checkpoint_path(path));
}

/// Build an `AccountCreated` event for `leaf_index` with the given commitment at
/// `(block_number, log_index)`.
fn account_created(
    block_number: u64,
    log_index: u64,
    leaf_index: u64,
    commitment: u64,
) -> BlockchainEvent<RegistryEvent> {
    BlockchainEvent {
        block_number,
        block_hash: U256::from(1_000_000 + block_number),
        tx_hash: U256::from(block_number * 100 + log_index),
        log_index,
        details: RegistryEvent::AccountCreated(AccountCreatedEvent {
            leaf_index,
            recovery_address: Address::ZERO,
            authenticator_addresses: vec![],
            authenticator_pubkeys: vec![],
            offchain_signer_commitment: U256::from(commitment),
        }),
    }
}

/// Compute the tree root at `DEPTH` after applying `events`, matching what the
/// indexer's tree would produce. Uses a throwaway in-memory tree (no checkpoint).
async fn root_after_events(events: &[BlockchainEvent<RegistryEvent>]) -> U256 {
    let path = temp_cache_path();
    let state = unsafe { TreeState::new_empty(DEPTH, &path) }.unwrap();
    for e in events {
        apply_event_to_tree(&state, e).await.unwrap();
    }
    let root = state.root().await;
    drop(state);
    cleanup(&path);
    root
}

/// Seed the DB with `AccountCreated` events for the given `(leaf_index, commitment)`
/// pairs at consecutive blocks starting at `first_block` (log_index 0), plus matching
/// `accounts` rows. Returns `(events, next_block)`.
async fn seed_stage(
    db: &DB,
    leaves: &[(u64, u64)],
    first_block: u64,
) -> (Vec<BlockchainEvent<RegistryEvent>>, u64) {
    let mut events = Vec::new();
    let mut block = first_block;
    for (leaf_index, commitment) in leaves {
        let ev = account_created(block, 0, *leaf_index, *commitment);
        insert_test_account(db, *leaf_index, Address::ZERO, U256::from(*commitment))
            .await
            .unwrap();
        insert_test_world_tree_event(db, &ev).await.unwrap();
        events.push(ev);
        block += 1;
    }
    (events, block)
}

// ============================================================================
// 1. Checkpoint is written on init and advances across restarts; restore is
//    correct.
// ============================================================================

#[tokio::test]
async fn test_checkpoint_written_and_advanced_on_restart() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    // Stage 1: 5 accounts (blocks 10..14) + RootRecorded at block 15.
    let stage1 = [(1u64, 101u64), (2, 102), (3, 103), (4, 104), (5, 105)];
    let (mut all_events, next_block) = seed_stage(db, &stage1, 10).await;
    let r5 = root_after_events(&all_events).await;
    insert_test_world_tree_root(db, next_block, 0, r5, U256::ZERO)
        .await
        .unwrap();

    // First init: no cache ⇒ full build from accounts, writes a checkpoint at the
    // latest event id (the RootRecorded at block 15).
    let ts1 = unsafe { init_tree(db, &cache_path, DEPTH).await.unwrap() };
    assert_eq!(ts1.root().await, r5, "built root must match expected");
    drop(ts1);

    let cp1 = checkpoint::read_checkpoint(&cache_path).expect("checkpoint written after init");
    assert_eq!(cp1.root_u256(), Some(r5));
    assert_eq!(
        cp1.cursor().block_number,
        next_block,
        "cursor at latest event"
    );

    // Stage 2 delta: 2 more accounts (blocks 16,17) + RootRecorded at block 18.
    let stage2 = [(6u64, 106u64), (7, 107)];
    let (delta_events, next_block2) = seed_stage(db, &stage2, 16).await;
    all_events.extend(delta_events);
    let r7 = root_after_events(&all_events).await;
    insert_test_world_tree_root(db, next_block2, 0, r7, U256::ZERO)
        .await
        .unwrap();

    // Second init: cache + valid checkpoint ⇒ incremental restore reaches r7 and
    // advances the checkpoint.
    let ts2 = unsafe { init_tree(db, &cache_path, DEPTH).await.unwrap() };
    assert_eq!(
        ts2.root().await,
        r7,
        "restore must reach the up-to-date root"
    );
    drop(ts2);

    let cp2 = checkpoint::read_checkpoint(&cache_path).expect("checkpoint still present");
    assert_eq!(cp2.root_u256(), Some(r7), "checkpoint root advanced");
    assert_eq!(
        cp2.cursor().block_number,
        next_block2,
        "cursor advanced to new latest"
    );

    cleanup(&cache_path);
}

// ============================================================================
// 2. Correctness: incremental restore == full rebuild (identical root).
// ============================================================================

#[tokio::test]
async fn test_incremental_restore_matches_full_rebuild() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    let stage1 = [(1u64, 11u64), (2, 22), (3, 33)];
    let (mut all_events, nb) = seed_stage(db, &stage1, 10).await;
    let r_a = root_after_events(&all_events).await;
    insert_test_world_tree_root(db, nb, 0, r_a, U256::ZERO)
        .await
        .unwrap();

    // First init builds + checkpoints.
    let ts1 = unsafe { init_tree(db, &cache_path, DEPTH).await.unwrap() };
    drop(ts1);

    // Delta.
    let stage2 = [(4u64, 44u64), (5, 55)];
    let (delta, nb2) = seed_stage(db, &stage2, 20).await;
    all_events.extend(delta);
    let r_b = root_after_events(&all_events).await;
    insert_test_world_tree_root(db, nb2, 0, r_b, U256::ZERO)
        .await
        .unwrap();

    // Path A: incremental restore (cache + checkpoint present).
    let incremental = unsafe { init_tree(db, &cache_path, DEPTH).await.unwrap() };
    let incremental_root = incremental.root().await;
    drop(incremental);

    // Path B: full rebuild from scratch (wipe cache + checkpoint).
    cleanup(&cache_path);
    let fresh = unsafe { init_tree(db, &cache_path, DEPTH).await.unwrap() };
    let fresh_root = fresh.root().await;
    drop(fresh);

    assert_eq!(
        incremental_root, fresh_root,
        "incremental restore and full rebuild MUST produce identical roots"
    );
    assert_eq!(
        incremental_root, r_b,
        "and must equal the expected up-to-date root"
    );

    cleanup(&cache_path);
}

// ============================================================================
// 3. Fast-path proof: incremental restore resumes from the checkpoint cursor and
//    does NOT re-scan history before it.
//
//    We checkpoint at block 15, then insert an event at block 12 (before the
//    cursor) that was not part of the mmap. A genesis replay would apply it and
//    change the root; an incremental restore (resuming after block 15) must ignore
//    it, leaving the root unchanged. This distinguishes the two code paths purely
//    by observable root value.
// ============================================================================

#[tokio::test]
async fn test_incremental_restore_resumes_from_cursor_and_ignores_earlier_events() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    let stage1 = [(1u64, 101u64), (2, 102), (3, 103), (4, 104), (5, 105)];
    let (all_events, next_block) = seed_stage(db, &stage1, 10).await;
    let r5 = root_after_events(&all_events).await;
    insert_test_world_tree_root(db, next_block, 0, r5, U256::ZERO)
        .await
        .unwrap();

    // Build + checkpoint at cursor (block 15).
    let ts1 = unsafe { init_tree(db, &cache_path, DEPTH).await.unwrap() };
    assert_eq!(ts1.root().await, r5);
    drop(ts1);
    let cp = checkpoint::read_checkpoint(&cache_path).unwrap();
    assert_eq!(cp.cursor().block_number, next_block);

    // Insert a "pre-cursor" event (block 12, log 5) touching a new leaf (20) that is
    // NOT reflected in the mmap. A full genesis replay would apply it.
    let stray = account_created(12, 5, 20, 999);
    insert_test_world_tree_event(db, &stray).await.unwrap();

    // What the root WOULD be if the stray were applied (genesis-replay outcome).
    let mut with_stray = all_events.clone();
    with_stray.push(stray);
    let r_with_stray = root_after_events(&with_stray).await;
    assert_ne!(r5, r_with_stray, "sanity: the stray event changes the root");

    // Restart: incremental restore resumes after block 15, so the block-12 stray is
    // ignored and the root stays r5.
    let ts2 = unsafe { init_tree(db, &cache_path, DEPTH).await.unwrap() };
    let restored = ts2.root().await;
    drop(ts2);

    assert_eq!(
        restored, r5,
        "incremental restore must resume from the cursor and ignore pre-cursor events"
    );
    assert_ne!(
        restored, r_with_stray,
        "a genesis replay (which would apply the stray) must NOT have happened"
    );

    cleanup(&cache_path);
}

// ============================================================================
// 4. Fallbacks: missing / corrupted / mismatched checkpoint ⇒ safe full replay,
//    still correct, and the checkpoint is rewritten.
// ============================================================================

/// Shared setup: build a cache + checkpoint, then add a delta. Returns the expected
/// up-to-date root.
async fn setup_with_delta(db: &DB, cache_path: &PathBuf) -> U256 {
    let stage1 = [(1u64, 11u64), (2, 22), (3, 33)];
    let (mut all_events, nb) = seed_stage(db, &stage1, 10).await;
    let r_a = root_after_events(&all_events).await;
    insert_test_world_tree_root(db, nb, 0, r_a, U256::ZERO)
        .await
        .unwrap();

    let ts1 = unsafe { init_tree(db, cache_path, DEPTH).await.unwrap() };
    drop(ts1);

    let stage2 = [(4u64, 44u64), (5, 55)];
    let (delta, nb2) = seed_stage(db, &stage2, 20).await;
    all_events.extend(delta);
    let r_b = root_after_events(&all_events).await;
    insert_test_world_tree_root(db, nb2, 0, r_b, U256::ZERO)
        .await
        .unwrap();

    r_b
}

#[tokio::test]
async fn test_fallback_when_checkpoint_missing() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    let expected_root = setup_with_delta(db, &cache_path).await;

    // Delete the checkpoint but keep the mmap cache.
    fs::remove_file(checkpoint::checkpoint_path(&cache_path)).unwrap();

    let ts = unsafe { init_tree(db, &cache_path, DEPTH).await.unwrap() };
    assert_eq!(
        ts.root().await,
        expected_root,
        "fallback (full replay) must still be correct"
    );
    drop(ts);

    assert!(
        checkpoint::read_checkpoint(&cache_path).is_some(),
        "a fresh checkpoint should be rewritten after fallback restore"
    );

    cleanup(&cache_path);
}

#[tokio::test]
async fn test_fallback_when_checkpoint_corrupted() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    let expected_root = setup_with_delta(db, &cache_path).await;

    // Corrupt the checkpoint file with garbage.
    fs::write(
        checkpoint::checkpoint_path(&cache_path),
        b"garbage not json",
    )
    .unwrap();

    let ts = unsafe { init_tree(db, &cache_path, DEPTH).await.unwrap() };
    assert_eq!(
        ts.root().await,
        expected_root,
        "corrupt checkpoint ⇒ safe full replay, still correct"
    );

    cleanup(&cache_path);
}

#[tokio::test]
async fn test_fallback_when_checkpoint_root_mismatches_mmap() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    let expected_root = setup_with_delta(db, &cache_path).await;

    // Write a well-formed checkpoint (valid checksum) whose root does NOT match the
    // mmap's root — simulating a checkpoint that is inconsistent with the actual
    // cache (e.g. post-crash or post-rollback). The restore-time root guard must
    // reject it and fall back to a full replay.
    let bogus = checkpoint::TreeCheckpoint::new(
        U256::from(0xdead_beefu64),
        world_id_indexer::db::WorldIdRegistryEventId {
            block_number: 999,
            log_index: 0,
        },
    );
    checkpoint::write_checkpoint(&cache_path, &bogus).unwrap();

    let ts = unsafe { init_tree(db, &cache_path, DEPTH).await.unwrap() };
    assert_eq!(
        ts.root().await,
        expected_root,
        "root-mismatched checkpoint ⇒ rejected, full replay, still correct"
    );

    cleanup(&cache_path);
}

// ============================================================================
// 5. Reorg: invalidating the checkpoint removes the sidecar; the next boot still
//    restores correctly (and rewrites a fresh checkpoint).
// ============================================================================

#[tokio::test]
async fn test_invalidate_checkpoint_removes_sidecar() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    let expected_root = setup_with_delta(db, &cache_path).await;

    // Simulate the reorg/rollback path invalidating the checkpoint via the tree's
    // own API.
    let ts = unsafe { init_tree(db, &cache_path, DEPTH).await.unwrap() };
    ts.invalidate_checkpoint();
    drop(ts);

    assert!(
        checkpoint::read_checkpoint(&cache_path).is_none(),
        "invalidate_checkpoint must remove the sidecar"
    );

    // Next boot: no checkpoint ⇒ safe full replay, still correct, checkpoint rewritten.
    let ts2 = unsafe { init_tree(db, &cache_path, DEPTH).await.unwrap() };
    assert_eq!(ts2.root().await, expected_root, "must still be correct");
    drop(ts2);
    assert!(
        checkpoint::read_checkpoint(&cache_path).is_some(),
        "checkpoint rewritten after fallback restore"
    );

    cleanup(&cache_path);
}

// ============================================================================
// 6. Stale mmap (root not in DB) ⇒ falls back to a full rebuild, does NOT
//    crash. Covered by using an empty DB: the first init_tree builds an empty
//    mmap whose root is never recorded in world_id_registry_events, so the
//    second init_tree hits StaleCache in try_restore and must recover via
//    build_from_db_with_cache rather than propagating the error.
// ============================================================================

#[tokio::test]
async fn test_stale_mmap_falls_back_to_rebuild() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    // First init: no mmap → build from empty DB → writes mmap with empty-tree
    // root. The empty-tree root is never inserted into world_id_registry_events.
    let ts1 = unsafe { init_tree(db, &cache_path, DEPTH).await.unwrap() };
    let empty_root = ts1.root().await;
    drop(ts1);

    // Second init: mmap exists → try_restore → root_exists(empty_root) == false
    // → StaleCache. With the fix, init_tree falls back to build_from_db_with_cache
    // and succeeds instead of propagating the error.
    let ts2 = unsafe { init_tree(db, &cache_path, DEPTH).await.unwrap() };
    assert_eq!(
        ts2.root().await,
        empty_root,
        "rebuilt tree must match empty DB"
    );
    drop(ts2);

    cleanup(&cache_path);
}

// ============================================================================
// 7. Multi-instance independence: each instance uses only its OWN local
//    checkpoint; one instance's missing checkpoint does not affect the other, and
//    both converge to the same correct root.
// ============================================================================

#[tokio::test]
async fn test_multi_instance_independent_checkpoints() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();

    let cache_a = temp_cache_path();
    let cache_b = temp_cache_path();

    // Shared DB state: stage 1 + root.
    let stage1 = [(1u64, 11u64), (2, 22), (3, 33)];
    let (mut all_events, nb) = seed_stage(db, &stage1, 10).await;
    let r_a = root_after_events(&all_events).await;
    insert_test_world_tree_root(db, nb, 0, r_a, U256::ZERO)
        .await
        .unwrap();

    // Both instances build independently from the same DB, each writing its own
    // checkpoint colocated with its own cache file.
    let a1 = unsafe { init_tree(db, &cache_a, DEPTH).await.unwrap() };
    drop(a1);
    let b1 = unsafe { init_tree(db, &cache_b, DEPTH).await.unwrap() };
    drop(b1);

    assert!(checkpoint::read_checkpoint(&cache_a).is_some());
    assert!(checkpoint::read_checkpoint(&cache_b).is_some());

    // Shared delta + root.
    let stage2 = [(4u64, 44u64), (5, 55)];
    let (delta, nb2) = seed_stage(db, &stage2, 20).await;
    all_events.extend(delta);
    let r_b = root_after_events(&all_events).await;
    insert_test_world_tree_root(db, nb2, 0, r_b, U256::ZERO)
        .await
        .unwrap();

    // Break ONLY instance B's checkpoint.
    fs::remove_file(checkpoint::checkpoint_path(&cache_b)).unwrap();

    // Instance A restarts using its own (still valid) checkpoint; instance B falls
    // back to a full replay. A's checkpoint is untouched and unused by B.
    let a2 = unsafe { init_tree(db, &cache_a, DEPTH).await.unwrap() };
    assert!(
        checkpoint::read_checkpoint(&cache_a).is_some(),
        "instance A's checkpoint remains present and independent"
    );
    let b2 = unsafe { init_tree(db, &cache_b, DEPTH).await.unwrap() };

    // Both instances converge to the same correct root.
    assert_eq!(a2.root().await, r_b);
    assert_eq!(b2.root().await, r_b);
    assert_eq!(a2.root().await, b2.root().await);

    drop(a2);
    drop(b2);
    cleanup(&cache_a);
    cleanup(&cache_b);
}

// ============================================================================
// 8. sync_from_db writes its own checkpoint; that checkpoint (not the one
//    written by init_tree) is used on the next restart.
//
//    Proof: init_tree checkpoints at the stage-1 cursor. sync_from_db then
//    applies stage-2 events and advances the checkpoint to the stage-2 cursor.
//    A stray event is inserted between the two cursors. On restart, if the
//    stage-2 (sync) checkpoint is used the stray is ignored; if the stage-1
//    (init) checkpoint were used the stray would be applied and change the root.
// ============================================================================

#[tokio::test]
async fn test_sync_from_db_checkpoint_used_on_restart() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    // Stage 1: build + checkpoint at stage-1 cursor.
    let stage1 = [(1u64, 11u64), (2, 22), (3, 33)];
    let (mut all_events, nb) = seed_stage(db, &stage1, 10).await;
    let r_a = root_after_events(&all_events).await;
    insert_test_world_tree_root(db, nb, 0, r_a, U256::ZERO)
        .await
        .unwrap();

    let ts1 = unsafe { init_tree(db, &cache_path, DEPTH).await.unwrap() };
    let cp_after_init = checkpoint::read_checkpoint(&cache_path).unwrap();

    // Stage 2 delta: add to DB but don't restart — simulate events arriving
    // while the indexer is running.
    let stage2 = [(4u64, 44u64), (5, 55)];
    let (delta, nb2) = seed_stage(db, &stage2, 20).await;
    all_events.extend(delta);
    let r_b = root_after_events(&all_events).await;
    insert_test_world_tree_root(db, nb2, 0, r_b, U256::ZERO)
        .await
        .unwrap();

    // sync_from_db applies stage 2 to the mmap and advances the checkpoint.
    sync_from_db(db, &ts1).await.unwrap();
    assert_eq!(ts1.root().await, r_b);

    let cp_after_sync = checkpoint::read_checkpoint(&cache_path).unwrap();
    assert_ne!(
        cp_after_init.cursor(),
        cp_after_sync.cursor(),
        "sync_from_db must advance the checkpoint past the init cursor"
    );
    assert_eq!(cp_after_sync.cursor().block_number, nb2);
    drop(ts1);

    // Insert a stray event strictly between the init cursor and the sync cursor.
    // (block 15 is after stage-1 end ≈ block 13 and before stage-2 start = block 20)
    let stray = account_created(15, 0, 20, 999);
    insert_test_world_tree_event(db, &stray).await.unwrap();

    let mut events_with_stray = all_events.clone();
    events_with_stray.push(stray);
    let r_with_stray = root_after_events(&events_with_stray).await;
    assert_ne!(r_b, r_with_stray, "sanity: stray must change the root");

    // Restart: init_tree reads the sync checkpoint (stage-2 cursor).
    // It must resume after the sync cursor, leaving the stray ignored.
    let ts2 = unsafe { init_tree(db, &cache_path, DEPTH).await.unwrap() };
    assert_eq!(
        ts2.root().await,
        r_b,
        "restart must use sync_from_db checkpoint and reach stage-2 root"
    );
    assert_ne!(
        ts2.root().await,
        r_with_stray,
        "a replay from the init cursor (which would include the stray) must NOT have happened"
    );
    drop(ts2);

    cleanup(&cache_path);
}

// ============================================================================
// 9. Fallback rebuild → checkpoint → incremental restore on the next restart
//    (fixes 1 and 2 compose correctly).
//
//    After a corrupted mmap forces a fallback rebuild, the checkpoint written
//    by that rebuild must be valid enough to enable incremental restore on the
//    subsequent restart — i.e., fix 2's output feeds correctly into fix 1.
//
//    Proof: a stray event inserted before the fallback cursor is ignored on the
//    third init; a genesis replay would include it and change the root.
// ============================================================================

#[tokio::test]
async fn test_post_fallback_checkpoint_enables_incremental_restore() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    // Stage 1 + RootRecorded so the mmap root is in world_id_registry_events.
    let stage1 = [(1u64, 11u64), (2, 22), (3, 33)];
    let (mut all_events, nb) = seed_stage(db, &stage1, 10).await;
    let r_a = root_after_events(&all_events).await;
    insert_test_world_tree_root(db, nb, 0, r_a, U256::ZERO)
        .await
        .unwrap();

    // First init: normal build, checkpoint at stage-1 cursor.
    let ts1 = unsafe { init_tree(db, &cache_path, DEPTH).await.unwrap() };
    drop(ts1);

    // Corrupt the mmap to force a fallback on the second init.
    fs::write(&cache_path, b"corrupted").unwrap();

    // Second init: corrupted mmap → fallback rebuild from DB → correct tree,
    // checkpoint written at stage-1 cursor with stage-1 root.
    let ts2 = unsafe { init_tree(db, &cache_path, DEPTH).await.unwrap() };
    assert_eq!(ts2.root().await, r_a);
    let fallback_cursor = checkpoint::read_checkpoint(&cache_path).unwrap().cursor();
    drop(ts2);

    // Stage 2 + RootRecorded.
    let stage2 = [(4u64, 44u64), (5, 55)];
    let (delta, nb2) = seed_stage(db, &stage2, 20).await;
    all_events.extend(delta);
    let r_b = root_after_events(&all_events).await;
    insert_test_world_tree_root(db, nb2, 0, r_b, U256::ZERO)
        .await
        .unwrap();

    // Insert a stray event strictly before the fallback cursor (block 5 < block ~13).
    let stray = account_created(5, 0, 20, 999);
    insert_test_world_tree_event(db, &stray).await.unwrap();
    assert!(
        stray.block_number < fallback_cursor.block_number,
        "stray must be before the fallback cursor for the test to be meaningful"
    );

    let mut events_with_stray = all_events.clone();
    events_with_stray.push(stray);
    let r_with_stray = root_after_events(&events_with_stray).await;
    assert_ne!(r_b, r_with_stray, "sanity: stray must change the root");

    // Third init: uses the post-fallback checkpoint → incremental from fallback cursor
    // → applies stage 2, ignores the stray.
    let ts3 = unsafe { init_tree(db, &cache_path, DEPTH).await.unwrap() };
    assert_eq!(
        ts3.root().await,
        r_b,
        "third init must reach the stage-2 root via incremental restore"
    );
    assert_ne!(
        ts3.root().await,
        r_with_stray,
        "a genesis replay (which would include the stray) must NOT have happened"
    );
    drop(ts3);

    cleanup(&cache_path);
}
