//! Tests for the local per-instance tree checkpoint (watermark) restore path.
//!
//! These assert the *desired* behavior of the incremental-restore optimization:
//!   - a valid local checkpoint makes restart replay only events AFTER the cursor
//!     (fast path), not the whole history from genesis;
//!   - incremental restore produces an IDENTICAL tree to a full rebuild (the
//!     critical correctness property for a ZK/identity Merkle tree);
//!   - a missing / corrupted / mismatched checkpoint safely falls back to the full
//!     replay (never a crash, never a silently-wrong tree);
//!   - invalidating the checkpoint (as the reorg/rollback path does) forces one
//!     safe full replay on the next boot;
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
        cached_tree::{InitStats, init_tree_with_stats},
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
/// `(block_number, 0)`.
fn account_created(
    block_number: u64,
    leaf_index: u64,
    commitment: u64,
) -> BlockchainEvent<RegistryEvent> {
    BlockchainEvent {
        block_number,
        block_hash: U256::from(1_000_000 + block_number),
        tx_hash: U256::from(block_number),
        log_index: 0,
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
/// pairs at consecutive blocks starting at `first_block`, plus matching `accounts`
/// rows. Returns `(events, next_block)`.
async fn seed_stage(
    db: &DB,
    leaves: &[(u64, u64)],
    first_block: u64,
) -> (Vec<BlockchainEvent<RegistryEvent>>, u64) {
    let mut events = Vec::new();
    let mut block = first_block;
    for (leaf_index, commitment) in leaves {
        let ev = account_created(block, *leaf_index, *commitment);
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
// 1. Fast path: valid checkpoint ⇒ replay only the delta, not from genesis.
// ============================================================================

#[tokio::test]
async fn test_restart_uses_checkpoint_and_replays_only_delta() {
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

    // First init: no cache ⇒ full build from accounts, writes checkpoint at the
    // latest event id (the RootRecorded at block 15).
    let (ts1, stats1) = unsafe { init_tree_with_stats(db, &cache_path, DEPTH).await.unwrap() };
    assert!(stats1.full_rebuild, "first init should build from DB");
    assert_eq!(ts1.root().await, r5, "built root must match expected");
    drop(ts1);

    assert!(
        checkpoint::read_checkpoint(&cache_path).is_some(),
        "a checkpoint should have been written after first init"
    );

    // Stage 2 delta: 2 more accounts (blocks 16,17) + RootRecorded at block 18.
    let stage2 = [(6u64, 106u64), (7, 107)];
    let (delta_events, next_block2) = seed_stage(db, &stage2, 16).await;
    all_events.extend(delta_events);
    let r7 = root_after_events(&all_events).await;
    insert_test_world_tree_root(db, next_block2, 0, r7, U256::ZERO)
        .await
        .unwrap();

    // Second init: cache + valid checkpoint ⇒ incremental restore.
    let (ts2, stats2) = unsafe { init_tree_with_stats(db, &cache_path, DEPTH).await.unwrap() };

    assert!(
        stats2.used_checkpoint,
        "restart with a valid checkpoint must use it (incremental restore)"
    );
    assert!(!stats2.full_rebuild, "restart must not rebuild from scratch");
    // Only the delta after the checkpoint cursor (block 15) is replayed:
    // blocks 16, 17 (AccountCreated) + 18 (RootRecorded) == 3 raw events.
    assert_eq!(
        stats2.replayed_events, 3,
        "must replay only events after the checkpoint cursor, not from genesis"
    );
    assert_eq!(
        ts2.root().await,
        r7,
        "incremental restore must reach the up-to-date root"
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
    let (ts1, _s1) = unsafe { init_tree_with_stats(db, &cache_path, DEPTH).await.unwrap() };
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
    let (incremental, stats_inc) =
        unsafe { init_tree_with_stats(db, &cache_path, DEPTH).await.unwrap() };
    assert!(stats_inc.used_checkpoint, "should have used checkpoint");
    let incremental_root = incremental.root().await;
    drop(incremental);

    // Path B: full rebuild from scratch (wipe cache + checkpoint).
    cleanup(&cache_path);
    let (fresh, stats_fresh) =
        unsafe { init_tree_with_stats(db, &cache_path, DEPTH).await.unwrap() };
    assert!(stats_fresh.full_rebuild, "should have rebuilt from DB");
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
// 3. Fallbacks: missing / corrupted / mismatched checkpoint ⇒ safe full replay.
// ============================================================================

/// Shared setup: build a cache + checkpoint, then add a delta. Returns the
/// expected up-to-date root and the number of events a *full genesis* replay
/// would process.
async fn setup_with_delta(db: &DB, cache_path: &PathBuf) -> (U256, usize) {
    let stage1 = [(1u64, 11u64), (2, 22), (3, 33)];
    let (mut all_events, nb) = seed_stage(db, &stage1, 10).await;
    let r_a = root_after_events(&all_events).await;
    insert_test_world_tree_root(db, nb, 0, r_a, U256::ZERO)
        .await
        .unwrap();

    let (ts1, _s1) = unsafe { init_tree_with_stats(db, cache_path, DEPTH).await.unwrap() };
    drop(ts1);

    let stage2 = [(4u64, 44u64), (5, 55)];
    let (delta, nb2) = seed_stage(db, &stage2, 20).await;
    all_events.extend(delta);
    let r_b = root_after_events(&all_events).await;
    insert_test_world_tree_root(db, nb2, 0, r_b, U256::ZERO)
        .await
        .unwrap();

    // Full genesis replay would process every event: 3 + root_a + 2 + root_b = 7.
    (r_b, 7)
}

#[tokio::test]
async fn test_fallback_when_checkpoint_missing() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    let (expected_root, full_count) = setup_with_delta(db, &cache_path).await;

    // Delete the checkpoint but keep the mmap cache.
    fs::remove_file(checkpoint::checkpoint_path(&cache_path)).unwrap();

    let (ts, stats) = unsafe { init_tree_with_stats(db, &cache_path, DEPTH).await.unwrap() };
    assert!(!stats.used_checkpoint, "no checkpoint ⇒ must not use one");
    assert!(
        !stats.full_rebuild,
        "mmap still present ⇒ restore path, not rebuild"
    );
    assert_eq!(
        stats.replayed_events, full_count,
        "missing checkpoint ⇒ full genesis replay"
    );
    assert_eq!(
        ts.root().await,
        expected_root,
        "fallback must still be correct"
    );

    cleanup(&cache_path);
}

#[tokio::test]
async fn test_fallback_when_checkpoint_corrupted() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    let (expected_root, full_count) = setup_with_delta(db, &cache_path).await;

    // Corrupt the checkpoint file with garbage.
    fs::write(checkpoint::checkpoint_path(&cache_path), b"garbage not json").unwrap();

    let (ts, stats) = unsafe { init_tree_with_stats(db, &cache_path, DEPTH).await.unwrap() };
    assert!(!stats.used_checkpoint, "corrupt checkpoint ⇒ ignored");
    assert_eq!(stats.replayed_events, full_count, "⇒ full genesis replay");
    assert_eq!(
        ts.root().await,
        expected_root,
        "fallback must still be correct"
    );

    cleanup(&cache_path);
}

#[tokio::test]
async fn test_fallback_when_checkpoint_root_mismatches_mmap() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    let (expected_root, full_count) = setup_with_delta(db, &cache_path).await;

    // Write a well-formed checkpoint (valid checksum) whose root does NOT match the
    // mmap's root — simulating a checkpoint that is ahead of / inconsistent with the
    // actual cache (e.g. post-crash or post-rollback).
    let bogus = checkpoint::TreeCheckpoint::new(
        U256::from(0xdead_beefu64),
        world_id_indexer::db::WorldIdRegistryEventId {
            block_number: 999,
            log_index: 0,
        },
        3,
    );
    checkpoint::write_checkpoint(&cache_path, &bogus).unwrap();

    let (ts, stats) = unsafe { init_tree_with_stats(db, &cache_path, DEPTH).await.unwrap() };
    assert!(
        !stats.used_checkpoint,
        "checkpoint whose root != mmap root must be rejected"
    );
    assert_eq!(stats.replayed_events, full_count, "⇒ full genesis replay");
    assert_eq!(
        ts.root().await,
        expected_root,
        "fallback must still be correct"
    );

    cleanup(&cache_path);
}

// ============================================================================
// 4. Reorg: invalidating the checkpoint forces one safe full replay next boot.
// ============================================================================

#[tokio::test]
async fn test_invalidate_checkpoint_forces_full_replay() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    let (expected_root, full_count) = setup_with_delta(db, &cache_path).await;

    // Simulate the reorg/rollback path invalidating the checkpoint via the tree's
    // own API.
    let (ts, _s) = unsafe { init_tree_with_stats(db, &cache_path, DEPTH).await.unwrap() };
    ts.invalidate_checkpoint();
    drop(ts);

    assert!(
        checkpoint::read_checkpoint(&cache_path).is_none(),
        "invalidate_checkpoint must remove the sidecar"
    );

    // Next boot: no checkpoint ⇒ safe full replay, still correct.
    let (ts2, stats2) = unsafe { init_tree_with_stats(db, &cache_path, DEPTH).await.unwrap() };
    assert!(
        !stats2.used_checkpoint,
        "after invalidation, must not use a checkpoint"
    );
    assert_eq!(stats2.replayed_events, full_count, "⇒ full genesis replay");
    assert_eq!(ts2.root().await, expected_root, "must still be correct");

    cleanup(&cache_path);
}

// ============================================================================
// 5. Multi-instance independence: each instance uses only its OWN local
//    checkpoint; one instance's missing checkpoint does not affect the other.
//    Both share the same DB and reach the same correct root.
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
    let (a1, _sa1) = unsafe { init_tree_with_stats(db, &cache_a, DEPTH).await.unwrap() };
    drop(a1);
    let (b1, _sb1) = unsafe { init_tree_with_stats(db, &cache_b, DEPTH).await.unwrap() };
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

    // Instance A restarts using its own (still valid) checkpoint → incremental.
    let (a2, stats_a) = unsafe { init_tree_with_stats(db, &cache_a, DEPTH).await.unwrap() };
    assert!(
        stats_a.used_checkpoint,
        "instance A must use its own valid checkpoint"
    );
    assert_eq!(
        stats_a.replayed_events, 3,
        "A replays only its own delta (blocks 20,21,22)"
    );

    // Instance B restarts; its checkpoint is gone → safe full replay. A's checkpoint
    // is untouched and unused by B.
    let (b2, stats_b) = unsafe { init_tree_with_stats(db, &cache_b, DEPTH).await.unwrap() };
    assert!(
        !stats_b.used_checkpoint,
        "instance B fell back independently of A"
    );
    assert_eq!(stats_b.replayed_events, 7, "B does a full genesis replay");

    // Both instances converge to the same correct root.
    assert_eq!(a2.root().await, r_b);
    assert_eq!(b2.root().await, r_b);
    assert_eq!(a2.root().await, b2.root().await);

    drop(a2);
    drop(b2);
    cleanup(&cache_a);
    cleanup(&cache_b);
}
