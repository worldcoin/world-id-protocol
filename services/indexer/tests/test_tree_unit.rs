#![cfg(feature = "integration-tests")]

mod helpers;

use std::{fs, path::PathBuf};

use alloy::primitives::{Address, U256};
use helpers::db_helpers::{
    create_unique_test_db, insert_test_account, insert_test_world_tree_event,
    insert_test_world_tree_root,
};
use world_id_indexer::{
    db::WorldTreeEventType,
    tree::{
        TreeState,
        cached_tree::{init_tree, sync_from_db},
    },
};

fn temp_cache_path() -> PathBuf {
    std::env::temp_dir().join(format!("test_tree_unit_{}.mmap", uuid::Uuid::new_v4()))
}

fn cleanup(path: &PathBuf) {
    let _ = fs::remove_file(path);
}

// ============================================================================
// Tree Creation tests
// ============================================================================

/// Test 1: Empty DB produces an empty tree with the default root.
#[tokio::test]
async fn test_init_tree_empty_db() {
    let test_db = create_unique_test_db().await;
    let cache_path = temp_cache_path();

    let tree_state = init_tree(test_db.db(), &cache_path, 6, 2).await.unwrap();

    let expected = TreeState::new_empty(6);
    assert_eq!(tree_state.root().await, expected.root().await);

    cleanup(&cache_path);
}

/// Test 2: All leaves fall within the dense prefix — sparse pass is skipped.
#[tokio::test]
async fn test_all_leaves_in_dense_prefix() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    // dense_prefix_depth=3 → dense_prefix_size=8; indices 1..=4 all fit
    for i in 1u64..=4 {
        insert_test_account(db, U256::from(i), Address::ZERO, U256::from(i * 100))
            .await
            .unwrap();
    }

    let tree_state = init_tree(db, &cache_path, 6, 3).await.unwrap();

    let expected = TreeState::new_empty(6);
    for i in 1u64..=4 {
        expected
            .set_leaf_at_index(i as usize, U256::from(i * 100))
            .await
            .unwrap();
    }

    assert_eq!(tree_state.root().await, expected.root().await);

    cleanup(&cache_path);
}

/// Test 3: Some leaves are beyond the dense prefix, exercising the sparse pass.
#[tokio::test]
async fn test_leaves_beyond_dense_prefix() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    // dense_prefix_depth=2 → dense_prefix_size=4
    // Indices 1, 2 are dense; 5 and 10 are sparse
    let leaves: &[(u64, u64)] = &[(1, 100), (2, 200), (5, 500), (10, 1000)];

    for &(idx, val) in leaves {
        insert_test_account(db, U256::from(idx), Address::ZERO, U256::from(val))
            .await
            .unwrap();
    }

    let tree_state = init_tree(db, &cache_path, 6, 2).await.unwrap();

    let expected = TreeState::new_empty(6);
    for &(idx, val) in leaves {
        expected
            .set_leaf_at_index(idx as usize, U256::from(val))
            .await
            .unwrap();
    }

    assert_eq!(tree_state.root().await, expected.root().await);

    cleanup(&cache_path);
}

/// Test 5: Accounts with leaf_index == 0 are skipped during tree building.
#[tokio::test]
async fn test_zero_index_leaf_skipped() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    // leaf_index 0 should be skipped; leaf_index 1 should be included
    insert_test_account(db, U256::ZERO, Address::ZERO, U256::from(999))
        .await
        .unwrap();
    insert_test_account(db, U256::from(1), Address::ZERO, U256::from(100))
        .await
        .unwrap();

    let tree_state = init_tree(db, &cache_path, 6, 2).await.unwrap();

    let tree = tree_state.read().await;
    assert_eq!(tree.get_leaf(0), U256::ZERO, "leaf 0 must remain zero");
    assert_eq!(tree.get_leaf(1), U256::from(100));

    cleanup(&cache_path);
}

/// Test 6: Account with leaf_index >= tree capacity produces an error.
#[tokio::test]
async fn test_leaf_index_out_of_range() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    // tree_depth=6 → capacity=64; leaf_index 100 is out of range
    insert_test_account(db, U256::from(100), Address::ZERO, U256::from(999))
        .await
        .unwrap();

    let result = init_tree(db, &cache_path, 6, 2).await;
    assert!(result.is_err(), "should fail for out-of-range leaf index");

    let err = result.err().expect("should be an error");
    let msg = format!("{err}");
    assert!(
        msg.contains("out of range"),
        "error should mention out of range, got: {msg}"
    );

    cleanup(&cache_path);
}

// ============================================================================
// Tree Restoration tests
// ============================================================================

/// Test 8: When the cached root is not in world_tree_roots (stale), init_tree
/// falls back to a full rebuild from the accounts table.
#[tokio::test]
async fn test_stale_cache_triggers_rebuild() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    // First init: builds cache from one account
    insert_test_account(db, U256::from(1), Address::ZERO, U256::from(100))
        .await
        .unwrap();

    let tree_state = init_tree(db, &cache_path, 6, 2).await.unwrap();
    drop(tree_state);
    assert!(cache_path.exists());

    // Add a second account — only visible to a full rebuild, not to replay
    insert_test_account(db, U256::from(2), Address::ZERO, U256::from(200))
        .await
        .unwrap();

    // Second init: cache root is NOT in world_tree_roots → StaleCache → fallback
    let tree_state2 = init_tree(db, &cache_path, 6, 2).await.unwrap();

    // If fallback rebuilt from accounts, both leaves must be present
    let tree = tree_state2.read().await;
    assert_eq!(tree.get_leaf(1), U256::from(100));
    assert_eq!(tree.get_leaf(2), U256::from(200));

    cleanup(&cache_path);
}

/// Test 9: Replay with zero new events — cache is already up-to-date.
#[tokio::test]
async fn test_replay_with_no_new_events() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    // Insert account + matching event
    insert_test_account(db, U256::from(1), Address::ZERO, U256::from(100))
        .await
        .unwrap();
    insert_test_world_tree_event(
        db,
        10,
        0,
        U256::from(1),
        WorldTreeEventType::AccountCreated,
        U256::from(1),
        U256::from(100),
    )
    .await
    .unwrap();

    // Build cache
    let tree_state = init_tree(db, &cache_path, 6, 2).await.unwrap();
    let root = tree_state.root().await;
    drop(tree_state);

    // Record the cache root so try_restore can validate it.
    // Place the root AT the same position as the latest event so
    // replay_events finds nothing after it.
    insert_test_world_tree_root(db, 10, 0, root, U256::ZERO)
        .await
        .unwrap();

    // Second init: restore from cache, replay 0 events
    let tree_state2 = init_tree(db, &cache_path, 6, 2).await.unwrap();
    assert_eq!(tree_state2.root().await, root, "root must be unchanged");

    cleanup(&cache_path);
}

/// Test 10: Replay deduplicates multiple events that update the same leaf,
/// keeping only the final commitment value.
#[tokio::test]
async fn test_replay_deduplication() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    // Initial state
    insert_test_account(db, U256::from(1), Address::ZERO, U256::from(100))
        .await
        .unwrap();
    insert_test_world_tree_event(
        db,
        10,
        0,
        U256::from(1),
        WorldTreeEventType::AccountCreated,
        U256::from(1),
        U256::from(100),
    )
    .await
    .unwrap();

    // Build cache
    let tree_state = init_tree(db, &cache_path, 6, 2).await.unwrap();
    let root = tree_state.root().await;
    drop(tree_state);

    // Record root so try_restore succeeds
    insert_test_world_tree_root(db, 10, 1, root, U256::ZERO)
        .await
        .unwrap();

    // Three updates to the same leaf after the root position
    for (block, commitment) in [(11, 200u64), (12, 300), (13, 400)] {
        insert_test_world_tree_event(
            db,
            block,
            0,
            U256::from(1),
            WorldTreeEventType::AccountUpdated,
            U256::from(block),
            U256::from(commitment),
        )
        .await
        .unwrap();
    }

    // Update account table to match final state (for potential rebuild parity)
    sqlx::query("UPDATE accounts SET offchain_signer_commitment = $1 WHERE leaf_index = $2")
        .bind(U256::from(400))
        .bind(U256::from(1))
        .execute(db.pool())
        .await
        .unwrap();

    // Restore + replay should deduplicate to final value 400
    let tree_state2 = init_tree(db, &cache_path, 6, 2).await.unwrap();

    let tree = tree_state2.read().await;
    assert_eq!(
        tree.get_leaf(1),
        U256::from(400),
        "dedup must keep only the final commitment"
    );

    cleanup(&cache_path);
}

/// Test 11: Replay of multiple distinct leaves produces the same tree root
/// as a fresh rebuild, regardless of HashMap iteration order.
#[tokio::test]
async fn test_replay_matches_fresh_build() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    // Initial state: two accounts
    insert_test_account(db, U256::from(1), Address::ZERO, U256::from(100))
        .await
        .unwrap();
    insert_test_account(db, U256::from(2), Address::ZERO, U256::from(200))
        .await
        .unwrap();

    insert_test_world_tree_event(
        db,
        10,
        0,
        U256::from(1),
        WorldTreeEventType::AccountCreated,
        U256::from(1),
        U256::from(100),
    )
    .await
    .unwrap();
    insert_test_world_tree_event(
        db,
        10,
        1,
        U256::from(2),
        WorldTreeEventType::AccountCreated,
        U256::from(2),
        U256::from(200),
    )
    .await
    .unwrap();

    // Build cache
    let tree_state = init_tree(db, &cache_path, 6, 2).await.unwrap();
    let root = tree_state.root().await;
    drop(tree_state);

    // Record root
    insert_test_world_tree_root(db, 10, 2, root, U256::ZERO)
        .await
        .unwrap();

    // Events after root: update leaf 1, update leaf 2, insert leaf 3
    insert_test_world_tree_event(
        db,
        11,
        0,
        U256::from(1),
        WorldTreeEventType::AccountUpdated,
        U256::from(11),
        U256::from(300),
    )
    .await
    .unwrap();
    insert_test_world_tree_event(
        db,
        11,
        1,
        U256::from(2),
        WorldTreeEventType::AccountUpdated,
        U256::from(12),
        U256::from(400),
    )
    .await
    .unwrap();
    insert_test_world_tree_event(
        db,
        12,
        0,
        U256::from(3),
        WorldTreeEventType::AccountCreated,
        U256::from(13),
        U256::from(500),
    )
    .await
    .unwrap();

    // Update accounts table to final state
    sqlx::query("UPDATE accounts SET offchain_signer_commitment = $1 WHERE leaf_index = $2")
        .bind(U256::from(300))
        .bind(U256::from(1))
        .execute(db.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE accounts SET offchain_signer_commitment = $1 WHERE leaf_index = $2")
        .bind(U256::from(400))
        .bind(U256::from(2))
        .execute(db.pool())
        .await
        .unwrap();
    insert_test_account(db, U256::from(3), Address::ZERO, U256::from(500))
        .await
        .unwrap();

    // Path A: Restore from cache + replay
    let replayed = init_tree(db, &cache_path, 6, 2).await.unwrap();
    let replayed_root = replayed.root().await;
    drop(replayed);

    // Path B: Fresh rebuild (delete cache first)
    cleanup(&cache_path);
    let fresh = init_tree(db, &cache_path, 6, 2).await.unwrap();
    let fresh_root = fresh.root().await;

    assert_eq!(
        replayed_root, fresh_root,
        "replay and fresh rebuild must produce identical roots"
    );

    cleanup(&cache_path);
}

// ============================================================================
// sync_from_db tests
// ============================================================================

/// Test 12: sync_from_db with no pending events returns 0.
#[tokio::test]
async fn test_sync_from_db_no_pending_events() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    let tree_state = init_tree(db, &cache_path, 6, 2).await.unwrap();

    let count = sync_from_db(db, &tree_state).await.unwrap();
    assert_eq!(count, 0);

    cleanup(&cache_path);
}

/// Test 13: sync_from_db deduplicates multiple events for the same leaf.
#[tokio::test]
async fn test_sync_from_db_deduplication() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    insert_test_account(db, U256::from(1), Address::ZERO, U256::from(100))
        .await
        .unwrap();

    // Build tree — last_synced_event_id will be (0,0) since no events exist yet
    let tree_state = init_tree(db, &cache_path, 6, 2).await.unwrap();

    // Insert 3 events for the same leaf with increasing commitments
    for (block, commitment) in [(100, 200u64), (101, 300), (102, 400)] {
        insert_test_world_tree_event(
            db,
            block,
            0,
            U256::from(1),
            WorldTreeEventType::AccountUpdated,
            U256::from(block),
            U256::from(commitment),
        )
        .await
        .unwrap();
    }

    let count = sync_from_db(db, &tree_state).await.unwrap();
    assert_eq!(count, 3, "all 3 raw events should be counted");

    let tree = tree_state.read().await;
    assert_eq!(
        tree.get_leaf(1),
        U256::from(400),
        "only the final commitment should remain"
    );

    cleanup(&cache_path);
}

// ============================================================================
// General edge cases
// ============================================================================

/// Test 18: Proof on an empty / freshly-initialized tree returns valid data.
/// In the real system the HTTP server starts only after init_tree, so this
/// tests the earliest possible proof request.
#[tokio::test]
async fn test_proof_on_empty_tree() {
    let state = TreeState::new_empty(6);

    let (leaf, _proof, root) = state.leaf_proof_and_root(0).await;
    assert_eq!(leaf, U256::ZERO);
    assert_eq!(root, state.root().await);

    // Non-zero index on an empty tree should also work
    let (leaf2, _proof2, root2) = state.leaf_proof_and_root(5).await;
    assert_eq!(leaf2, U256::ZERO);
    assert_eq!(root2, root, "same root since tree is empty");
}
