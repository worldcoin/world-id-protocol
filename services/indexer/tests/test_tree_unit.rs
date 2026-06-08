#![cfg(feature = "integration-tests")]

mod helpers;

use std::{fs, path::PathBuf};

use alloy::primitives::{Address, U256};
use helpers::db_helpers::{create_unique_test_db, insert_test_account, seed_forward_batch};
use world_id_indexer::{
    blockchain::{AccountCreatedEvent, BlockchainEvent, RegistryEvent, RootRecordedEvent},
    events_committer::EventsCommitter,
    handle_registry_event,
    tree::{
        TreeState,
        cache_metadata::metadata_path,
        cached_tree::{init_tree, sync_from_db},
    },
};

fn temp_cache_path() -> PathBuf {
    std::env::temp_dir().join(format!("test_tree_unit_{}.mmap", uuid::Uuid::new_v4()))
}

fn cleanup(path: &PathBuf) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(metadata_path(path));
}

async fn root_for_leaves(tree_depth: usize, leaves: &[(usize, U256)]) -> U256 {
    let path = temp_cache_path();
    let tree = unsafe { TreeState::new_empty(tree_depth, &path).unwrap() };
    for &(leaf_index, value) in leaves {
        tree.set_leaf_at_index(leaf_index, value).await.unwrap();
    }
    let root = tree.root().await;
    cleanup(&path);
    root
}

// ============================================================================
// Tree Creation tests
// ============================================================================

#[tokio::test]
async fn test_init_tree_empty_db() {
    let test_db = create_unique_test_db().await;
    let cache_path = temp_cache_path();

    let tree_state = unsafe { init_tree(test_db.db(), &cache_path, 6).await.unwrap() };

    let expected = unsafe { TreeState::new_empty(6, temp_cache_path()) }.unwrap();
    assert_eq!(tree_state.root().await, expected.root().await);

    cleanup(&cache_path);
}

// ============================================================================
// Tree Restoration tests
// ============================================================================

/// When clean metadata no longer matches the cached tree, init rebuilds from sync_log.
#[tokio::test]
async fn test_stale_cache_rebuilds_from_sync_log() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    let first_root = root_for_leaves(6, &[(1, U256::from(100))]).await;
    let checkpoint_id = seed_forward_batch(
        db,
        first_root,
        2,
        &[(1, Some(U256::from(100)))],
    )
    .await
    .unwrap();

    let tree_state = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    drop(tree_state);

    let updated_root = root_for_leaves(6, &[(1, U256::from(400))]).await;
    seed_forward_batch(
        db,
        updated_root,
        2,
        &[(1, Some(U256::from(400)))],
    )
    .await
    .unwrap();

    world_id_indexer::tree::cache_metadata::write_clean_metadata(&cache_path, 6, checkpoint_id)
        .unwrap();

    let rebuilt = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    assert_eq!(rebuilt.root().await, updated_root);
    assert_eq!(rebuilt.get_leaf(1).await, U256::from(400));

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

    let tree_state = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };

    let count = sync_from_db(db, &tree_state).await.unwrap();
    assert_eq!(count, 0);

    cleanup(&cache_path);
}

/// Test 13: sync_from_db deduplicates multiple sync_log rows for the same leaf.
#[tokio::test]
async fn test_sync_from_db_deduplication() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    let tree_state = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };

    let expected_root = root_for_leaves(6, &[(1, U256::from(400))]).await;
    seed_forward_batch(
        db,
        expected_root,
        2,
        &[
            (1, Some(U256::from(100))),
            (1, Some(U256::from(200))),
            (1, Some(U256::from(400))),
        ],
    )
    .await
    .unwrap();

    let count = sync_from_db(db, &tree_state).await.unwrap();
    assert_eq!(
        count, 3,
        "all leaf changes in the batch should be counted"
    );

    let tree = tree_state.read().await;
    assert_eq!(
        tree.get_leaf(1),
        U256::from(400),
        "only the final commitment should remain"
    );

    cleanup(&cache_path);
}

// ============================================================================
// handle_registry_event root validation tests
// ============================================================================

/// handle_registry_event returns ReorgDetected when the simulated batch root
/// does not match the RootRecorded event.
#[tokio::test]
async fn test_handle_registry_event_root_mismatch() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    // Create an account so the tree has a non-empty leaf
    insert_test_account(db, 1, Address::ZERO, U256::from(100))
        .await
        .unwrap();

    let tree_state = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };

    // Simulate a batch: AccountCreated event followed by RootRecorded.
    // The RootRecorded root is bogus — it won't match the tree root after sync.
    let mut committer = EventsCommitter::new(db, tree_state);

    let create_event = BlockchainEvent {
        block_number: 50,
        block_hash: U256::from(150),
        tx_hash: U256::from(50),
        log_index: 0,
        details: RegistryEvent::AccountCreated(AccountCreatedEvent {
            leaf_index: 2,
            recovery_address: Address::ZERO,
            authenticator_addresses: vec![],
            authenticator_pubkeys: vec![],
            offchain_signer_commitment: U256::from(200),
        }),
    };

    let root_event = BlockchainEvent {
        block_number: 50,
        block_hash: U256::from(150),
        tx_hash: U256::from(50),
        log_index: 1,
        details: RegistryEvent::RootRecorded(RootRecordedEvent {
            root: U256::from(999), // bogus root — won't match tree
            timestamp: U256::ZERO,
        }),
    };

    // Process the create event (just buffers, no commit)
    let result = handle_registry_event(&mut committer, create_event).await;
    assert!(result.is_ok());

    // Process the root event — triggers commit + sync + root check
    let result = handle_registry_event(&mut committer, root_event).await;
    assert!(
        result.is_err(),
        "should fail because tree root doesn't match any DB root"
    );

    cleanup(&cache_path);
}

/// handle_registry_event succeeds when tree root matches a known root after sync.
#[tokio::test]
async fn test_handle_registry_event_root_match() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    let tree_state = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };

    // Build a temporary tree to compute the expected root after inserting leaf 1
    let tmp_path = temp_cache_path();
    let expected_tree = unsafe { TreeState::new_empty(6, &tmp_path) }.unwrap();
    expected_tree
        .set_leaf_at_index(1, U256::from(100))
        .await
        .unwrap();
    let expected_root = expected_tree.root().await;
    cleanup(&tmp_path);

    let mut committer = EventsCommitter::new(db, tree_state);

    let create_event = BlockchainEvent {
        block_number: 50,
        block_hash: U256::from(150),
        tx_hash: U256::from(50),
        log_index: 0,
        details: RegistryEvent::AccountCreated(AccountCreatedEvent {
            leaf_index: 1,
            recovery_address: Address::ZERO,
            authenticator_addresses: vec![],
            authenticator_pubkeys: vec![],
            offchain_signer_commitment: U256::from(100),
        }),
    };

    let root_event = BlockchainEvent {
        block_number: 50,
        block_hash: U256::from(150),
        tx_hash: U256::from(50),
        log_index: 1,
        details: RegistryEvent::RootRecorded(RootRecordedEvent {
            root: expected_root,
            timestamp: U256::ZERO,
        }),
    };

    let result = handle_registry_event(&mut committer, create_event).await;
    assert!(result.is_ok());

    let result = handle_registry_event(&mut committer, root_event).await;
    assert!(
        result.is_ok(),
        "should succeed because tree root matches a known DB root, got: {:?}",
        result.err()
    );

    cleanup(&cache_path);
}

// ============================================================================
// init_tree error propagation tests
// ============================================================================

/// init_tree rebuilds when cache and metadata exist but mmap storage is invalid.
#[tokio::test]
async fn test_init_tree_restore_failure_rebuilds() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    let expected_root = root_for_leaves(6, &[(1, U256::from(100))]).await;
    let checkpoint_id = seed_forward_batch(
        db,
        expected_root,
        2,
        &[(1, Some(U256::from(100)))],
    )
    .await
    .unwrap();

    fs::write(&cache_path, b"not a valid mmap file").unwrap();
    world_id_indexer::tree::cache_metadata::write_clean_metadata(&cache_path, 6, checkpoint_id)
        .unwrap();

    let tree_state = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    assert_eq!(tree_state.root().await, expected_root);
    assert!(cache_path.exists());
    assert!(metadata_path(&cache_path).exists());

    cleanup(&cache_path);
}

/// After init_tree rebuilds from invalid cache, a subsequent restore succeeds.
#[tokio::test]
async fn test_init_tree_recovers_after_cache_rebuild() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    let expected_root = root_for_leaves(6, &[(1, U256::from(100))]).await;
    seed_forward_batch(
        db,
        expected_root,
        2,
        &[(1, Some(U256::from(100)))],
    )
    .await
    .unwrap();

    fs::write(&cache_path, b"corrupted").unwrap();
    let first = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    assert_eq!(first.root().await, expected_root);

    let second = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    assert_eq!(second.root().await, expected_root);

    cleanup(&cache_path);
}
