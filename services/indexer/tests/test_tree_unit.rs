#![cfg(feature = "integration-tests")]

mod helpers;

use std::{fs, path::PathBuf};

use alloy::primitives::{Address, U256};
use helpers::db_helpers::{
    create_unique_test_db, insert_test_account, insert_test_world_tree_event,
    insert_test_world_tree_root,
};
use world_id_indexer::{
    blockchain::{
        AccountCreatedEvent, AccountUpdatedEvent, BlockchainEvent, RegistryEvent, RootRecordedEvent,
    },
    events_committer::EventsCommitter,
    handle_registry_event,
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

/// When the cached root is not in world_tree_roots (stale), init_tree
/// returns an error and deletes the cache file.
#[tokio::test]
async fn test_stale_cache_returns_error() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    // First init: builds cache from one account
    insert_test_account(db, 1, Address::ZERO, U256::from(100))
        .await
        .unwrap();

    let tree_state = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    drop(tree_state);
    assert!(cache_path.exists());

    // Second init: cache root is NOT in world_tree_roots → StaleCache → error
    let result = unsafe { init_tree(db, &cache_path, 6).await };
    assert!(
        result.is_err(),
        "init_tree should fail when cache root is not in DB"
    );

    // Cache file should have been deleted
    assert!(
        !cache_path.exists(),
        "cache file should be deleted on restore failure"
    );

    cleanup(&cache_path);
}

/// Test 9: Replay with zero new events — cache is already up-to-date.
#[tokio::test]
async fn test_replay_with_no_new_events() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    // Insert account + matching event
    insert_test_account(db, 1, Address::ZERO, U256::from(100))
        .await
        .unwrap();
    insert_test_world_tree_event(
        db,
        &BlockchainEvent {
            block_number: 10,
            block_hash: U256::from(11),
            tx_hash: U256::from(1),
            log_index: 0,
            details: RegistryEvent::AccountCreated(AccountCreatedEvent {
                leaf_index: 1,
                recovery_address: Address::ZERO,
                authenticator_addresses: vec![],
                authenticator_pubkeys: vec![],
                offchain_signer_commitment: U256::from(100),
            }),
        },
    )
    .await
    .unwrap();

    // Build cache
    let tree_state = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    let root = tree_state.root().await;
    drop(tree_state);

    // Record the cache root so try_restore can validate it.
    // Place the root AFTER the latest event (at log_index 1) so
    // replay_events finds nothing after it.
    insert_test_world_tree_root(db, 10, 1, root, U256::ZERO)
        .await
        .unwrap();

    // Second init: restore from cache, replay 0 events
    let tree_state2 = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
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
    insert_test_account(db, 1, Address::ZERO, U256::from(100))
        .await
        .unwrap();
    insert_test_world_tree_event(
        db,
        &BlockchainEvent {
            block_number: 10,
            block_hash: U256::from(11),
            tx_hash: U256::from(1),
            log_index: 0,
            details: RegistryEvent::AccountCreated(AccountCreatedEvent {
                leaf_index: 1,
                recovery_address: Address::ZERO,
                authenticator_addresses: vec![],
                authenticator_pubkeys: vec![],
                offchain_signer_commitment: U256::from(100),
            }),
        },
    )
    .await
    .unwrap();

    // Build cache
    let tree_state = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
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
            &BlockchainEvent {
                block_number: block,
                block_hash: U256::from(1000 + block),
                tx_hash: U256::from(block),
                log_index: 0,
                details: RegistryEvent::AccountUpdated(AccountUpdatedEvent {
                    leaf_index: 1,
                    pubkey_id: 0,
                    new_authenticator_pubkey: U256::from(commitment),
                    old_authenticator_address: Address::ZERO,
                    new_authenticator_address: Address::ZERO,
                    old_offchain_signer_commitment: U256::ZERO,
                    new_offchain_signer_commitment: U256::from(commitment),
                }),
            },
        )
        .await
        .unwrap();
    }

    // Update account table to match final state (for potential rebuild parity)
    sqlx::query("UPDATE accounts SET offchain_signer_commitment = $1 WHERE leaf_index = $2")
        .bind(U256::from(400))
        .bind(1)
        .execute(db.pool())
        .await
        .unwrap();

    // Restore + replay should deduplicate to final value 400
    let tree_state2 = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };

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
    insert_test_account(db, 1, Address::ZERO, U256::from(100))
        .await
        .unwrap();
    insert_test_account(db, 2, Address::ZERO, U256::from(200))
        .await
        .unwrap();

    insert_test_world_tree_event(
        db,
        &BlockchainEvent {
            block_number: 10,
            block_hash: U256::from(11),
            tx_hash: U256::from(1),
            log_index: 0,
            details: RegistryEvent::AccountCreated(AccountCreatedEvent {
                leaf_index: 1,
                recovery_address: Address::ZERO,
                authenticator_addresses: vec![],
                authenticator_pubkeys: vec![],
                offchain_signer_commitment: U256::from(100),
            }),
        },
    )
    .await
    .unwrap();
    insert_test_world_tree_event(
        db,
        &BlockchainEvent {
            block_number: 10,
            block_hash: U256::from(12),
            tx_hash: U256::from(2),
            log_index: 1,
            details: RegistryEvent::AccountCreated(AccountCreatedEvent {
                leaf_index: 2,
                recovery_address: Address::ZERO,
                authenticator_addresses: vec![],
                authenticator_pubkeys: vec![],
                offchain_signer_commitment: U256::from(200),
            }),
        },
    )
    .await
    .unwrap();

    // Build cache
    let tree_state = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    let root = tree_state.root().await;
    drop(tree_state);

    // Record root
    insert_test_world_tree_root(db, 10, 2, root, U256::ZERO)
        .await
        .unwrap();

    // Events after root: update leaf 1, update leaf 2, insert leaf 3
    insert_test_world_tree_event(
        db,
        &BlockchainEvent {
            block_number: 11,
            block_hash: U256::from(111),
            tx_hash: U256::from(11),
            log_index: 0,
            details: RegistryEvent::AccountUpdated(AccountUpdatedEvent {
                leaf_index: 1,
                pubkey_id: 0,
                new_authenticator_pubkey: U256::from(300),
                old_authenticator_address: Address::ZERO,
                new_authenticator_address: Address::ZERO,
                old_offchain_signer_commitment: U256::ZERO,
                new_offchain_signer_commitment: U256::from(300),
            }),
        },
    )
    .await
    .unwrap();
    insert_test_world_tree_event(
        db,
        &BlockchainEvent {
            block_number: 11,
            block_hash: U256::from(112),
            tx_hash: U256::from(12),
            log_index: 1,
            details: RegistryEvent::AccountUpdated(AccountUpdatedEvent {
                leaf_index: 2,
                pubkey_id: 0,
                new_authenticator_pubkey: U256::from(400),
                old_authenticator_address: Address::ZERO,
                new_authenticator_address: Address::ZERO,
                old_offchain_signer_commitment: U256::ZERO,
                new_offchain_signer_commitment: U256::from(400),
            }),
        },
    )
    .await
    .unwrap();
    insert_test_world_tree_event(
        db,
        &BlockchainEvent {
            block_number: 12,
            block_hash: U256::from(113),
            tx_hash: U256::from(13),
            log_index: 0,
            details: RegistryEvent::AccountCreated(AccountCreatedEvent {
                leaf_index: 3,
                recovery_address: Address::ZERO,
                authenticator_addresses: vec![],
                authenticator_pubkeys: vec![],
                offchain_signer_commitment: U256::from(500),
            }),
        },
    )
    .await
    .unwrap();

    // Update accounts table to final state
    sqlx::query("UPDATE accounts SET offchain_signer_commitment = $1 WHERE leaf_index = $2")
        .bind(U256::from(300))
        .bind(1)
        .execute(db.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE accounts SET offchain_signer_commitment = $1 WHERE leaf_index = $2")
        .bind(U256::from(400))
        .bind(2)
        .execute(db.pool())
        .await
        .unwrap();
    insert_test_account(db, 3, Address::ZERO, U256::from(500))
        .await
        .unwrap();

    // Path A: Restore from cache + replay
    let replayed = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    let replayed_root = replayed.root().await;
    drop(replayed);

    // Path B: Fresh rebuild (delete cache first)
    cleanup(&cache_path);
    let fresh = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
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

    let tree_state = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };

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

    insert_test_account(db, 1, Address::ZERO, U256::from(100))
        .await
        .unwrap();

    // Build tree — last_synced_event_id will be (0,0) since no events exist yet
    let tree_state = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };

    // Insert 3 events for the same leaf with increasing commitments
    for (block, commitment) in [(100, 200u64), (101, 300), (102, 400)] {
        insert_test_world_tree_event(
            db,
            &BlockchainEvent {
                block_number: block,
                block_hash: U256::from(1000 + block),
                tx_hash: U256::from(block),
                log_index: 0,
                details: RegistryEvent::AccountUpdated(AccountUpdatedEvent {
                    leaf_index: 1,
                    pubkey_id: 0,
                    new_authenticator_pubkey: U256::from(commitment),
                    old_authenticator_address: Address::ZERO,
                    new_authenticator_address: Address::ZERO,
                    old_offchain_signer_commitment: U256::ZERO,
                    new_offchain_signer_commitment: U256::from(commitment),
                }),
            },
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
// handle_registry_event root validation tests
// ============================================================================

/// handle_registry_event returns RootMismatch error when tree root after sync
/// does not match any known root in world_tree_roots.
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
    let mut committer = EventsCommitter::new(db);

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
    let result = handle_registry_event(db, &mut committer, &create_event, &tree_state).await;
    assert!(result.is_ok());

    // Process the root event — triggers commit + sync + root check
    let result = handle_registry_event(db, &mut committer, &root_event, &tree_state).await;
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

    let mut committer = EventsCommitter::new(db);

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

    let result = handle_registry_event(db, &mut committer, &create_event, &tree_state).await;
    assert!(result.is_ok());

    let result = handle_registry_event(db, &mut committer, &root_event, &tree_state).await;
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

/// init_tree deletes the cache file and returns error when restore fails.
#[tokio::test]
async fn test_init_tree_restore_failure_deletes_cache() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    // Write garbage to the cache file to simulate corruption
    fs::write(&cache_path, b"not a valid mmap file").unwrap();
    assert!(cache_path.exists());

    let result = unsafe { init_tree(db, &cache_path, 6).await };
    assert!(result.is_err(), "should fail with corrupted cache");
    assert!(
        !cache_path.exists(),
        "cache file should be deleted after restore failure"
    );

    cleanup(&cache_path);
}

/// After init_tree fails and deletes cache, a subsequent call succeeds
/// by doing a fresh build from DB (the single rebuild path).
#[tokio::test]
async fn test_init_tree_recovers_after_cache_deletion() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let cache_path = temp_cache_path();

    insert_test_account(db, 1, Address::ZERO, U256::from(100))
        .await
        .unwrap();

    // First call: corrupted cache → error + cache deleted
    fs::write(&cache_path, b"corrupted").unwrap();
    let result = unsafe { init_tree(db, &cache_path, 6).await };
    assert!(result.is_err());
    assert!(!cache_path.exists());

    // Second call: no cache file → fresh build from DB
    let tree_state = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    let tree = tree_state.read().await;
    assert_eq!(tree.get_leaf(1), U256::from(100));

    cleanup(&cache_path);
}
