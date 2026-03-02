//! Integration tests for the rollback feature
//!
//! These tests verify the functionality of RollbackExecutor which allows
//! reverting the database state to a specific event point.
//!
//! # Running these tests
//!
//! These tests require a PostgreSQL database to be running. Use Docker Compose:
//!
//! ```bash
//! docker compose up -d postgres
//! cargo test -p world-id-indexer --test rollback_tests
//! ```
//!
//! The tests will automatically create unique test databases for isolation.

mod helpers;

use alloy::primitives::{Address, U256};
use helpers::{common::init_test_tracing, db_helpers::*, mock_blockchain::*};
use world_id_indexer::{
    db::{IsolationLevel, WorldIdRegistryEventId},
    events_committer::EventsCommitter,
    rollback_executor::rollback_to_event,
};

/// Test basic rollback: delete events after a specific point
#[tokio::test]
async fn test_basic_rollback_deletes_events_after_point() {
    init_test_tracing();
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db, make_versioned_tree());

    let event1 = mock_account_created_event(100, 0, 1, Address::ZERO, U256::from(100));
    let event2 = mock_account_created_event(101, 0, 2, Address::ZERO, U256::from(200));
    let event3 = mock_account_created_event(102, 0, 3, Address::ZERO, U256::from(300));

    let roots = compute_batch_roots(&[&[event1.clone()], &[event2.clone()], &[event3.clone()]]).await;
    let root1 = mock_root_recorded_event(100, 1, roots[0], U256::from(100));
    let root2 = mock_root_recorded_event(101, 1, roots[1], U256::from(101));
    let root3 = mock_root_recorded_event(102, 1, roots[2], U256::from(102));

    committer.handle_event(event1).await.unwrap();
    committer.handle_event(root1).await.unwrap();
    committer.handle_event(event2).await.unwrap();
    committer.handle_event(root2).await.unwrap();
    committer.handle_event(event3).await.unwrap();
    committer.handle_event(root3).await.unwrap();

    assert_account_count(db.pool(), 3).await;
    assert_event_count(db.pool(), 3).await;
    assert_root_count(db.pool(), 3).await;

    let rollback_point = WorldIdRegistryEventId { block_number: 101, log_index: 1 };
    let mut tx = db.transaction(IsolationLevel::Serializable).await.unwrap();
    rollback_to_event(&mut tx, rollback_point).await.unwrap();
    tx.commit().await.unwrap();

    assert_account_count(db.pool(), 2).await;
    assert_event_count(db.pool(), 2).await;
    assert_root_count(db.pool(), 2).await;
    assert_account_exists(db.pool(), 1).await;
    assert_account_exists(db.pool(), 2).await;
    assert_account_not_exists(db.pool(), 3).await;
}

/// Test rollback within same block (using log_index)
#[tokio::test]
async fn test_rollback_within_same_block() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db, make_versioned_tree());

    let event1 = mock_account_created_event(100, 0, 1, Address::ZERO, U256::from(100));
    let event2 = mock_account_created_event(100, 1, 2, Address::ZERO, U256::from(200));
    let event3 = mock_account_created_event(100, 2, 3, Address::ZERO, U256::from(300));

    let roots = compute_batch_roots(&[&[event1.clone(), event2.clone(), event3.clone()]]).await;
    let root = mock_root_recorded_event(100, 3, roots[0], U256::from(100));

    committer.handle_event(event1).await.unwrap();
    committer.handle_event(event2).await.unwrap();
    committer.handle_event(event3).await.unwrap();
    committer.handle_event(root).await.unwrap();

    assert_account_count(db.pool(), 3).await;
    assert_event_count(db.pool(), 3).await;

    let rollback_point = WorldIdRegistryEventId { block_number: 100, log_index: 1 };
    let mut tx = db.transaction(IsolationLevel::Serializable).await.unwrap();
    rollback_to_event(&mut tx, rollback_point).await.unwrap();
    tx.commit().await.unwrap();

    assert_account_count(db.pool(), 2).await;
    assert_event_count(db.pool(), 2).await;
    assert_root_count(db.pool(), 0).await; // Root was at log_index 3, so it's removed
    assert_account_exists(db.pool(), 1).await;
    assert_account_exists(db.pool(), 2).await;
    assert_account_not_exists(db.pool(), 3).await;
}

/// Test rollback removes all data when rolling back to before first event
#[tokio::test]
async fn test_rollback_to_genesis() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db, make_versioned_tree());

    let event1 = mock_account_created_event(100, 0, 1, Address::ZERO, U256::from(100));
    let roots = compute_batch_roots(&[&[event1.clone()]]).await;
    let root1 = mock_root_recorded_event(100, 1, roots[0], U256::from(100));

    committer.handle_event(event1).await.unwrap();
    committer.handle_event(root1).await.unwrap();

    assert_account_count(db.pool(), 1).await;
    assert_event_count(db.pool(), 1).await;
    assert_root_count(db.pool(), 1).await;

    let rollback_point = WorldIdRegistryEventId { block_number: 99, log_index: 0 };
    let mut tx = db.transaction(IsolationLevel::Serializable).await.unwrap();
    rollback_to_event(&mut tx, rollback_point).await.unwrap();
    tx.commit().await.unwrap();

    assert_account_count(db.pool(), 0).await;
    assert_event_count(db.pool(), 0).await;
    assert_root_count(db.pool(), 0).await;
}

/// Test rollback with account updates - only accounts modified after rollback point are removed
#[tokio::test]
async fn test_rollback_with_account_updates() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db, make_versioned_tree());

    let event1 = mock_account_created_event_with_authenticators(
        100, 0, 1, Address::ZERO,
        vec![Address::from([1u8; 20])],
        vec![U256::from(111)],
        U256::from(100),
    );
    let event2 = mock_account_updated_event(
        101, 0, 1, 0,
        Address::from([2u8; 20]),
        U256::from(222),
        U256::from(100),
        U256::from(200),
    );
    let event3 = mock_account_created_event(102, 0, 2, Address::ZERO, U256::from(300));

    let roots = compute_batch_roots(&[
        &[event1.clone()],
        &[event2.clone()],
        &[event3.clone()],
    ]).await;
    let root1 = mock_root_recorded_event(100, 1, roots[0], U256::from(100));
    let root2 = mock_root_recorded_event(101, 1, roots[1], U256::from(101));
    let root3 = mock_root_recorded_event(102, 1, roots[2], U256::from(102));

    committer.handle_event(event1).await.unwrap();
    committer.handle_event(root1).await.unwrap();
    committer.handle_event(event2).await.unwrap();
    committer.handle_event(root2).await.unwrap();
    committer.handle_event(event3).await.unwrap();
    committer.handle_event(root3).await.unwrap();

    assert_account_count(db.pool(), 2).await;
    assert_event_count(db.pool(), 3).await;

    let rollback_point = WorldIdRegistryEventId { block_number: 101, log_index: 1 };
    let mut tx = db.transaction(IsolationLevel::Serializable).await.unwrap();
    rollback_to_event(&mut tx, rollback_point).await.unwrap();
    tx.commit().await.unwrap();

    assert_account_count(db.pool(), 1).await;
    assert_event_count(db.pool(), 2).await;
    assert_root_count(db.pool(), 2).await;

    let account = db.accounts().get_account(1).await.unwrap().expect("Account 1 should exist");
    assert_eq!(account.authenticator_addresses.len(), 1);
    assert_eq!(account.authenticator_addresses[0], Some(Address::from([2u8; 20])));
}

/// Test rollback doesn't affect accounts modified before the rollback point
#[tokio::test]
async fn test_rollback_preserves_old_accounts() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db, make_versioned_tree());

    let event1 = mock_account_created_event(100, 0, 1, Address::ZERO, U256::from(100));
    let event2 = mock_account_created_event(101, 0, 2, Address::ZERO, U256::from(200));
    let event3 = mock_account_created_event(102, 0, 3, Address::ZERO, U256::from(300));

    let roots = compute_batch_roots(&[&[event1.clone()], &[event2.clone()], &[event3.clone()]]).await;
    let root1 = mock_root_recorded_event(100, 1, roots[0], U256::from(100));
    let root2 = mock_root_recorded_event(101, 1, roots[1], U256::from(101));
    let root3 = mock_root_recorded_event(102, 1, roots[2], U256::from(102));

    committer.handle_event(event1).await.unwrap();
    committer.handle_event(root1).await.unwrap();
    committer.handle_event(event2).await.unwrap();
    committer.handle_event(root2).await.unwrap();
    committer.handle_event(event3).await.unwrap();
    committer.handle_event(root3).await.unwrap();

    assert_account_count(db.pool(), 3).await;

    let rollback_point = WorldIdRegistryEventId { block_number: 101, log_index: 1 };
    let mut tx = db.transaction(IsolationLevel::Serializable).await.unwrap();
    rollback_to_event(&mut tx, rollback_point).await.unwrap();
    tx.commit().await.unwrap();

    assert_account_count(db.pool(), 2).await;
    assert_account_exists(db.pool(), 1).await;
    assert_account_exists(db.pool(), 2).await;
    assert_account_not_exists(db.pool(), 3).await;
}

/// Test rollback with multiple account types (created, updated, recovered)
#[tokio::test]
async fn test_rollback_with_mixed_event_types() {
    init_test_tracing();
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db, make_versioned_tree());

    let event1 = mock_account_created_event_with_authenticators(
        100, 0, 1, Address::ZERO,
        vec![Address::from([1u8; 20])],
        vec![U256::from(111)],
        U256::from(100),
    );
    let event2 = mock_authenticator_inserted_event(
        101, 0, 1, 1,
        Address::from([2u8; 20]),
        U256::from(222),
        U256::from(100),
        U256::from(200),
    );
    let event3 = mock_account_recovered_event(
        102, 0, 1,
        Address::from([3u8; 20]),
        U256::from(333),
        U256::from(200),
        U256::from(300),
    );

    let roots = compute_batch_roots(&[
        &[event1.clone()],
        &[event2.clone()],
        &[event3.clone()],
    ]).await;
    let root1 = mock_root_recorded_event(100, 1, roots[0], U256::from(100));
    let root2 = mock_root_recorded_event(101, 1, roots[1], U256::from(101));
    let root3 = mock_root_recorded_event(102, 1, roots[2], U256::from(102));

    committer.handle_event(event1).await.unwrap();
    committer.handle_event(root1).await.unwrap();
    committer.handle_event(event2).await.unwrap();
    committer.handle_event(root2).await.unwrap();
    committer.handle_event(event3).await.unwrap();
    committer.handle_event(root3).await.unwrap();

    assert_account_count(db.pool(), 1).await;
    assert_event_count(db.pool(), 3).await;
    assert_root_count(db.pool(), 3).await;

    let rollback_point = WorldIdRegistryEventId { block_number: 101, log_index: 1 };
    let mut tx = db.transaction(IsolationLevel::Serializable).await.unwrap();
    rollback_to_event(&mut tx, rollback_point).await.unwrap();
    tx.commit().await.unwrap();

    assert_account_count(db.pool(), 1).await;
    assert_event_count(db.pool(), 2).await;
    assert_root_count(db.pool(), 2).await;

    let account = db.accounts().get_account(1).await.unwrap().expect("Account 1 should exist");
    assert_eq!(account.authenticator_addresses.len(), 2, "Expected 2 authenticators");
    assert_eq!(account.authenticator_addresses[0], Some(Address::from([1u8; 20])));
    assert_eq!(account.authenticator_addresses[1], Some(Address::from([2u8; 20])));
}

/// Test that rollback to current state has no effect
#[tokio::test]
async fn test_rollback_to_current_state_no_op() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db, make_versioned_tree());

    let event1 = mock_account_created_event(100, 0, 1, Address::ZERO, U256::from(100));
    let roots = compute_batch_roots(&[&[event1.clone()]]).await;
    let root1 = mock_root_recorded_event(100, 1, roots[0], U256::from(100));

    committer.handle_event(event1).await.unwrap();
    committer.handle_event(root1).await.unwrap();

    assert_account_count(db.pool(), 1).await;
    assert_event_count(db.pool(), 1).await;
    assert_root_count(db.pool(), 1).await;

    let rollback_point = WorldIdRegistryEventId { block_number: 100, log_index: 1 };
    let mut tx = db.transaction(IsolationLevel::Serializable).await.unwrap();
    rollback_to_event(&mut tx, rollback_point).await.unwrap();
    tx.commit().await.unwrap();

    assert_account_count(db.pool(), 1).await;
    assert_event_count(db.pool(), 1).await;
    assert_root_count(db.pool(), 1).await;
}

/// Test rollback with empty database
#[tokio::test]
async fn test_rollback_empty_database() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    assert_account_count(db.pool(), 0).await;
    assert_event_count(db.pool(), 0).await;
    assert_root_count(db.pool(), 0).await;

    let rollback_point = WorldIdRegistryEventId { block_number: 100, log_index: 0 };
    let mut tx = db.transaction(IsolationLevel::Serializable).await.unwrap();
    rollback_to_event(&mut tx, rollback_point).await.unwrap();
    tx.commit().await.unwrap();

    assert_account_count(db.pool(), 0).await;
    assert_event_count(db.pool(), 0).await;
    assert_root_count(db.pool(), 0).await;
}

/// Test rollback correctly identifies affected leaf indices
#[tokio::test]
async fn test_rollback_identifies_affected_leaves() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db, make_versioned_tree());

    let ev: Vec<_> = (1u64..=5)
        .map(|i| mock_account_created_event(99 + i, 0, i, Address::ZERO, U256::from(i * 100)))
        .collect();

    let batches: Vec<&[_]> = ev.iter().map(|e| std::slice::from_ref(e)).collect();
    let roots = compute_batch_roots(&batches).await;

    for (i, event) in ev.into_iter().enumerate() {
        let block = 100 + i as u64;
        let root = mock_root_recorded_event(block, 1, roots[i], U256::from(block));
        committer.handle_event(event).await.unwrap();
        committer.handle_event(root).await.unwrap();
    }

    assert_account_count(db.pool(), 5).await;

    let rollback_point = WorldIdRegistryEventId { block_number: 102, log_index: 1 };
    let mut tx = db.transaction(IsolationLevel::Serializable).await.unwrap();
    rollback_to_event(&mut tx, rollback_point).await.unwrap();
    tx.commit().await.unwrap();

    assert_account_count(db.pool(), 3).await;
    for i in 1..=3 {
        assert_account_exists(db.pool(), i).await;
    }
    for i in 4..=5 {
        assert_account_not_exists(db.pool(), i).await;
    }
}
