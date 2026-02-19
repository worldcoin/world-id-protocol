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
    db::WorldIdRegistryEventId, events_committer::EventsCommitter,
    rollback_executor::RollbackExecutor,
};

/// Test basic rollback: delete events after a specific point
#[tokio::test]
async fn test_basic_rollback_deletes_events_after_point() {
    init_test_tracing();
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db);

    // Create a sequence of events across multiple blocks
    let event1 = mock_account_created_event(100, 0, 1, Address::ZERO, U256::from(100));
    let root1 = mock_root_recorded_event(100, 1, U256::from(1000), U256::from(100));

    let event2 = mock_account_created_event(101, 0, 2, Address::ZERO, U256::from(200));
    let root2 = mock_root_recorded_event(101, 1, U256::from(2000), U256::from(101));

    let event3 = mock_account_created_event(102, 0, 3, Address::ZERO, U256::from(300));
    let root3 = mock_root_recorded_event(102, 1, U256::from(3000), U256::from(102));

    // Process all events
    committer.handle_event(event1).await.unwrap();
    committer.handle_event(root1).await.unwrap();
    committer.handle_event(event2).await.unwrap();
    committer.handle_event(root2).await.unwrap();
    committer.handle_event(event3).await.unwrap();
    committer.handle_event(root3).await.unwrap();

    // Verify all data is present
    assert_account_count(db.pool(), 3).await;
    assert_event_count(db.pool(), 3).await;
    assert_root_count(db.pool(), 3).await;

    // Rollback to block 101, log_index 1 (should keep first two blocks, remove third)
    let rollback_point = WorldIdRegistryEventId {
        block_number: 101,
        log_index: 1,
    };

    let mut executor = RollbackExecutor::new(db);
    executor.rollback_to_event(rollback_point).await.unwrap();

    // Verify data after rollback
    assert_account_count(db.pool(), 2).await;
    assert_event_count(db.pool(), 2).await;
    assert_root_count(db.pool(), 2).await;

    // Verify specific accounts
    assert_account_exists(db.pool(), 1).await;
    assert_account_exists(db.pool(), 2).await;
    assert_account_not_exists(db.pool(), 3).await;
}

/// Test rollback within same block (using log_index)
#[tokio::test]
async fn test_rollback_within_same_block() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db);

    // Create multiple events in the same block
    let event1 = mock_account_created_event(100, 0, 1, Address::ZERO, U256::from(100));
    let event2 = mock_account_created_event(100, 1, 2, Address::ZERO, U256::from(200));
    let event3 = mock_account_created_event(100, 2, 3, Address::ZERO, U256::from(300));
    let root = mock_root_recorded_event(100, 3, U256::from(1000), U256::from(100));

    // Process all events
    committer.handle_event(event1).await.unwrap();
    committer.handle_event(event2).await.unwrap();
    committer.handle_event(event3).await.unwrap();
    committer.handle_event(root).await.unwrap();

    // Verify all data is present
    assert_account_count(db.pool(), 3).await;
    assert_event_count(db.pool(), 3).await;

    // Rollback to log_index 1 within block 100 (keep events 0 and 1, remove 2)
    let rollback_point = WorldIdRegistryEventId {
        block_number: 100,
        log_index: 1,
    };

    let mut executor = RollbackExecutor::new(db);
    executor.rollback_to_event(rollback_point).await.unwrap();

    // Verify data after rollback
    assert_account_count(db.pool(), 2).await;
    assert_event_count(db.pool(), 2).await;
    assert_root_count(db.pool(), 0).await; // Root was at log_index 3, so it's removed

    // Verify specific accounts
    assert_account_exists(db.pool(), 1).await;
    assert_account_exists(db.pool(), 2).await;
    assert_account_not_exists(db.pool(), 3).await;
}

/// Test rollback removes all data when rolling back to before first event
#[tokio::test]
async fn test_rollback_to_genesis() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db);

    // Create some events
    let event1 = mock_account_created_event(100, 0, 1, Address::ZERO, U256::from(100));
    let root1 = mock_root_recorded_event(100, 1, U256::from(1000), U256::from(100));

    committer.handle_event(event1).await.unwrap();
    committer.handle_event(root1).await.unwrap();

    // Verify data is present
    assert_account_count(db.pool(), 1).await;
    assert_event_count(db.pool(), 1).await;
    assert_root_count(db.pool(), 1).await;

    // Rollback to before all events (block 99)
    let rollback_point = WorldIdRegistryEventId {
        block_number: 99,
        log_index: 0,
    };

    let mut executor = RollbackExecutor::new(db);
    executor.rollback_to_event(rollback_point).await.unwrap();

    // Verify all data is removed
    assert_account_count(db.pool(), 0).await;
    assert_event_count(db.pool(), 0).await;
    assert_root_count(db.pool(), 0).await;
}

/// Test rollback with account updates - only accounts modified after rollback point are removed
#[tokio::test]
async fn test_rollback_with_account_updates() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db);

    // Create account at block 100
    let event1 = mock_account_created_event_with_authenticators(
        100,
        0,
        1,
        Address::ZERO,
        vec![Address::from([1u8; 20])],
        vec![U256::from(111)],
        U256::from(100),
    );
    let root1 = mock_root_recorded_event(100, 1, U256::from(1000), U256::from(100));

    // Update account at block 101
    let event2 = mock_account_updated_event(
        101,
        0,
        1,
        0,
        Address::from([2u8; 20]),
        U256::from(222),
        U256::from(100),
        U256::from(200),
    );
    let root2 = mock_root_recorded_event(101, 1, U256::from(2000), U256::from(101));

    // Create another account at block 102
    let event3 = mock_account_created_event(102, 0, 2, Address::ZERO, U256::from(300));
    let root3 = mock_root_recorded_event(102, 1, U256::from(3000), U256::from(102));

    // Process all events
    committer.handle_event(event1).await.unwrap();
    committer.handle_event(root1).await.unwrap();
    committer.handle_event(event2).await.unwrap();
    committer.handle_event(root2).await.unwrap();
    committer.handle_event(event3).await.unwrap();
    committer.handle_event(root3).await.unwrap();

    // Verify all data is present
    assert_account_count(db.pool(), 2).await;
    assert_event_count(db.pool(), 3).await;

    // Rollback to block 101, log_index 1
    // This should remove:
    // - Account 2 (because it was created at block 102)
    let rollback_point = WorldIdRegistryEventId {
        block_number: 101,
        log_index: 1,
    };

    let mut executor = RollbackExecutor::new(db);
    executor.rollback_to_event(rollback_point).await.unwrap();

    // After rollback:
    // - Account 1 should EXIST with updated state (events at 100,0 and 101,0 are both kept)
    // - Account 2 should be removed (created at 102, which is after 101,1)
    // - Events at block 102 should be removed
    // - Root at block 102 should be removed
    assert_account_count(db.pool(), 1).await;
    assert_event_count(db.pool(), 2).await;
    assert_root_count(db.pool(), 2).await;

    // Verify Account 1 exists with the updated authenticator
    let account = db
        .accounts()
        .get_account(1)
        .await
        .unwrap()
        .expect("Account 1 should exist");
    assert_eq!(account.authenticator_addresses.len(), 1);
    assert_eq!(
        account.authenticator_addresses[0],
        Some(Address::from([2u8; 20]))
    );
}

/// Test rollback doesn't affect accounts modified before the rollback point
#[tokio::test]
async fn test_rollback_preserves_old_accounts() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db);

    // Create account 1 at block 100
    let event1 = mock_account_created_event(100, 0, 1, Address::ZERO, U256::from(100));
    let root1 = mock_root_recorded_event(100, 1, U256::from(1000), U256::from(100));

    // Create account 2 at block 101
    let event2 = mock_account_created_event(101, 0, 2, Address::ZERO, U256::from(200));
    let root2 = mock_root_recorded_event(101, 1, U256::from(2000), U256::from(101));

    // Create account 3 at block 102
    let event3 = mock_account_created_event(102, 0, 3, Address::ZERO, U256::from(300));
    let root3 = mock_root_recorded_event(102, 1, U256::from(3000), U256::from(102));

    // Process all events
    committer.handle_event(event1).await.unwrap();
    committer.handle_event(root1).await.unwrap();
    committer.handle_event(event2).await.unwrap();
    committer.handle_event(root2).await.unwrap();
    committer.handle_event(event3).await.unwrap();
    committer.handle_event(root3).await.unwrap();

    // Verify all data is present
    assert_account_count(db.pool(), 3).await;

    // Rollback to block 101, log_index 1 (keep blocks 100 and 101)
    let rollback_point = WorldIdRegistryEventId {
        block_number: 101,
        log_index: 1,
    };

    let mut executor = RollbackExecutor::new(db);
    executor.rollback_to_event(rollback_point).await.unwrap();

    // Verify accounts 1 and 2 are preserved, account 3 is removed
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

    let mut committer = EventsCommitter::new(db);

    // Block 100: Create account 1
    let event1 = mock_account_created_event_with_authenticators(
        100,
        0,
        1,
        Address::ZERO,
        vec![Address::from([1u8; 20])],
        vec![U256::from(111)],
        U256::from(100),
    );
    let root1 = mock_root_recorded_event(100, 1, U256::from(1000), U256::from(100));

    // Block 101: Insert authenticator for account 1
    let event2 = mock_authenticator_inserted_event(
        101,
        0,
        1,
        1,
        Address::from([2u8; 20]),
        U256::from(222),
        U256::from(100),
        U256::from(200),
    );
    let root2 = mock_root_recorded_event(101, 1, U256::from(2000), U256::from(101));

    // Block 102: Recover account 1
    let event3 = mock_account_recovered_event(
        102,
        0,
        1,
        Address::from([3u8; 20]),
        U256::from(333),
        U256::from(200),
        U256::from(300),
    );
    let root3 = mock_root_recorded_event(102, 1, U256::from(3000), U256::from(102));

    // Process all events
    committer.handle_event(event1).await.unwrap();
    committer.handle_event(root1).await.unwrap();
    committer.handle_event(event2).await.unwrap();
    committer.handle_event(root2).await.unwrap();
    committer.handle_event(event3).await.unwrap();
    committer.handle_event(root3).await.unwrap();

    // Verify data
    assert_account_count(db.pool(), 1).await;
    assert_event_count(db.pool(), 3).await;
    assert_root_count(db.pool(), 3).await;

    eprintln!("Before rollback:");
    eprintln!("  Accounts: 1");
    eprintln!("  Events: 3");
    eprintln!("  Roots: 3");

    // Rollback to block 101, log_index 1 (before recovery)
    let rollback_point = WorldIdRegistryEventId {
        block_number: 101,
        log_index: 1,
    };

    let mut executor = RollbackExecutor::new(db);
    executor.rollback_to_event(rollback_point).await.unwrap();

    // Account should EXIST with state after authenticator insertion (at block 101)
    // Recovery event at block 102 should be removed
    // Events and roots after block 101, log_index 1 should be removed
    assert_account_count(db.pool(), 1).await;
    assert_event_count(db.pool(), 2).await;
    assert_root_count(db.pool(), 2).await;

    // Verify Account 1 exists with 2 authenticators (original + inserted)
    let account = db
        .accounts()
        .get_account(1)
        .await
        .unwrap()
        .expect("Account 1 should exist");

    eprintln!(
        "Account authenticator_addresses: {:?}",
        account.authenticator_addresses
    );
    eprintln!(
        "Account authenticator_pubkeys: {:?}",
        account.authenticator_pubkeys
    );

    assert_eq!(
        account.authenticator_addresses.len(),
        2,
        "Expected 2 authenticators"
    );
    assert_eq!(
        account.authenticator_addresses[0],
        Some(Address::from([1u8; 20]))
    );
    assert_eq!(
        account.authenticator_addresses[1],
        Some(Address::from([2u8; 20]))
    );
}

/// Test that rollback to current state has no effect
#[tokio::test]
async fn test_rollback_to_current_state_no_op() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db);

    // Create account
    let event1 = mock_account_created_event(100, 0, 1, Address::ZERO, U256::from(100));
    let root1 = mock_root_recorded_event(100, 1, U256::from(1000), U256::from(100));

    committer.handle_event(event1).await.unwrap();
    committer.handle_event(root1).await.unwrap();

    // Verify data
    assert_account_count(db.pool(), 1).await;
    assert_event_count(db.pool(), 1).await;
    assert_root_count(db.pool(), 1).await;

    // Rollback to the latest event (should be no-op)
    let rollback_point = WorldIdRegistryEventId {
        block_number: 100,
        log_index: 1,
    };

    let mut executor = RollbackExecutor::new(db);
    executor.rollback_to_event(rollback_point).await.unwrap();

    // Verify data unchanged
    assert_account_count(db.pool(), 1).await;
    assert_event_count(db.pool(), 1).await;
    assert_root_count(db.pool(), 1).await;
}

/// Test rollback with empty database
#[tokio::test]
async fn test_rollback_empty_database() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    // Verify database is empty
    assert_account_count(db.pool(), 0).await;
    assert_event_count(db.pool(), 0).await;
    assert_root_count(db.pool(), 0).await;

    // Try to rollback (should succeed with no effect)
    let rollback_point = WorldIdRegistryEventId {
        block_number: 100,
        log_index: 0,
    };

    let mut executor = RollbackExecutor::new(db);
    executor.rollback_to_event(rollback_point).await.unwrap();

    // Verify database still empty
    assert_account_count(db.pool(), 0).await;
    assert_event_count(db.pool(), 0).await;
    assert_root_count(db.pool(), 0).await;
}

/// Test rollback correctly identifies affected leaf indices
#[tokio::test]
async fn test_rollback_identifies_affected_leaves() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db);

    // Create 5 accounts across different blocks
    let events = vec![
        (
            mock_account_created_event(100, 0, 1, Address::ZERO, U256::from(100)),
            mock_root_recorded_event(100, 1, U256::from(1000), U256::from(100)),
        ),
        (
            mock_account_created_event(101, 0, 2, Address::ZERO, U256::from(200)),
            mock_root_recorded_event(101, 1, U256::from(2000), U256::from(101)),
        ),
        (
            mock_account_created_event(102, 0, 3, Address::ZERO, U256::from(300)),
            mock_root_recorded_event(102, 1, U256::from(3000), U256::from(102)),
        ),
        (
            mock_account_created_event(103, 0, 4, Address::ZERO, U256::from(400)),
            mock_root_recorded_event(103, 1, U256::from(4000), U256::from(103)),
        ),
        (
            mock_account_created_event(104, 0, 5, Address::ZERO, U256::from(500)),
            mock_root_recorded_event(104, 1, U256::from(5000), U256::from(104)),
        ),
    ];

    for (event, root) in events {
        committer.handle_event(event).await.unwrap();
        committer.handle_event(root).await.unwrap();
    }

    // Verify all accounts exist
    assert_account_count(db.pool(), 5).await;

    // Rollback to block 102, log_index 1 (keep first 3 accounts)
    let rollback_point = WorldIdRegistryEventId {
        block_number: 102,
        log_index: 1,
    };

    let mut executor = RollbackExecutor::new(db);
    executor.rollback_to_event(rollback_point).await.unwrap();

    // Verify correct accounts remain
    assert_account_count(db.pool(), 3).await;
    for i in 1..=3 {
        assert_account_exists(db.pool(), i).await;
    }
    for i in 4..=5 {
        assert_account_not_exists(db.pool(), i).await;
    }
}
