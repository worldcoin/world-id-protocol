mod helpers;

use alloy::primitives::{Address, U256};
use helpers::db_helpers::*;
use helpers::mock_blockchain::*;
use serial_test::serial;
use world_id_indexer::events_committer::EventsCommitter;

/// Test that events are properly buffered and committed
#[tokio::test]
#[serial]
async fn test_events_are_buffered_and_committed() {
    let (db, db_name) = create_unique_test_db().await;

    let mut committer = EventsCommitter::new(&db);

    // Create AccountCreated event
    let event1 = mock_account_created_event(100, 0, U256::from(1), Address::ZERO, U256::from(123));

    // Create AccountUpdated event
    let event2 = mock_account_updated_event(
        100,
        1,
        U256::from(1),
        0,
        Address::ZERO,
        U256::from(456),
        U256::from(123),
        U256::from(789),
    );

    // Create RootRecorded event (triggers commit)
    let event3 = mock_root_recorded_event(100, 2, U256::from(999), U256::from(1000));

    // Handle events
    committer.handle_event(event1).await.unwrap();
    committer.handle_event(event2).await.unwrap();

    // Before RootRecorded, nothing should be committed
    let count = count_accounts(db.pool()).await.unwrap();
    assert_eq!(count, 0, "Events should be buffered, not committed yet");

    // Handle RootRecorded - should trigger commit
    committer.handle_event(event3).await.unwrap();

    // Now events should be committed
    let account_count = count_accounts(db.pool()).await.unwrap();
    assert_eq!(account_count, 1, "Account should be created and committed");

    let event_count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(event_count, 2, "Two world tree events should be committed");

    let root_count = count_world_tree_roots(db.pool()).await.unwrap();
    assert_eq!(root_count, 1, "Root event should be committed");

    cleanup_test_db(&db_name).await;
}

/// Test idempotency - processing same event twice should not create duplicates
#[tokio::test]
#[serial]
async fn test_event_idempotency() {
    let (db, db_name) = create_unique_test_db().await;

    let mut committer = EventsCommitter::new(&db);

    // Create the same event twice
    let event1 = mock_account_created_event(100, 0, U256::from(1), Address::ZERO, U256::from(123));
    let event2 = mock_account_created_event(100, 0, U256::from(1), Address::ZERO, U256::from(123));
    let root_event = mock_root_recorded_event(100, 1, U256::from(999), U256::from(1000));

    // Process first event
    committer.handle_event(event1).await.unwrap();
    committer.handle_event(root_event.clone()).await.unwrap();

    // Verify one account was created
    let count = count_accounts(db.pool()).await.unwrap();
    assert_eq!(count, 1);

    // Create new committer and process same event again
    let mut committer2 = EventsCommitter::new(&db);
    committer2.handle_event(event2).await.unwrap();
    committer2.handle_event(root_event).await.unwrap();

    // Should still be only one account (idempotent)
    let count = count_accounts(db.pool()).await.unwrap();
    assert_eq!(
        count, 1,
        "Duplicate event should not create duplicate account"
    );

    cleanup_test_db(&db_name).await;
}

/// Test that AccountUpdated event properly updates an existing account
#[tokio::test]
#[serial]
async fn test_account_update_modifies_existing_account() {
    let (db, db_name) = create_unique_test_db().await;

    let mut committer = EventsCommitter::new(&db);

    let leaf_index = U256::from(1);
    let initial_commitment = U256::from(123);
    let updated_commitment = U256::from(456);

    // Create account
    let create_event =
        mock_account_created_event(100, 0, leaf_index, Address::ZERO, initial_commitment);
    let update_event = mock_account_updated_event(
        100,
        1,
        leaf_index,
        0,
        Address::ZERO,
        U256::from(789),
        initial_commitment,
        updated_commitment,
    );
    let root_event = mock_root_recorded_event(100, 2, U256::from(999), U256::from(1000));

    committer.handle_event(create_event).await.unwrap();
    committer.handle_event(update_event).await.unwrap();
    committer.handle_event(root_event).await.unwrap();

    // Verify account exists (was updated)
    let exists = account_exists(db.pool(), leaf_index).await.unwrap();
    assert!(exists, "Account should exist after update");

    cleanup_test_db(&db_name).await;
}

/// Test that multiple batches of events can be processed
#[tokio::test]
#[serial]
async fn test_multiple_event_batches() {
    let (db, db_name) = create_unique_test_db().await;

    let mut committer = EventsCommitter::new(&db);

    // First batch
    let event1 = mock_account_created_event(100, 0, U256::from(1), Address::ZERO, U256::from(100));
    let root1 = mock_root_recorded_event(100, 1, U256::from(500), U256::from(1000));

    committer.handle_event(event1).await.unwrap();
    committer.handle_event(root1).await.unwrap();

    // Second batch
    let event2 = mock_account_created_event(101, 0, U256::from(2), Address::ZERO, U256::from(200));
    let root2 = mock_root_recorded_event(101, 1, U256::from(600), U256::from(2000));

    committer.handle_event(event2).await.unwrap();
    committer.handle_event(root2).await.unwrap();

    // Verify both accounts were created
    let count = count_accounts(db.pool()).await.unwrap();
    assert_eq!(count, 2, "Both batches should be committed");

    let root_count = count_world_tree_roots(db.pool()).await.unwrap();
    assert_eq!(root_count, 2, "Both roots should be committed");

    cleanup_test_db(&db_name).await;
}

/// Test AuthenticatorInserted event
#[tokio::test]
#[serial]
async fn test_authenticator_inserted() {
    let (db, db_name) = create_unique_test_db().await;

    let mut committer = EventsCommitter::new(&db);

    let leaf_index = U256::from(1);
    let create_event =
        mock_account_created_event(100, 0, leaf_index, Address::ZERO, U256::from(100));
    let insert_event = mock_authenticator_inserted_event(
        100,
        1,
        leaf_index,
        0,
        Address::ZERO,
        U256::from(200),
        U256::from(100),
        U256::from(300),
    );
    let root_event = mock_root_recorded_event(100, 2, U256::from(999), U256::from(1000));

    committer.handle_event(create_event).await.unwrap();
    committer.handle_event(insert_event).await.unwrap();
    committer.handle_event(root_event).await.unwrap();

    // Verify events were recorded
    let event_count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(
        event_count, 2,
        "AccountCreated and AuthenticatorInserted should be recorded"
    );

    cleanup_test_db(&db_name).await;
}

/// Test AuthenticatorRemoved event
#[tokio::test]
#[serial]
async fn test_authenticator_removed() {
    let (db, db_name) = create_unique_test_db().await;

    let mut committer = EventsCommitter::new(&db);

    let leaf_index = U256::from(1);
    let create_event =
        mock_account_created_event(100, 0, leaf_index, Address::ZERO, U256::from(100));
    let remove_event = mock_authenticator_removed_event(
        100,
        1,
        leaf_index,
        0,
        Address::ZERO,
        U256::from(200),
        U256::from(100),
        U256::from(300),
    );
    let root_event = mock_root_recorded_event(100, 2, U256::from(999), U256::from(1000));

    committer.handle_event(create_event).await.unwrap();
    committer.handle_event(remove_event).await.unwrap();
    committer.handle_event(root_event).await.unwrap();

    // Verify events were recorded
    let event_count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(
        event_count, 2,
        "AccountCreated and AuthenticatorRemoved should be recorded"
    );

    cleanup_test_db(&db_name).await;
}

/// Test AccountRecovered event
#[tokio::test]
#[serial]
async fn test_account_recovered() {
    let (db, db_name) = create_unique_test_db().await;

    let mut committer = EventsCommitter::new(&db);

    let leaf_index = U256::from(1);
    let create_event =
        mock_account_created_event(100, 0, leaf_index, Address::ZERO, U256::from(100));
    let recover_event = mock_account_recovered_event(
        100,
        1,
        leaf_index,
        Address::ZERO,
        U256::from(200),
        U256::from(100),
        U256::from(300),
    );
    let root_event = mock_root_recorded_event(100, 2, U256::from(999), U256::from(1000));

    committer.handle_event(create_event).await.unwrap();
    committer.handle_event(recover_event).await.unwrap();
    committer.handle_event(root_event).await.unwrap();

    // Verify events were recorded
    let event_count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(
        event_count, 2,
        "AccountCreated and AccountRecovered should be recorded"
    );

    cleanup_test_db(&db_name).await;
}

/// Test that transaction rollback works on error
#[tokio::test]
#[serial]
async fn test_transaction_rollback_on_error() {
    let (db, db_name) = create_unique_test_db().await;

    // Pre-insert an account with leaf_index 1
    insert_test_account(&db, U256::from(1), Address::ZERO, U256::from(500))
        .await
        .unwrap();

    let mut committer = EventsCommitter::new(&db);

    // Try to create an account that already exists (duplicate), which should cause unique constraint error
    let duplicate_create_event = mock_account_created_event(
        100,
        0,
        U256::from(1), // Same leaf_index as existing account
        Address::from([1u8; 20]),
        U256::from(789),
    );
    let root_event = mock_root_recorded_event(100, 1, U256::from(999), U256::from(1000));

    committer
        .handle_event(duplicate_create_event)
        .await
        .unwrap();
    let result = committer.handle_event(root_event).await;

    // The commit should fail due to unique constraint violation
    assert!(
        result.is_err(),
        "Transaction should fail for duplicate account creation"
    );

    // Verify no events were committed (rollback occurred)
    let event_count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(event_count, 0, "Events should be rolled back on error");

    // Original account should still exist
    let exists = account_exists(db.pool(), U256::from(1)).await.unwrap();
    assert!(exists, "Account should still exist after rollback");

    cleanup_test_db(&db_name).await;
}

/// Test buffer clearing after commit
#[tokio::test]
#[serial]
async fn test_buffer_cleared_after_commit() {
    let (db, db_name) = create_unique_test_db().await;

    let mut committer = EventsCommitter::new(&db);

    // First batch
    let event1 = mock_account_created_event(100, 0, U256::from(1), Address::ZERO, U256::from(100));
    let root1 = mock_root_recorded_event(100, 1, U256::from(500), U256::from(1000));

    committer.handle_event(event1).await.unwrap();
    committer.handle_event(root1).await.unwrap();

    // Second batch - buffer should be empty, so only this event should be committed
    let event2 = mock_account_created_event(101, 0, U256::from(2), Address::ZERO, U256::from(200));
    let root2 = mock_root_recorded_event(101, 1, U256::from(600), U256::from(2000));

    committer.handle_event(event2).await.unwrap();
    committer.handle_event(root2).await.unwrap();

    // Verify separate commits worked correctly
    let count = count_accounts(db.pool()).await.unwrap();
    assert_eq!(count, 2, "Two separate batches should create two accounts");

    cleanup_test_db(&db_name).await;
}
