mod helpers;

use alloy::primitives::{Address, U256};
use helpers::{db_helpers::*, mock_blockchain::*};
use world_id_indexer::events_committer::EventsCommitter;

/// Test that events are properly buffered and committed
#[tokio::test]
async fn test_events_are_buffered_and_committed() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db);

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
}

/// Test idempotency - processing same event twice should not create duplicates
#[tokio::test]
async fn test_event_idempotency() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db);

    // Create the same event twice
    let event = mock_account_created_event(100, 0, U256::from(1), Address::ZERO, U256::from(123));
    let root_event = mock_root_recorded_event(100, 1, U256::from(999), U256::from(1000));

    // Process first event
    committer.handle_event(event.clone()).await.unwrap();
    committer.handle_event(root_event.clone()).await.unwrap();

    // Verify one account was created
    let count = count_accounts(db.pool()).await.unwrap();
    assert_eq!(count, 1);

    // Create new committer and process same event again (using clone)
    let mut committer2 = EventsCommitter::new(db);
    committer2.handle_event(event).await.unwrap();
    committer2.handle_event(root_event).await.unwrap();

    // Should still be only one account (idempotent)
    let count = count_accounts(db.pool()).await.unwrap();
    assert_eq!(
        count, 1,
        "Duplicate event should not create duplicate account"
    );
}

/// Test that AccountUpdated event properly updates an existing account
#[tokio::test]
async fn test_account_update_modifies_existing_account() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db);

    let leaf_index = U256::from(1);
    let recovery_address = Address::ZERO;
    let initial_address = Address::from([1u8; 20]);
    let initial_pubkey = U256::from(111);
    let initial_commitment = U256::from(123);

    let updated_address = Address::from([2u8; 20]);
    let updated_pubkey = U256::from(789);
    let updated_commitment = U256::from(456);

    // Create account with initial authenticator
    let create_event = mock_account_created_event_with_authenticators(
        100,
        0,
        leaf_index,
        recovery_address,
        vec![initial_address],
        vec![initial_pubkey],
        initial_commitment,
    );
    let update_event = mock_account_updated_event(
        100,
        1,
        leaf_index,
        0,
        updated_address,
        updated_pubkey,
        initial_commitment,
        updated_commitment,
    );
    let root_event = mock_root_recorded_event(100, 2, U256::from(999), U256::from(1000));

    // Process events: create, update, then root (which triggers commit)
    // Account should NOT exist in DB until root event is processed
    committer.handle_event(create_event).await.unwrap();
    committer.handle_event(update_event).await.unwrap();
    committer.handle_event(root_event).await.unwrap();

    // Verify account was created with UPDATED values (not initial values)
    // This confirms that the update event modified the account before it was committed
    let account = db.accounts().get_account(&leaf_index).await.unwrap();
    assert!(account.is_some(), "Account should exist after root event");
    let account = account.unwrap();
    assert_eq!(account.leaf_index, leaf_index);
    assert_eq!(
        account.authenticator_addresses[0], updated_address,
        "Authenticator address should be the UPDATED value"
    );
    assert_eq!(
        account.authenticator_pubkeys[0], updated_pubkey,
        "Authenticator pubkey should be the UPDATED value"
    );
    assert_eq!(
        account.offchain_signer_commitment, updated_commitment,
        "Commitment should be the UPDATED value, not initial"
    );
}

/// Test that multiple batches of events can be processed
#[tokio::test]
async fn test_multiple_event_batches() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db);

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
}

/// Test AuthenticatorInserted event
#[tokio::test]
async fn test_authenticator_inserted() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db);

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
}

/// Test AuthenticatorRemoved event
#[tokio::test]
async fn test_authenticator_removed() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db);

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
}

/// Test AccountRecovered event
#[tokio::test]
async fn test_account_recovered() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db);

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
}

/// Test that transaction rollback works on error
#[tokio::test]
async fn test_transaction_rollback_on_error() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    // Pre-insert an account with leaf_index 1
    insert_test_account(db, U256::from(1), Address::ZERO, U256::from(500))
        .await
        .unwrap();

    let mut committer = EventsCommitter::new(db);

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
}

/// Test buffer clearing after commit
#[tokio::test]
async fn test_buffer_cleared_after_commit() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db);

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
}
