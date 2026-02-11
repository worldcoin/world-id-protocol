mod helpers;

use alloy::primitives::{Address, U256};
use helpers::db_helpers::*;
use world_id_indexer::db::{IsolationLevel, WorldTreeEventType, WorldTreeRootEventType};

/// Test inserting an account
#[tokio::test]
async fn test_insert_account() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let leaf_index = 1u64;
    let recovery_address = Address::ZERO;
    let auth_addresses = vec![Address::ZERO];
    let auth_pubkeys = vec![U256::from(123)];
    let commitment = U256::from(456);

    db.accounts()
        .insert(
            leaf_index,
            &recovery_address,
            &auth_addresses,
            &auth_pubkeys,
            &commitment,
        )
        .await
        .unwrap();

    // Verify account was inserted with correct data
    let account = db
        .accounts()
        .get_account(leaf_index)
        .await
        .unwrap();
    assert!(account.is_some(), "Account should exist");

    let account = account.unwrap();
    assert_eq!(account.leaf_index, leaf_index);
    assert_eq!(account.recovery_address, recovery_address);
    assert_eq!(account.authenticator_addresses, auth_addresses);
    assert_eq!(account.authenticator_pubkeys, auth_pubkeys);
    assert_eq!(account.offchain_signer_commitment, commitment);
    // Cleanup happens automatically when test_db is dropped
}

/// Test duplicate insert is handled gracefully (idempotent)
#[tokio::test]
async fn test_duplicate_insert_account() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let leaf_index = 1u64;
    let recovery_address = Address::ZERO;
    let auth_addresses = vec![Address::ZERO];
    let auth_pubkeys = vec![U256::from(123)];
    let commitment = U256::from(456);

    // First insert
    db.accounts()
        .insert(
            leaf_index,
            &recovery_address,
            &auth_addresses,
            &auth_pubkeys,
            &commitment,
        )
        .await
        .unwrap();

    // Second insert with same data - should error (duplicate key)
    let result = db
        .accounts()
        .insert(
            leaf_index,
            &recovery_address,
            &auth_addresses,
            &auth_pubkeys,
            &commitment,
        )
        .await;

    assert!(
        result.is_err(),
        "Duplicate insert should fail with unique constraint violation"
    );

    // Should still have only one account
    let count = count_accounts(db.pool()).await.unwrap();
    assert_eq!(count, 1);
}

/// Test updating authenticator at index
#[tokio::test]
async fn test_update_authenticator_at_index() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let leaf_index = 1u64;
    let initial_address = Address::from([1u8; 20]);
    let initial_pubkey = U256::from(123);
    let initial_commitment = U256::from(456);

    // Insert account
    db.accounts()
        .insert(
            leaf_index,
            &Address::ZERO,
            &[initial_address],
            &[initial_pubkey],
            &initial_commitment,
        )
        .await
        .unwrap();

    // Update authenticator
    let new_address = Address::from([2u8; 20]);
    let new_pubkey = U256::from(789);
    let new_commitment = U256::from(999);

    db.accounts()
        .update_authenticator_at_index(
            leaf_index,
            0,
            &new_address,
            &new_pubkey,
            &new_commitment,
        )
        .await
        .unwrap();

    // Verify update with field checks
    let account = db
        .accounts()
        .get_account(leaf_index)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(account.authenticator_addresses[0], new_address);
    assert_eq!(account.authenticator_pubkeys[0], new_pubkey);
    assert_eq!(account.offchain_signer_commitment, new_commitment);
}

/// Test inserting authenticator at index
#[tokio::test]
async fn test_insert_authenticator_at_index() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let leaf_index = 1u64;
    let initial_commitment = U256::from(456);

    // Insert account with one authenticator
    db.accounts()
        .insert(
            leaf_index,
            &Address::ZERO,
            &[Address::from([1u8; 20])],
            &[U256::from(123)],
            &initial_commitment,
        )
        .await
        .unwrap();

    // Insert another authenticator
    let new_address = Address::from([2u8; 20]);
    let new_pubkey = U256::from(789);
    let new_commitment = U256::from(999);

    db.accounts()
        .insert_authenticator_at_index(
            leaf_index,
            1,
            &new_address,
            &new_pubkey,
            &new_commitment,
        )
        .await
        .unwrap();

    // Verify insertion with field checks
    let account = db
        .accounts()
        .get_account(leaf_index)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(account.authenticator_addresses.len(), 2);
    assert_eq!(account.authenticator_addresses[1], new_address);
    assert_eq!(account.authenticator_pubkeys[1], new_pubkey);
    assert_eq!(account.offchain_signer_commitment, new_commitment);
}

/// Test removing authenticator at index
#[tokio::test]
async fn test_remove_authenticator_at_index() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let leaf_index = 1u64;
    let initial_commitment = U256::from(456);

    // Insert account with two authenticators
    db.accounts()
        .insert(
            leaf_index,
            &Address::ZERO,
            &[Address::from([1u8; 20]), Address::from([2u8; 20])],
            &[U256::from(123), U256::from(456)],
            &initial_commitment,
        )
        .await
        .unwrap();

    // Remove second authenticator
    let new_commitment = U256::from(999);

    db.accounts()
        .remove_authenticator_at_index(leaf_index, 1, &new_commitment)
        .await
        .unwrap();

    // Verify removal with field checks
    let account = db
        .accounts()
        .get_account(leaf_index)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(account.authenticator_addresses.len(), 1);
    assert_eq!(account.authenticator_addresses[0], Address::from([1u8; 20]));
    assert_eq!(account.authenticator_pubkeys[0], U256::from(123));
    assert_eq!(account.offchain_signer_commitment, new_commitment);
}

/// Test resetting authenticator (account recovery)
#[tokio::test]
async fn test_reset_authenticator() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let leaf_index = 1u64;
    let initial_commitment = U256::from(456);

    // Insert account
    db.accounts()
        .insert(
            leaf_index,
            &Address::ZERO,
            &[Address::from([1u8; 20])],
            &[U256::from(123)],
            &initial_commitment,
        )
        .await
        .unwrap();

    // Reset authenticator
    let new_address = Address::from([3u8; 20]);
    let new_pubkey = U256::from(999);
    let new_commitment = U256::from(1111);

    db.accounts()
        .reset_authenticator(
            leaf_index,
            &new_address,
            &new_pubkey,
            &new_commitment,
        )
        .await
        .unwrap();

    // Verify reset
    let account = db
        .accounts()
        .get_account(leaf_index)
        .await
        .unwrap();
    assert!(account.is_some(), "Account should exist after reset");
    let account = account.unwrap();

    // After reset, authenticator array should have exactly 1 element
    assert_eq!(account.authenticator_addresses.len(), 1);
    assert_eq!(account.authenticator_pubkeys.len(), 1);

    // Verify the new authenticator values
    assert_eq!(account.authenticator_addresses[0], new_address);
    assert_eq!(account.authenticator_pubkeys[0], new_pubkey);
    assert_eq!(account.offchain_signer_commitment, new_commitment);
}

/// Test inserting world tree event
#[tokio::test]
async fn test_insert_world_tree_event() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let block_number = 100;
    let log_index = 5;
    let leaf_index = 1u64;
    let tx_hash = U256::from(999);
    let commitment = U256::from(456);

    db.world_tree_events()
        .insert_event(
            leaf_index,
            WorldTreeEventType::AccountCreated,
            &commitment,
            block_number,
            &tx_hash,
            log_index,
        )
        .await
        .unwrap();

    // Verify event was inserted with correct data
    let event = db
        .world_tree_events()
        .get_event((block_number, log_index))
        .await
        .unwrap();

    assert!(event.is_some(), "Event should exist");
    let event = event.unwrap();
    assert_eq!(event.id.block_number, block_number);
    assert_eq!(event.id.log_index, log_index);
    assert_eq!(event.leaf_index, u64::try_from(leaf_index).unwrap());
    assert_eq!(event.event_type, WorldTreeEventType::AccountCreated);
    assert_eq!(event.offchain_signer_commitment, commitment);
    assert_eq!(event.tx_hash, tx_hash);
}

/// Test duplicate world tree event insert is handled
#[tokio::test]
async fn test_duplicate_world_tree_event_insert() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let block_number = 100;
    let log_index = 5;
    let leaf_index = 1u64;
    let tx_hash = U256::from(999);
    let commitment = U256::from(456);

    // First insert
    db.world_tree_events()
        .insert_event(
            leaf_index,
            WorldTreeEventType::AccountCreated,
            &commitment,
            block_number,
            &tx_hash,
            log_index,
        )
        .await
        .unwrap();

    // Duplicate insert - should error (duplicate key)
    let result = db
        .world_tree_events()
        .insert_event(
            leaf_index,
            WorldTreeEventType::AccountCreated,
            &commitment,
            block_number,
            &tx_hash,
            log_index,
        )
        .await;

    assert!(
        result.is_err(),
        "Duplicate event insert should fail with unique constraint violation"
    );

    // Should still have only one event
    let count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(count, 1);
}

/// Test getting world tree event by ID
#[tokio::test]
async fn test_get_world_tree_event() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let block_number = 100;
    let log_index = 5;
    let leaf_index = 1u64;
    let tx_hash = U256::from(999);
    let commitment = U256::from(456);

    db.world_tree_events()
        .insert_event(
            leaf_index,
            WorldTreeEventType::AccountCreated,
            &commitment,
            block_number,
            &tx_hash,
            log_index,
        )
        .await
        .unwrap();

    // Get event
    let event = db
        .world_tree_events()
        .get_event((block_number, log_index))
        .await
        .unwrap();

    assert!(event.is_some());
    let event = event.unwrap();
    assert_eq!(event.id.block_number, block_number);
    assert_eq!(event.id.log_index, log_index);
    assert_eq!(event.leaf_index, u64::try_from(leaf_index).unwrap());
    assert_eq!(event.event_type, WorldTreeEventType::AccountCreated);
}

/// Test getting latest world tree events
#[tokio::test]
async fn test_get_latest_world_tree_events() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    // Insert multiple events
    for i in 0..5 {
        db.world_tree_events()
            .insert_event(
                i,
                WorldTreeEventType::AccountCreated,
                &U256::from(i * 100),
                100 + i,
                &U256::from(999),
                i,
            )
            .await
            .unwrap();
    }

    // Verify all events were inserted with correct data
    let count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(count, 5);

    // Verify we can retrieve each event with correct data
    for i in 0..5 {
        let event = db
            .world_tree_events()
            .get_event((100 + i, i))
            .await
            .unwrap();

        assert!(event.is_some(), "Event {} should exist", i);
        let event = event.unwrap();
        assert_eq!(event.id.block_number, 100 + i);
        assert_eq!(event.id.log_index, i);
        assert_eq!(event.leaf_index, i);
        assert_eq!(event.offchain_signer_commitment, U256::from(i * 100));
        assert_eq!(event.tx_hash, U256::from(999));
    }
}

/// Test inserting world tree root
#[tokio::test]
async fn test_insert_world_tree_root() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let block_number = 100;
    let log_index = 5;
    let root = U256::from(12345);
    let timestamp = U256::from(1000);
    let tx_hash = U256::from(999);

    db.world_tree_roots()
        .insert_event(
            block_number,
            log_index,
            WorldTreeRootEventType::RootRecorded,
            &tx_hash,
            &root,
            &timestamp,
        )
        .await
        .unwrap();

    // Verify root was inserted with correct data
    let root_event = db
        .world_tree_roots()
        .get_root((block_number, log_index))
        .await
        .unwrap();

    assert!(root_event.is_some(), "Root event should exist");
    let root_event = root_event.unwrap();
    assert_eq!(root_event.id.block_number, block_number);
    assert_eq!(root_event.id.log_index, log_index);
    assert_eq!(root_event.root, root);
    assert_eq!(root_event.timestamp, timestamp);
    assert_eq!(root_event.event_type, WorldTreeRootEventType::RootRecorded);
    assert_eq!(root_event.tx_hash, tx_hash);
}

/// Test duplicate world tree root insert is handled
#[tokio::test]
async fn test_duplicate_world_tree_root_insert() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let block_number = 100;
    let log_index = 5;
    let root = U256::from(12345);
    let timestamp = U256::from(1000);
    let tx_hash = U256::from(999);

    // First insert
    db.world_tree_roots()
        .insert_event(
            block_number,
            log_index,
            WorldTreeRootEventType::RootRecorded,
            &tx_hash,
            &root,
            &timestamp,
        )
        .await
        .unwrap();

    // Duplicate insert - should error (duplicate key)
    let result = db
        .world_tree_roots()
        .insert_event(
            block_number,
            log_index,
            WorldTreeRootEventType::RootRecorded,
            &tx_hash,
            &root,
            &timestamp,
        )
        .await;

    assert!(
        result.is_err(),
        "Duplicate root insert should fail with unique constraint violation"
    );

    // Should still have only one root
    let count = count_world_tree_roots(db.pool()).await.unwrap();
    assert_eq!(count, 1);
}

/// Test getting world tree root by ID
#[tokio::test]
async fn test_get_world_tree_root() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let block_number = 100;
    let log_index = 5;
    let root = U256::from(12345);
    let timestamp = U256::from(1000);
    let tx_hash = U256::from(999);

    db.world_tree_roots()
        .insert_event(
            block_number,
            log_index,
            WorldTreeRootEventType::RootRecorded,
            &tx_hash,
            &root,
            &timestamp,
        )
        .await
        .unwrap();

    // Get root
    let root_event = db
        .world_tree_roots()
        .get_root((block_number, log_index))
        .await
        .unwrap();

    assert!(root_event.is_some());
    let root_event = root_event.unwrap();
    assert_eq!(root_event.id.block_number, block_number);
    assert_eq!(root_event.id.log_index, log_index);
    assert_eq!(root_event.root, root);
    assert_eq!(root_event.timestamp, timestamp);
}

/// Test transaction commit
#[tokio::test]
async fn test_transaction_commit() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut tx = db.transaction(IsolationLevel::Serializable).await.unwrap();

    // Insert within transaction
    tx.accounts()
        .await
        .unwrap()
        .insert(
            1u64,
            &Address::ZERO,
            &[],
            &[],
            &U256::from(123),
        )
        .await
        .unwrap();

    // Before commit, should not be visible
    let count = count_accounts(db.pool()).await.unwrap();
    assert_eq!(count, 0, "Transaction not committed yet");

    // Commit
    tx.commit().await.unwrap();

    // Now should be visible
    let count = count_accounts(db.pool()).await.unwrap();
    assert_eq!(count, 1, "Transaction committed successfully");
}

/// Test transaction rollback
#[tokio::test]
async fn test_transaction_rollback() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut tx = db.transaction(IsolationLevel::Serializable).await.unwrap();

    // Insert within transaction
    tx.accounts()
        .await
        .unwrap()
        .insert(
            1u64,
            &Address::ZERO,
            &[],
            &[],
            &U256::from(123),
        )
        .await
        .unwrap();

    // Rollback
    tx.rollback().await.unwrap();

    // Should not be visible
    let count = count_accounts(db.pool()).await.unwrap();
    assert_eq!(count, 0, "Transaction rolled back successfully");
}

/// Test multiple operations in single transaction
#[tokio::test]
async fn test_multiple_operations_in_transaction() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let mut tx = db.transaction(IsolationLevel::Serializable).await.unwrap();

    // Insert account
    tx.accounts()
        .await
        .unwrap()
        .insert(
            1u64,
            &Address::ZERO,
            &[],
            &[],
            &U256::from(123),
        )
        .await
        .unwrap();

    // Insert event
    tx.world_tree_events()
        .await
        .unwrap()
        .insert_event(
            1,
            WorldTreeEventType::AccountCreated,
            &U256::from(123),
            100,
            &U256::from(999),
            0,
        )
        .await
        .unwrap();

    // Insert root
    tx.world_tree_roots()
        .await
        .unwrap()
        .insert_event(
            100,
            1,
            WorldTreeRootEventType::RootRecorded,
            &U256::from(999),
            &U256::from(5555),
            &U256::from(1000),
        )
        .await
        .unwrap();

    // Commit all
    tx.commit().await.unwrap();

    // Verify all operations committed
    let account_count = count_accounts(db.pool()).await.unwrap();
    let event_count = count_world_tree_events(db.pool()).await.unwrap();
    let root_count = count_world_tree_roots(db.pool()).await.unwrap();

    assert_eq!(account_count, 1);
    assert_eq!(event_count, 1);
    assert_eq!(root_count, 1);
}
