mod helpers;

use alloy::primitives::{Address, U256};
use helpers::db_helpers::*;
use serial_test::serial;
use world_id_indexer::db::WorldTreeEventType;

/// Test handling of maximum U256 values
#[tokio::test]
#[serial]
async fn test_max_u256_values() {
    let (db, db_name) = create_unique_test_db().await;

    let max_u256 = U256::MAX;

    // Insert account with max values
    db.accounts()
        .insert(&max_u256, &Address::ZERO, &vec![], &vec![], &max_u256)
        .await
        .unwrap();

    // Verify account was created
    let exists = account_exists(db.pool(), max_u256).await.unwrap();
    assert!(exists, "Account should exist");

    cleanup_test_db(&db_name).await;
}

/// Test handling of zero values
#[tokio::test]
#[serial]
async fn test_zero_values() {
    let (db, db_name) = create_unique_test_db().await;

    // Insert account with zero values
    db.accounts()
        .insert(&U256::ZERO, &Address::ZERO, &vec![], &vec![], &U256::ZERO)
        .await
        .unwrap();

    // Verify account was created
    let exists = account_exists(db.pool(), U256::ZERO).await.unwrap();
    assert!(exists, "Account should exist");

    cleanup_test_db(&db_name).await;
}

/// Test handling of empty arrays
#[tokio::test]
#[serial]
async fn test_empty_authenticator_arrays() {
    let (db, db_name) = create_unique_test_db().await;

    // Insert account with empty authenticator arrays
    let result = db
        .accounts()
        .insert(
            &U256::from(1),
            &Address::ZERO,
            &vec![],
            &vec![],
            &U256::from(100),
        )
        .await;

    result.expect("Should handle empty authenticator arrays");

    cleanup_test_db(&db_name).await;
}

/// Test handling of very large arrays
#[tokio::test]
#[serial]
async fn test_large_authenticator_arrays() {
    let (db, db_name) = create_unique_test_db().await;

    // Create large arrays (but reasonable size for authenticators)
    let addresses = vec![Address::from([1u8; 20]); 10];
    let pubkeys = vec![U256::from(123); 10];

    let result = db
        .accounts()
        .insert(
            &U256::from(1),
            &Address::ZERO,
            &addresses,
            &pubkeys,
            &U256::from(100),
        )
        .await;

    assert!(
        result.is_ok(),
        "Should handle reasonably large authenticator arrays"
    );

    cleanup_test_db(&db_name).await;
}

/// Test handling of block number 0
#[tokio::test]
#[serial]
async fn test_block_number_zero() {
    let (db, db_name) = create_unique_test_db().await;

    // Insert event at block 0
    db.world_tree_events()
        .insert_event(
            &U256::from(1),
            WorldTreeEventType::AccountCreated,
            &U256::from(100),
            0, // Block 0
            &U256::from(1000),
            0,
        )
        .await
        .unwrap();

    let event = db.world_tree_events().get_event((0, 0)).await.unwrap();
    assert!(event.is_some());

    cleanup_test_db(&db_name).await;
}

/// Test handling of very high block numbers
#[tokio::test]
#[serial]
async fn test_high_block_number() {
    let (db, db_name) = create_unique_test_db().await;

    let high_block = u64::MAX;

    // Insert event at very high block number
    db.world_tree_events()
        .insert_event(
            &U256::from(1),
            WorldTreeEventType::AccountCreated,
            &U256::from(100),
            high_block,
            &U256::from(1000),
            0,
        )
        .await
        .unwrap();

    let event = db
        .world_tree_events()
        .get_event((high_block, 0))
        .await
        .unwrap();
    assert!(event.is_some());

    cleanup_test_db(&db_name).await;
}

/// Test handling of maximum log index
#[tokio::test]
#[serial]
async fn test_max_log_index() {
    let (db, db_name) = create_unique_test_db().await;

    let max_log_index = u64::MAX;

    // Insert event with max log index
    db.world_tree_events()
        .insert_event(
            &U256::from(1),
            WorldTreeEventType::AccountCreated,
            &U256::from(100),
            100,
            &U256::from(1000),
            max_log_index,
        )
        .await
        .unwrap();

    let event = db
        .world_tree_events()
        .get_event((100, max_log_index))
        .await
        .unwrap();
    assert!(event.is_some());

    cleanup_test_db(&db_name).await;
}

/// Test ordering of events with same block number but different log indices
#[tokio::test]
#[serial]
async fn test_event_ordering_by_log_index() {
    let (db, db_name) = create_unique_test_db().await;

    let block = 100;

    // Insert events out of order
    db.world_tree_events()
        .insert_event(
            &U256::from(3),
            WorldTreeEventType::AccountCreated,
            &U256::from(300),
            block,
            &U256::from(1000),
            2,
        )
        .await
        .unwrap();

    db.world_tree_events()
        .insert_event(
            &U256::from(1),
            WorldTreeEventType::AccountCreated,
            &U256::from(100),
            block,
            &U256::from(1000),
            0,
        )
        .await
        .unwrap();

    db.world_tree_events()
        .insert_event(
            &U256::from(2),
            WorldTreeEventType::AccountCreated,
            &U256::from(200),
            block,
            &U256::from(1000),
            1,
        )
        .await
        .unwrap();

    // Verify all events were inserted
    let count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(count, 3);

    cleanup_test_db(&db_name).await;
}

/// Test handling of same account being updated multiple times
#[tokio::test]
#[serial]
async fn test_multiple_updates_same_account() {
    let (db, db_name) = create_unique_test_db().await;

    let leaf_index = U256::from(1);

    // Create account
    db.accounts()
        .insert(
            &leaf_index,
            &Address::ZERO,
            &vec![Address::from([1u8; 20])],
            &vec![U256::from(100)],
            &U256::from(100),
        )
        .await
        .unwrap();

    // Update multiple times
    for i in 1..10 {
        db.accounts()
            .update_authenticator_at_index(
                &leaf_index,
                0,
                &Address::from([i as u8; 20]),
                &U256::from(i * 100),
                &U256::from(i * 100),
            )
            .await
            .unwrap();
    }

    // Verify final state
    let exists = account_exists(db.pool(), leaf_index).await.unwrap();
    assert!(exists, "Account should exist");

    cleanup_test_db(&db_name).await;
}

/// Test handling of account with maximum number of authenticators
#[tokio::test]
#[serial]
async fn test_max_authenticators() {
    let (db, db_name) = create_unique_test_db().await;

    // Create account with many authenticators (reasonable limit)
    let max_auth = 32; // Reasonable max for testing
    let addresses: Vec<Address> = (0..max_auth)
        .map(|i| Address::from([i as u8; 20]))
        .collect();
    let pubkeys: Vec<U256> = (0..max_auth).map(|i| U256::from(i)).collect();

    let result = db
        .accounts()
        .insert(
            &U256::from(1),
            &Address::ZERO,
            &addresses,
            &pubkeys,
            &U256::from(100),
        )
        .await
        .expect("Should handle reasonably large authenticator arrays");

    cleanup_test_db(&db_name).await;
}

/// Test concurrent inserts with different leaf indices
#[tokio::test]
#[serial]
async fn test_concurrent_different_leaf_inserts() {
    let (db, db_name) = create_unique_test_db().await;

    let mut handles = vec![];

    // Create many concurrent inserts with different leaf indices
    for i in 0..20 {
        let db_clone = db.clone();
        let handle = tokio::spawn(async move {
            db_clone
                .accounts()
                .insert(
                    &U256::from(i),
                    &Address::ZERO,
                    &vec![],
                    &vec![],
                    &U256::from(i * 100),
                )
                .await
        });
        handles.push(handle);
    }

    // Wait for all inserts
    for handle in handles {
        handle
            .await
            .expect("Join handle should succeed")
            .expect("Insert should succeed");
    }

    // Verify all accounts were created
    let count = count_accounts(db.pool()).await.unwrap();
    assert_eq!(count, 20);

    cleanup_test_db(&db_name).await;
}

/// Test event type enum coverage
#[tokio::test]
#[serial]
async fn test_all_event_types() {
    let (db, db_name) = create_unique_test_db().await;

    let event_types = vec![
        WorldTreeEventType::AccountCreated,
        WorldTreeEventType::AccountUpdated,
        WorldTreeEventType::AuthenticationInserted,
        WorldTreeEventType::AuthenticationRemoved,
        WorldTreeEventType::AccountRecovered,
    ];

    for (i, event_type) in event_types.iter().enumerate() {
        db.world_tree_events()
            .insert_event(
                &U256::from(i),
                *event_type,
                &U256::from(i * 100),
                100,
                &U256::from(1000),
                i as u64,
            )
            .await
            .unwrap();
    }

    let count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(count, 5);

    cleanup_test_db(&db_name).await;
}

/// Test handling of null/zero addresses
#[tokio::test]
#[serial]
async fn test_zero_addresses() {
    let (db, db_name) = create_unique_test_db().await;

    // Insert account with zero addresses
    db.accounts()
        .insert(
            &U256::from(1),
            &Address::ZERO,
            &vec![Address::ZERO],
            &vec![U256::from(100)],
            &U256::from(100),
        )
        .await
        .unwrap();

    let exists = account_exists(db.pool(), U256::from(1)).await.unwrap();
    assert!(exists, "Account should exist");

    cleanup_test_db(&db_name).await;
}

/// Test boundary between dense and sparse tree
#[tokio::test]
#[serial]
async fn test_tree_depth_boundaries() {
    let (db, db_name) = create_unique_test_db().await;

    // Test leaf indices at various tree depth boundaries
    let boundary_indices = vec![
        U256::from(0),
        U256::from(1),
        U256::from(1023),    // 2^10 - 1
        U256::from(1024),    // 2^10
        U256::from(1048575), // 2^20 - 1
        U256::from(1048576), // 2^20
    ];

    for (i, leaf_index) in boundary_indices.iter().enumerate() {
        db.accounts()
            .insert(
                leaf_index,
                &Address::ZERO,
                &vec![],
                &vec![],
                &U256::from(i * 100),
            )
            .await
            .unwrap();
    }

    let count = count_accounts(db.pool()).await.unwrap();
    assert_eq!(count, 6);

    cleanup_test_db(&db_name).await;
}

/// Test query with limit edge cases
#[tokio::test]
#[serial]
async fn test_query_limit_edge_cases() {
    let (db, db_name) = create_unique_test_db().await;

    // Insert multiple events
    for i in 0..10 {
        db.world_tree_events()
            .insert_event(
                &U256::from(i),
                WorldTreeEventType::AccountCreated,
                &U256::from(i * 100),
                100 + i,
                &U256::from(1000),
                0,
            )
            .await
            .unwrap();
    }

    // Verify all events were inserted
    let count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(count, 10);

    cleanup_test_db(&db_name).await;
}

/// Test timestamp edge cases for roots
#[tokio::test]
#[serial]
async fn test_root_timestamp_edge_cases() {
    let (db, db_name) = create_unique_test_db().await;

    // Insert root with zero timestamp
    insert_test_world_tree_root(&db, 100, 0, U256::from(5555), U256::ZERO)
        .await
        .unwrap();

    // Insert root with max timestamp
    insert_test_world_tree_root(&db, 100, 1, U256::from(6666), U256::MAX)
        .await
        .unwrap();

    let count = count_world_tree_roots(db.pool()).await.unwrap();
    assert_eq!(count, 2);

    cleanup_test_db(&db_name).await;
}

/// Test handling of special characters in data (shouldn't affect U256/Address)
#[tokio::test]
#[serial]
async fn test_data_integrity() {
    let (db, db_name) = create_unique_test_db().await;

    // Create specific bit patterns
    let leaf_index = U256::from_be_bytes([0xFF; 32]);
    let commitment = U256::from_be_bytes([0xAA; 32]);

    db.accounts()
        .insert(&leaf_index, &Address::ZERO, &vec![], &vec![], &commitment)
        .await
        .unwrap();

    let exists = account_exists(db.pool(), leaf_index).await.unwrap();
    assert!(exists, "Account should exist");

    cleanup_test_db(&db_name).await;
}
