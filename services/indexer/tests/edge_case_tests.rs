mod helpers;

use alloy::primitives::{Address, U256};
use helpers::db_helpers::*;
use world_id_indexer::db::WorldTreeEventType;

/// Test handling of maximum U256 values
#[tokio::test]
async fn test_max_u256_values() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let max_u256 = U256::MAX;

    // Insert account with max values
    db.accounts()
        .insert(&max_u256, &Address::ZERO, &[], &[], &max_u256)
        .await
        .unwrap();

    // Verify account was created with MAX values
    let account = db.accounts().get_account(&max_u256).await.unwrap();
    assert!(account.is_some(), "Account should exist");
    let account = account.unwrap();
    assert_eq!(account.leaf_index, max_u256, "Leaf index should be MAX");
    assert_eq!(
        account.offchain_signer_commitment, max_u256,
        "Commitment should be MAX"
    );
}

/// Test handling of zero values
#[tokio::test]
async fn test_zero_values() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    // Insert account with zero values
    db.accounts()
        .insert(&U256::ZERO, &Address::ZERO, &[], &[], &U256::ZERO)
        .await
        .unwrap();

    // Verify account was created with zero values
    let account = db.accounts().get_account(&U256::ZERO).await.unwrap();
    assert!(account.is_some(), "Account should exist");
    let account = account.unwrap();
    assert_eq!(account.leaf_index, U256::ZERO, "Leaf index should be ZERO");
    assert_eq!(
        account.recovery_address,
        Address::ZERO,
        "Recovery address should be ZERO"
    );
    assert_eq!(
        account.offchain_signer_commitment,
        U256::ZERO,
        "Commitment should be ZERO"
    );
}

/// Test handling of empty arrays
#[tokio::test]
async fn test_empty_authenticator_arrays() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    // Insert account with empty authenticator arrays
    let result = db
        .accounts()
        .insert(&U256::from(1), &Address::ZERO, &[], &[], &U256::from(100))
        .await;

    result.expect("Should handle empty authenticator arrays");
}

/// Test handling of maximum block number
#[tokio::test]
async fn test_max_block_number() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let max_block_number = u64::MAX;

    // Insert event with max block number
    db.world_tree_events()
        .insert_event(
            &U256::from(1),
            WorldTreeEventType::AccountCreated,
            &U256::from(100),
            max_block_number,
            &U256::from(1000),
            0,
        )
        .await
        .unwrap();

    let event = db
        .world_tree_events()
        .get_event((max_block_number, 0))
        .await
        .unwrap();
    assert!(event.is_some());
}

/// Test handling of maximum log index
#[tokio::test]
async fn test_max_log_index() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

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
}

/// Test handling of account with maximum number of authenticators
#[tokio::test]
async fn test_max_authenticators() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    // Create account with many authenticators (reasonable limit)
    let max_auth = 32; // Reasonable max for testing
    let addresses: Vec<Address> = (0..max_auth)
        .map(|i| Address::from([i as u8; 20]))
        .collect();
    let pubkeys: Vec<U256> = (0..max_auth).map(|i| U256::from(i)).collect();

    db.accounts()
        .insert(
            &U256::from(1),
            &Address::ZERO,
            &addresses,
            &pubkeys,
            &U256::from(100),
        )
        .await
        .expect("Should handle reasonably large authenticator arrays");
}

/// Test event type enum coverage
#[tokio::test]
async fn test_all_event_types() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let event_types = [
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
}

/// Test timestamp edge cases for roots
#[tokio::test]
async fn test_root_timestamp_edge_cases() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    // Insert root with zero timestamp
    insert_test_world_tree_root(db, 100, 0, U256::from(5555), U256::ZERO)
        .await
        .unwrap();

    // Insert root with max timestamp
    insert_test_world_tree_root(db, 100, 1, U256::from(6666), U256::MAX)
        .await
        .unwrap();

    let count = count_world_tree_roots(db.pool()).await.unwrap();
    assert_eq!(count, 2);

    // Verify zero timestamp
    let root0 = db.world_tree_roots().get_root((100, 0)).await.unwrap();
    assert!(root0.is_some(), "Root with zero timestamp should exist");
    assert_eq!(
        root0.unwrap().timestamp,
        U256::ZERO,
        "Timestamp should be ZERO"
    );

    // Verify max timestamp
    let root1 = db.world_tree_roots().get_root((100, 1)).await.unwrap();
    assert!(root1.is_some(), "Root with max timestamp should exist");
    assert_eq!(
        root1.unwrap().timestamp,
        U256::MAX,
        "Timestamp should be MAX"
    );
}
