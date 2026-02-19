mod helpers;

use alloy::primitives::{Address, U256};
use helpers::db_helpers::*;
use world_id_indexer::db::WorldIdRegistryEventType;

/// Test handling of maximum U256 values
#[tokio::test]
async fn test_max_u256_values() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let max_leaf_index = u64::MAX;
    let max_u256 = U256::MAX;

    // Insert account with max values
    db.accounts()
        .insert(max_leaf_index, &Address::ZERO, &[], &[], &max_u256, 100, 0)
        .await
        .unwrap();

    // Verify account was created with MAX values
    let account = db.accounts().get_account(max_leaf_index).await.unwrap();
    assert!(account.is_some(), "Account should exist");
    let account = account.unwrap();
    assert_eq!(
        account.leaf_index, max_leaf_index,
        "Leaf index should be MAX"
    );
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
        .insert(0, &Address::ZERO, &[], &[], &U256::ZERO, 100, 0)
        .await
        .unwrap();

    // Verify account was created with zero values
    let account = db.accounts().get_account(0).await.unwrap();
    assert!(account.is_some(), "Account should exist");
    let account = account.unwrap();
    assert_eq!(account.leaf_index, 0, "Leaf index should be ZERO");
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
        .insert(1, &Address::ZERO, &[], &[], &U256::from(100), 100, 0)
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
    let event = world_id_indexer::blockchain::BlockchainEvent {
        block_number: max_block_number,
        tx_hash: U256::from(1000),
        log_index: 0,
        details: world_id_indexer::blockchain::RegistryEvent::AccountCreated(
            world_id_indexer::blockchain::AccountCreatedEvent {
                leaf_index: 1,
                recovery_address: Address::ZERO,
                authenticator_addresses: vec![],
                authenticator_pubkeys: vec![],
                offchain_signer_commitment: U256::from(100),
            },
        ),
    };
    db.world_id_registry_events()
        .insert_event(&event)
        .await
        .unwrap();

    let event = db
        .world_id_registry_events()
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
    let event = world_id_indexer::blockchain::BlockchainEvent {
        block_number: 100,
        tx_hash: U256::from(1000),
        log_index: max_log_index,
        details: world_id_indexer::blockchain::RegistryEvent::AccountCreated(
            world_id_indexer::blockchain::AccountCreatedEvent {
                leaf_index: 1,
                recovery_address: Address::ZERO,
                authenticator_addresses: vec![],
                authenticator_pubkeys: vec![],
                offchain_signer_commitment: U256::from(100),
            },
        ),
    };
    db.world_id_registry_events()
        .insert_event(&event)
        .await
        .unwrap();

    let event = db
        .world_id_registry_events()
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
            1,
            &Address::ZERO,
            &addresses,
            &pubkeys,
            &U256::from(100),
            100,
            0,
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
        WorldIdRegistryEventType::AccountCreated,
        WorldIdRegistryEventType::AccountUpdated,
        WorldIdRegistryEventType::AuthenticatorInserted,
        WorldIdRegistryEventType::AuthenticatorRemoved,
        WorldIdRegistryEventType::AccountRecovered,
    ];

    for (i, event_type) in event_types.iter().enumerate() {
        let details = match event_type {
            WorldIdRegistryEventType::AccountCreated => {
                world_id_indexer::blockchain::RegistryEvent::AccountCreated(
                    world_id_indexer::blockchain::AccountCreatedEvent {
                        leaf_index: i as u64,
                        recovery_address: Address::ZERO,
                        authenticator_addresses: vec![],
                        authenticator_pubkeys: vec![],
                        offchain_signer_commitment: U256::from(i * 100),
                    },
                )
            }
            WorldIdRegistryEventType::AccountUpdated => {
                world_id_indexer::blockchain::RegistryEvent::AccountUpdated(
                    world_id_indexer::blockchain::AccountUpdatedEvent {
                        leaf_index: i as u64,
                        pubkey_id: 0,
                        new_authenticator_pubkey: U256::from(i * 100),
                        old_authenticator_address: Address::ZERO,
                        new_authenticator_address: Address::ZERO,
                        old_offchain_signer_commitment: U256::ZERO,
                        new_offchain_signer_commitment: U256::from(i * 100),
                    },
                )
            }
            WorldIdRegistryEventType::AuthenticatorInserted => {
                world_id_indexer::blockchain::RegistryEvent::AuthenticatorInserted(
                    world_id_indexer::blockchain::AuthenticatorInsertedEvent {
                        leaf_index: i as u64,
                        pubkey_id: 0,
                        authenticator_address: Address::ZERO,
                        new_authenticator_pubkey: U256::from(i * 100),
                        old_offchain_signer_commitment: U256::ZERO,
                        new_offchain_signer_commitment: U256::from(i * 100),
                    },
                )
            }
            WorldIdRegistryEventType::AuthenticatorRemoved => {
                world_id_indexer::blockchain::RegistryEvent::AuthenticatorRemoved(
                    world_id_indexer::blockchain::AuthenticatorRemovedEvent {
                        leaf_index: i as u64,
                        pubkey_id: 0,
                        authenticator_address: Address::ZERO,
                        authenticator_pubkey: U256::from(i * 100),
                        old_offchain_signer_commitment: U256::ZERO,
                        new_offchain_signer_commitment: U256::from(i * 100),
                    },
                )
            }
            WorldIdRegistryEventType::AccountRecovered => {
                world_id_indexer::blockchain::RegistryEvent::AccountRecovered(
                    world_id_indexer::blockchain::AccountRecoveredEvent {
                        leaf_index: i as u64,
                        new_authenticator_address: Address::ZERO,
                        new_authenticator_pubkey: U256::from(i * 100),
                        old_offchain_signer_commitment: U256::ZERO,
                        new_offchain_signer_commitment: U256::from(i * 100),
                    },
                )
            }
            WorldIdRegistryEventType::RootRecorded => {
                world_id_indexer::blockchain::RegistryEvent::RootRecorded(
                    world_id_indexer::blockchain::RootRecordedEvent {
                        root: U256::from(i * 100),
                        timestamp: U256::ZERO,
                    },
                )
            }
        };

        let event = world_id_indexer::blockchain::BlockchainEvent {
            block_number: 100,
            tx_hash: U256::from(1000),
            log_index: i as u64,
            details,
        };

        db.world_id_registry_events()
            .insert_event(&event)
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
    let event0 = db
        .world_id_registry_events()
        .get_event((100, 0))
        .await
        .unwrap();
    assert!(event0.is_some(), "Root with zero timestamp should exist");
    let event0 = event0.unwrap();
    assert_eq!(
        event0.event_type,
        WorldIdRegistryEventType::RootRecorded,
        "Event type should be RootRecorded"
    );
    // Timestamp is stored in event_data as JSON

    // Verify max timestamp
    let event1 = db
        .world_id_registry_events()
        .get_event((100, 1))
        .await
        .unwrap();
    assert!(event1.is_some(), "Root with max timestamp should exist");
    let event1 = event1.unwrap();
    assert_eq!(
        event1.event_type,
        WorldIdRegistryEventType::RootRecorded,
        "Event type should be RootRecorded"
    );
    // Timestamp is stored in event_data as JSON
}
