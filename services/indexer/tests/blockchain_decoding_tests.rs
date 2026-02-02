use alloy::primitives::{Address, Bytes, FixedBytes, Log, LogData, U256};
use alloy::rpc::types::Log as RpcLog;
use alloy::sol_types::SolEvent;
use world_id_core::world_id_registry::WorldIdRegistry;
use world_id_indexer::blockchain::RegistryEvent;

/// Helper to create a mock RPC log
fn create_mock_rpc_log(
    address: Address,
    topics: Vec<FixedBytes<32>>,
    data: Bytes,
    block_number: u64,
    tx_hash: FixedBytes<32>,
    log_index: u64,
) -> RpcLog {
    RpcLog {
        inner: Log {
            address,
            data: LogData::new_unchecked(topics, data),
        },
        block_hash: Some(FixedBytes::ZERO),
        block_number: Some(block_number),
        block_timestamp: None,
        transaction_hash: Some(tx_hash),
        transaction_index: Some(0),
        log_index: Some(log_index),
        removed: false,
    }
}

#[test]
fn test_decode_account_created_event() {
    let leaf_index = U256::from(1);
    let recovery_address = Address::from([1u8; 20]);
    let auth_addresses = vec![Address::from([2u8; 20])];
    let auth_pubkeys = vec![U256::from(123)];
    let commitment = U256::from(456);

    // Encode event data using alloy
    let event_data = WorldIdRegistry::AccountCreated {
        leafIndex: leaf_index,
        recoveryAddress: recovery_address,
        authenticatorAddresses: auth_addresses.clone(),
        authenticatorPubkeys: auth_pubkeys.clone(),
        offchainSignerCommitment: commitment,
    };

    let encoded = event_data.encode_data();

    let log = create_mock_rpc_log(
        Address::ZERO,
        vec![
            WorldIdRegistry::AccountCreated::SIGNATURE_HASH,
            FixedBytes::from(leaf_index),
            recovery_address.into_word(),
        ],
        encoded.into(),
        100,
        FixedBytes::from([1u8; 32]),
        0,
    );

    let blockchain_event = RegistryEvent::decode(&log).expect("Decoding should succeed");

    assert_eq!(blockchain_event.block_number, 100);
    assert_eq!(blockchain_event.log_index, 0);

    match blockchain_event.details {
        world_id_indexer::blockchain::RegistryEvent::AccountCreated(ev) => {
            assert_eq!(ev.leaf_index, leaf_index);
            assert_eq!(ev.recovery_address, recovery_address);
            assert_eq!(ev.authenticator_addresses, auth_addresses);
            assert_eq!(ev.authenticator_pubkeys, auth_pubkeys);
            assert_eq!(ev.offchain_signer_commitment, commitment);
        }
        _ => panic!("Expected AccountCreated event"),
    }
}

#[test]
fn test_decode_account_updated_event() {
    let leaf_index = U256::from(1);
    let pubkey_id = 0u32;
    let new_pubkey = U256::from(789);
    let old_address = Address::from([1u8; 20]);
    let new_address = Address::from([2u8; 20]);
    let old_commitment = U256::from(100);
    let new_commitment = U256::from(200);

    let event_data = WorldIdRegistry::AccountUpdated {
        leafIndex: leaf_index,
        pubkeyId: pubkey_id,
        newAuthenticatorPubkey: new_pubkey,
        oldAuthenticatorAddress: old_address,
        newAuthenticatorAddress: new_address,
        oldOffchainSignerCommitment: old_commitment,
        newOffchainSignerCommitment: new_commitment,
    };

    let encoded = event_data.encode_data();

    let log = create_mock_rpc_log(
        Address::ZERO,
        vec![
            WorldIdRegistry::AccountUpdated::SIGNATURE_HASH,
            FixedBytes::from(leaf_index),
            old_address.into_word(),
            new_address.into_word(),
        ],
        encoded.into(),
        100,
        FixedBytes::from([1u8; 32]),
        0,
    );

    let blockchain_event = RegistryEvent::decode(&log).expect("Decoding should succeed");

    match blockchain_event.details {
        world_id_indexer::blockchain::RegistryEvent::AccountUpdated(ev) => {
            assert_eq!(ev.leaf_index, leaf_index);
            assert_eq!(ev.pubkey_id, pubkey_id);
            assert_eq!(ev.new_authenticator_pubkey, new_pubkey);
            assert_eq!(ev.old_authenticator_address, old_address);
            assert_eq!(ev.new_authenticator_address, new_address);
            assert_eq!(ev.old_offchain_signer_commitment, old_commitment);
            assert_eq!(ev.new_offchain_signer_commitment, new_commitment);
        }
        _ => panic!("Expected AccountUpdated event"),
    }
}

#[test]
fn test_decode_authenticator_inserted_event() {
    let leaf_index = U256::from(1);
    let pubkey_id = 1u32;
    let auth_address = Address::from([3u8; 20]);
    let new_pubkey = U256::from(999);
    let old_commitment = U256::from(100);
    let new_commitment = U256::from(200);

    let event_data = WorldIdRegistry::AuthenticatorInserted {
        leafIndex: leaf_index,
        pubkeyId: pubkey_id,
        authenticatorAddress: auth_address,
        newAuthenticatorPubkey: new_pubkey,
        oldOffchainSignerCommitment: old_commitment,
        newOffchainSignerCommitment: new_commitment,
    };

    let encoded = event_data.encode_data();

    let log = create_mock_rpc_log(
        Address::ZERO,
        vec![
            WorldIdRegistry::AuthenticatorInserted::SIGNATURE_HASH,
            FixedBytes::from(leaf_index),
            auth_address.into_word(),
            FixedBytes::from(new_pubkey),
        ],
        encoded.into(),
        100,
        FixedBytes::from([1u8; 32]),
        0,
    );

    let blockchain_event = RegistryEvent::decode(&log).expect("Decoding should succeed");

    match blockchain_event.details {
        world_id_indexer::blockchain::RegistryEvent::AuthenticatorInserted(ev) => {
            assert_eq!(ev.leaf_index, leaf_index);
            assert_eq!(ev.pubkey_id, pubkey_id);
            assert_eq!(ev.authenticator_address, auth_address);
            assert_eq!(ev.new_authenticator_pubkey, new_pubkey);
            assert_eq!(ev.old_offchain_signer_commitment, old_commitment);
            assert_eq!(ev.new_offchain_signer_commitment, new_commitment);
        }
        _ => panic!("Expected AuthenticatorInserted event"),
    }
}

#[test]
fn test_decode_authenticator_removed_event() {
    let leaf_index = U256::from(1);
    let pubkey_id = 0u32;
    let auth_address = Address::from([4u8; 20]);
    let pubkey = U256::from(888);
    let old_commitment = U256::from(100);
    let new_commitment = U256::from(200);

    let event_data = WorldIdRegistry::AuthenticatorRemoved {
        leafIndex: leaf_index,
        pubkeyId: pubkey_id,
        authenticatorAddress: auth_address,
        authenticatorPubkey: pubkey,
        oldOffchainSignerCommitment: old_commitment,
        newOffchainSignerCommitment: new_commitment,
    };

    let encoded = event_data.encode_data();

    let log = create_mock_rpc_log(
        Address::ZERO,
        vec![
            WorldIdRegistry::AuthenticatorRemoved::SIGNATURE_HASH,
            FixedBytes::from(leaf_index),
            auth_address.into_word(),
            FixedBytes::from(pubkey),
        ],
        encoded.into(),
        100,
        FixedBytes::from([1u8; 32]),
        0,
    );

    let blockchain_event = RegistryEvent::decode(&log).expect("Decoding should succeed");

    match blockchain_event.details {
        world_id_indexer::blockchain::RegistryEvent::AuthenticatorRemoved(ev) => {
            assert_eq!(ev.leaf_index, leaf_index);
            assert_eq!(ev.pubkey_id, pubkey_id);
            assert_eq!(ev.authenticator_address, auth_address);
            assert_eq!(ev.authenticator_pubkey, pubkey);
            assert_eq!(ev.old_offchain_signer_commitment, old_commitment);
            assert_eq!(ev.new_offchain_signer_commitment, new_commitment);
        }
        _ => panic!("Expected AuthenticatorRemoved event"),
    }
}

#[test]
fn test_decode_account_recovered_event() {
    let leaf_index = U256::from(1);
    let new_address = Address::from([5u8; 20]);
    let new_pubkey = U256::from(777);
    let old_commitment = U256::from(100);
    let new_commitment = U256::from(200);

    let event_data = WorldIdRegistry::AccountRecovered {
        leafIndex: leaf_index,
        newAuthenticatorAddress: new_address,
        newAuthenticatorPubkey: new_pubkey,
        oldOffchainSignerCommitment: old_commitment,
        newOffchainSignerCommitment: new_commitment,
    };

    let encoded = event_data.encode_data();

    let log = create_mock_rpc_log(
        Address::ZERO,
        vec![
            WorldIdRegistry::AccountRecovered::SIGNATURE_HASH,
            FixedBytes::from(leaf_index),
            new_address.into_word(),
            FixedBytes::from(new_pubkey),
        ],
        encoded.into(),
        100,
        FixedBytes::from([1u8; 32]),
        0,
    );

    let blockchain_event = RegistryEvent::decode(&log).expect("Decoding should succeed");

    match blockchain_event.details {
        world_id_indexer::blockchain::RegistryEvent::AccountRecovered(ev) => {
            assert_eq!(ev.leaf_index, leaf_index);
            assert_eq!(ev.new_authenticator_address, new_address);
            assert_eq!(ev.new_authenticator_pubkey, new_pubkey);
            assert_eq!(ev.old_offchain_signer_commitment, old_commitment);
            assert_eq!(ev.new_offchain_signer_commitment, new_commitment);
        }
        _ => panic!("Expected AccountRecovered event"),
    }
}

#[test]
fn test_decode_root_recorded_event() {
    let root = U256::from(123456);
    let timestamp = U256::from(1000000);

    let event_data = WorldIdRegistry::RootRecorded { root, timestamp };

    let encoded = event_data.encode_data();

    let log = create_mock_rpc_log(
        Address::ZERO,
        vec![
            WorldIdRegistry::RootRecorded::SIGNATURE_HASH,
            FixedBytes::from(root),
        ],
        encoded.into(),
        100,
        FixedBytes::from([1u8; 32]),
        0,
    );

    let blockchain_event = RegistryEvent::decode(&log).expect("Decoding should succeed");

    match blockchain_event.details {
        world_id_indexer::blockchain::RegistryEvent::RootRecorded(ev) => {
            assert_eq!(ev.root, root);
            assert_eq!(ev.timestamp, timestamp);
        }
        _ => panic!("Expected RootRecorded event"),
    }
}

#[test]
fn test_decode_log_with_missing_block_number() {
    let event_data = WorldIdRegistry::RootRecorded {
        root: U256::from(123),
        timestamp: U256::from(456),
    };

    let encoded = event_data.encode_data();

    let mut log = create_mock_rpc_log(
        Address::ZERO,
        vec![
            WorldIdRegistry::RootRecorded::SIGNATURE_HASH,
            FixedBytes::from(U256::from(123)),
        ],
        encoded.into(),
        100,
        FixedBytes::from([1u8; 32]),
        0,
    );

    // Remove block number
    log.block_number = None;

    let result = RegistryEvent::decode(&log);
    assert!(result.is_err(), "Decoding should fail without block number");
}

#[test]
fn test_decode_log_with_missing_tx_hash() {
    let event_data = WorldIdRegistry::RootRecorded {
        root: U256::from(123),
        timestamp: U256::from(456),
    };

    let encoded = event_data.encode_data();

    let mut log = create_mock_rpc_log(
        Address::ZERO,
        vec![
            WorldIdRegistry::RootRecorded::SIGNATURE_HASH,
            FixedBytes::from(U256::from(123)),
        ],
        encoded.into(),
        100,
        FixedBytes::from([1u8; 32]),
        0,
    );

    // Remove tx hash
    log.transaction_hash = None;

    let result = RegistryEvent::decode(&log);
    assert!(
        result.is_err(),
        "Decoding should fail without transaction hash"
    );
}

#[test]
fn test_decode_log_with_missing_log_index() {
    let event_data = WorldIdRegistry::RootRecorded {
        root: U256::from(123),
        timestamp: U256::from(456),
    };

    let encoded = event_data.encode_data();

    let mut log = create_mock_rpc_log(
        Address::ZERO,
        vec![
            WorldIdRegistry::RootRecorded::SIGNATURE_HASH,
            FixedBytes::from(U256::from(123)),
        ],
        encoded.into(),
        100,
        FixedBytes::from([1u8; 32]),
        0,
    );

    // Remove log index
    log.log_index = None;

    let result = RegistryEvent::decode(&log);
    assert!(result.is_err(), "Decoding should fail without log index");
}

#[test]
fn test_decode_unknown_event_signature() {
    let log = create_mock_rpc_log(
        Address::ZERO,
        vec![FixedBytes::from([0xFFu8; 32])], // Unknown signature
        Bytes::new(),
        100,
        FixedBytes::from([1u8; 32]),
        0,
    );

    let result = RegistryEvent::decode(&log);
    assert!(
        result.is_err(),
        "Decoding should fail for unknown event signature"
    );
}

#[test]
fn test_decode_log_with_no_topics() {
    let log = RpcLog {
        inner: Log {
            address: Address::ZERO,
            data: LogData::new_unchecked(vec![], Bytes::new()),
        },
        block_hash: Some(FixedBytes::ZERO),
        block_number: Some(100),
        block_timestamp: None,
        transaction_hash: Some(FixedBytes::from([1u8; 32])),
        transaction_index: Some(0),
        log_index: Some(0),
        removed: false,
    };

    let result = RegistryEvent::decode(&log);
    assert!(result.is_err(), "Decoding should fail with no topics");
}

#[test]
fn test_registry_event_signatures() {
    let signatures = RegistryEvent::signatures();

    // Should have all 6 event types
    assert_eq!(signatures.len(), 6);

    // Verify each signature is present
    assert!(signatures.contains(&WorldIdRegistry::AccountCreated::SIGNATURE_HASH));
    assert!(signatures.contains(&WorldIdRegistry::AccountUpdated::SIGNATURE_HASH));
    assert!(signatures.contains(&WorldIdRegistry::AuthenticatorInserted::SIGNATURE_HASH));
    assert!(signatures.contains(&WorldIdRegistry::AuthenticatorRemoved::SIGNATURE_HASH));
    assert!(signatures.contains(&WorldIdRegistry::AccountRecovered::SIGNATURE_HASH));
    assert!(signatures.contains(&WorldIdRegistry::RootRecorded::SIGNATURE_HASH));
}

#[test]
fn test_decode_account_created_with_multiple_authenticators() {
    let leaf_index = U256::from(1);
    let recovery_address = Address::from([1u8; 20]);
    let auth_addresses = vec![
        Address::from([2u8; 20]),
        Address::from([3u8; 20]),
        Address::from([4u8; 20]),
    ];
    let auth_pubkeys = vec![U256::from(123), U256::from(456), U256::from(789)];
    let commitment = U256::from(999);

    let event_data = WorldIdRegistry::AccountCreated {
        leafIndex: leaf_index,
        recoveryAddress: recovery_address,
        authenticatorAddresses: auth_addresses.clone(),
        authenticatorPubkeys: auth_pubkeys.clone(),
        offchainSignerCommitment: commitment,
    };

    let encoded = event_data.encode_data();

    let log = create_mock_rpc_log(
        Address::ZERO,
        vec![
            WorldIdRegistry::AccountCreated::SIGNATURE_HASH,
            FixedBytes::from(leaf_index),
            recovery_address.into_word(),
        ],
        encoded.into(),
        100,
        FixedBytes::from([1u8; 32]),
        0,
    );

    let blockchain_event = RegistryEvent::decode(&log).expect("Decoding should succeed");

    match blockchain_event.details {
        world_id_indexer::blockchain::RegistryEvent::AccountCreated(ev) => {
            assert_eq!(ev.authenticator_addresses.len(), 3);
            assert_eq!(ev.authenticator_pubkeys.len(), 3);
            assert_eq!(ev.authenticator_addresses, auth_addresses);
            assert_eq!(ev.authenticator_pubkeys, auth_pubkeys);
        }
        _ => panic!("Expected AccountCreated event"),
    }
}
