use alloy::{
    primitives::{Address, FixedBytes, Log, U256},
    sol_types::SolEvent,
};
use world_id_core::world_id_registry::WorldIdRegistry;

use super::{BlockchainError, BlockchainResult};

#[derive(Debug, Clone, PartialEq)]
pub struct BlockchainEvent<T: Clone> {
    pub block_number: u64,
    pub block_hash: U256,
    pub tx_hash: U256,
    pub log_index: u64,
    pub details: T,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AccountCreatedEvent {
    pub leaf_index: u64,
    pub recovery_address: Address,
    pub authenticator_addresses: Vec<Address>,
    pub authenticator_pubkeys: Vec<U256>,
    pub offchain_signer_commitment: U256,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AccountUpdatedEvent {
    pub leaf_index: u64,
    pub pubkey_id: u32,
    pub new_authenticator_pubkey: U256,
    pub old_authenticator_address: Address,
    pub new_authenticator_address: Address,
    pub old_offchain_signer_commitment: U256,
    pub new_offchain_signer_commitment: U256,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthenticatorInsertedEvent {
    pub leaf_index: u64,
    pub pubkey_id: u32,
    pub authenticator_address: Address,
    pub new_authenticator_pubkey: U256,
    pub old_offchain_signer_commitment: U256,
    pub new_offchain_signer_commitment: U256,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthenticatorRemovedEvent {
    pub leaf_index: u64,
    pub pubkey_id: u32,
    pub authenticator_address: Address,
    pub authenticator_pubkey: U256,
    pub old_offchain_signer_commitment: U256,
    pub new_offchain_signer_commitment: U256,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AccountRecoveredEvent {
    pub leaf_index: u64,
    pub new_authenticator_address: Address,
    pub new_authenticator_pubkey: U256,
    pub old_offchain_signer_commitment: U256,
    pub new_offchain_signer_commitment: U256,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RootRecordedEvent {
    pub root: U256,
    pub timestamp: U256,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RegistryEvent {
    AccountCreated(AccountCreatedEvent),
    AccountUpdated(AccountUpdatedEvent),
    AuthenticatorInserted(AuthenticatorInsertedEvent),
    AuthenticatorRemoved(AuthenticatorRemovedEvent),
    AccountRecovered(AccountRecoveredEvent),
    RootRecorded(RootRecordedEvent),
}

impl RegistryEvent {
    pub fn signatures() -> Vec<FixedBytes<32>> {
        vec![
            WorldIdRegistry::AccountCreated::SIGNATURE_HASH,
            WorldIdRegistry::AccountUpdated::SIGNATURE_HASH,
            WorldIdRegistry::AuthenticatorInserted::SIGNATURE_HASH,
            WorldIdRegistry::AuthenticatorRemoved::SIGNATURE_HASH,
            WorldIdRegistry::AccountRecovered::SIGNATURE_HASH,
            WorldIdRegistry::RootRecorded::SIGNATURE_HASH,
        ]
    }

    pub fn decode(lg: &alloy::rpc::types::Log) -> BlockchainResult<BlockchainEvent<RegistryEvent>> {
        if lg.topics().is_empty() {
            return Err(BlockchainError::EmptyTopics);
        }

        let event_sig = lg.topics()[0];

        let block_number = lg.block_number.ok_or(BlockchainError::MissingBlockNumber)?;
        let block_hash = lg.block_hash.ok_or(BlockchainError::MissingBlockHash)?;
        let tx_hash = lg.transaction_hash.ok_or(BlockchainError::MissingTxHash)?;
        let log_index = lg.log_index.ok_or(BlockchainError::MissingLogIndex)?;

        let details = match event_sig {
            WorldIdRegistry::AccountCreated::SIGNATURE_HASH => {
                RegistryEvent::AccountCreated(Self::decode_account_created(lg)?)
            }
            WorldIdRegistry::AccountUpdated::SIGNATURE_HASH => {
                RegistryEvent::AccountUpdated(Self::decode_account_updated(lg)?)
            }
            WorldIdRegistry::AuthenticatorInserted::SIGNATURE_HASH => {
                RegistryEvent::AuthenticatorInserted(Self::decode_authenticator_inserted(lg)?)
            }
            WorldIdRegistry::AuthenticatorRemoved::SIGNATURE_HASH => {
                RegistryEvent::AuthenticatorRemoved(Self::decode_authenticator_removed(lg)?)
            }
            WorldIdRegistry::AccountRecovered::SIGNATURE_HASH => {
                RegistryEvent::AccountRecovered(Self::decode_account_recovered(lg)?)
            }
            WorldIdRegistry::RootRecorded::SIGNATURE_HASH => {
                RegistryEvent::RootRecorded(Self::decode_root_recorded(lg)?)
            }
            _ => return Err(BlockchainError::UnknownEventSignature(event_sig)),
        };

        Ok(BlockchainEvent {
            block_number,
            block_hash: block_hash.into(),
            tx_hash: tx_hash.into(),
            log_index,
            details,
        })
    }

    fn decode_account_created(
        lg: &alloy::rpc::types::Log,
    ) -> BlockchainResult<AccountCreatedEvent> {
        let prim = Log::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
            .ok_or_else(|| BlockchainError::InvalidLog)?;
        let typed = WorldIdRegistry::AccountCreated::decode_log(&prim)
            .map_err(BlockchainError::LogDecode)?;

        // TODO: Validate pubkey is valid affine compressed
        Ok(AccountCreatedEvent {
            leaf_index: typed.data.leafIndex,
            recovery_address: typed.data.recoveryAddress,
            authenticator_addresses: typed.data.authenticatorAddresses,
            authenticator_pubkeys: typed.data.authenticatorPubkeys,
            offchain_signer_commitment: typed.data.offchainSignerCommitment,
        })
    }

    fn decode_account_updated(
        lg: &alloy::rpc::types::Log,
    ) -> BlockchainResult<AccountUpdatedEvent> {
        let prim = Log::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
            .ok_or_else(|| BlockchainError::InvalidLog)?;
        let typed = WorldIdRegistry::AccountUpdated::decode_log(&prim)
            .map_err(BlockchainError::LogDecode)?;

        Ok(AccountUpdatedEvent {
            leaf_index: typed.data.leafIndex,
            pubkey_id: typed.data.pubkeyId,
            new_authenticator_pubkey: typed.data.newAuthenticatorPubkey,
            old_authenticator_address: typed.data.oldAuthenticatorAddress,
            new_authenticator_address: typed.data.newAuthenticatorAddress,
            old_offchain_signer_commitment: typed.data.oldOffchainSignerCommitment,
            new_offchain_signer_commitment: typed.data.newOffchainSignerCommitment,
        })
    }

    fn decode_authenticator_inserted(
        lg: &alloy::rpc::types::Log,
    ) -> BlockchainResult<AuthenticatorInsertedEvent> {
        let prim = Log::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
            .ok_or_else(|| BlockchainError::InvalidLog)?;
        let typed = WorldIdRegistry::AuthenticatorInserted::decode_log(&prim)
            .map_err(BlockchainError::LogDecode)?;

        Ok(AuthenticatorInsertedEvent {
            leaf_index: typed.data.leafIndex,
            pubkey_id: typed.data.pubkeyId,
            authenticator_address: typed.data.authenticatorAddress,
            new_authenticator_pubkey: typed.data.newAuthenticatorPubkey,
            old_offchain_signer_commitment: typed.data.oldOffchainSignerCommitment,
            new_offchain_signer_commitment: typed.data.newOffchainSignerCommitment,
        })
    }

    fn decode_authenticator_removed(
        lg: &alloy::rpc::types::Log,
    ) -> BlockchainResult<AuthenticatorRemovedEvent> {
        let prim = Log::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
            .ok_or_else(|| BlockchainError::InvalidLog)?;
        let typed = WorldIdRegistry::AuthenticatorRemoved::decode_log(&prim)
            .map_err(BlockchainError::LogDecode)?;

        Ok(AuthenticatorRemovedEvent {
            leaf_index: typed.data.leafIndex,
            pubkey_id: typed.data.pubkeyId,
            authenticator_address: typed.data.authenticatorAddress,
            authenticator_pubkey: typed.data.authenticatorPubkey,
            old_offchain_signer_commitment: typed.data.oldOffchainSignerCommitment,
            new_offchain_signer_commitment: typed.data.newOffchainSignerCommitment,
        })
    }

    fn decode_account_recovered(
        lg: &alloy::rpc::types::Log,
    ) -> BlockchainResult<AccountRecoveredEvent> {
        let prim = Log::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
            .ok_or_else(|| BlockchainError::InvalidLog)?;
        let typed = WorldIdRegistry::AccountRecovered::decode_log(&prim)
            .map_err(BlockchainError::LogDecode)?;

        Ok(AccountRecoveredEvent {
            leaf_index: typed.data.leafIndex,
            new_authenticator_address: typed.data.newAuthenticatorAddress,
            new_authenticator_pubkey: typed.data.newAuthenticatorPubkey,
            old_offchain_signer_commitment: typed.data.oldOffchainSignerCommitment,
            new_offchain_signer_commitment: typed.data.newOffchainSignerCommitment,
        })
    }

    fn decode_root_recorded(lg: &alloy::rpc::types::Log) -> BlockchainResult<RootRecordedEvent> {
        let prim = Log::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
            .ok_or_else(|| BlockchainError::InvalidLog)?;
        let typed =
            WorldIdRegistry::RootRecorded::decode_log(&prim).map_err(BlockchainError::LogDecode)?;

        Ok(RootRecordedEvent {
            root: typed.data.root,
            timestamp: typed.data.timestamp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        primitives::{Bytes, FixedBytes, Log, LogData},
        rpc::types::Log as RpcLog,
        sol_types::SolEvent,
    };
    use world_id_core::world_id_registry::WorldIdRegistry;

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
        let leaf_index = 1u64;
        let recovery_address = Address::from([1u8; 20]);
        let auth_addresses = vec![Address::from([2u8; 20])];
        let auth_pubkeys = vec![U256::from(123)];
        let commitment = U256::from(456);

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
                FixedBytes::from(U256::from(leaf_index)),
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
            RegistryEvent::AccountCreated(ev) => {
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
        let leaf_index = 1u64;
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
                FixedBytes::from(U256::from(leaf_index)),
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
            RegistryEvent::AccountUpdated(ev) => {
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
        let leaf_index = 1u64;
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
                FixedBytes::from(U256::from(leaf_index)),
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
            RegistryEvent::AuthenticatorInserted(ev) => {
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
        let leaf_index = 1u64;
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
                FixedBytes::from(U256::from(leaf_index)),
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
            RegistryEvent::AuthenticatorRemoved(ev) => {
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
        let leaf_index = 1u64;
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
                FixedBytes::from(U256::from(leaf_index)),
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
            RegistryEvent::AccountRecovered(ev) => {
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
            RegistryEvent::RootRecorded(ev) => {
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

        log.log_index = None;

        let result = RegistryEvent::decode(&log);
        assert!(result.is_err(), "Decoding should fail without log index");
    }

    #[test]
    fn test_decode_unknown_event_signature() {
        let log = create_mock_rpc_log(
            Address::ZERO,
            vec![FixedBytes::from([0xFFu8; 32])],
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

        assert_eq!(signatures.len(), 6);

        assert!(signatures.contains(&WorldIdRegistry::AccountCreated::SIGNATURE_HASH));
        assert!(signatures.contains(&WorldIdRegistry::AccountUpdated::SIGNATURE_HASH));
        assert!(signatures.contains(&WorldIdRegistry::AuthenticatorInserted::SIGNATURE_HASH));
        assert!(signatures.contains(&WorldIdRegistry::AuthenticatorRemoved::SIGNATURE_HASH));
        assert!(signatures.contains(&WorldIdRegistry::AccountRecovered::SIGNATURE_HASH));
        assert!(signatures.contains(&WorldIdRegistry::RootRecorded::SIGNATURE_HASH));
    }

    #[test]
    fn test_decode_account_created_with_multiple_authenticators() {
        let leaf_index = 1u64;
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
                FixedBytes::from(U256::from(leaf_index)),
                recovery_address.into_word(),
            ],
            encoded.into(),
            100,
            FixedBytes::from([1u8; 32]),
            0,
        );

        let blockchain_event = RegistryEvent::decode(&log).expect("Decoding should succeed");

        match blockchain_event.details {
            RegistryEvent::AccountCreated(ev) => {
                assert_eq!(ev.authenticator_addresses.len(), 3);
                assert_eq!(ev.authenticator_pubkeys.len(), 3);
                assert_eq!(ev.authenticator_addresses, auth_addresses);
                assert_eq!(ev.authenticator_pubkeys, auth_pubkeys);
            }
            _ => panic!("Expected AccountCreated event"),
        }
    }
}
