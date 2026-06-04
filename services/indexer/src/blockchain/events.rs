use alloy::{
    primitives::{FixedBytes, U256},
    sol_types::{SolEvent, SolEventInterface},
};
use world_id_registries::world_id::WorldIdRegistry;

use super::{BlockchainError, BlockchainResult};

/// Re-export the alloy-generated registry event types under stable local names.
///
/// These are the types produced by the `sol!` bindings in `world_id_registries`;
/// the indexer no longer hand-rolls parallel copies of them.
pub use world_id_registries::world_id::WorldIdRegistry::{
    AccountCreated as AccountCreatedEvent, AccountRecovered as AccountRecoveredEvent,
    AccountUpdated as AccountUpdatedEvent, AuthenticatorInserted as AuthenticatorInsertedEvent,
    AuthenticatorRemoved as AuthenticatorRemovedEvent, RootRecorded as RootRecordedEvent,
    WorldIdRegistryEvents as RegistryEvent,
};

/// A decoded registry event together with the block metadata of the log it was
/// decoded from.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockchainEvent<T: Clone> {
    pub block_number: u64,
    pub block_hash: U256,
    pub tx_hash: U256,
    pub log_index: u64,
    pub details: T,
}

/// Extension methods on the generated [`RegistryEvent`] enum.
///
/// `RegistryEvent` aliases a type defined in `world_id_registries`, so these
/// cannot be inherent methods (orphan rule) and live on this trait instead.
pub trait RegistryEventExt: Sized + Clone {
    /// The topic-0 signature hashes of every registry event variant, used to
    /// build log filters.
    fn signatures() -> Vec<FixedBytes<32>>;

    /// Decode an RPC log into a [`BlockchainEvent`], pulling block metadata from
    /// the log and delegating event-body decoding to the generated bindings.
    fn decode(log: &alloy::rpc::types::Log) -> BlockchainResult<BlockchainEvent<Self>>;
}

impl RegistryEventExt for RegistryEvent {
    fn signatures() -> Vec<FixedBytes<32>> {
        vec![
            WorldIdRegistry::AccountCreated::SIGNATURE_HASH,
            WorldIdRegistry::AccountUpdated::SIGNATURE_HASH,
            WorldIdRegistry::AuthenticatorInserted::SIGNATURE_HASH,
            WorldIdRegistry::AuthenticatorRemoved::SIGNATURE_HASH,
            WorldIdRegistry::AccountRecovered::SIGNATURE_HASH,
            WorldIdRegistry::RootRecorded::SIGNATURE_HASH,
        ]
    }

    fn decode(log: &alloy::rpc::types::Log) -> BlockchainResult<BlockchainEvent<Self>> {
        let block_number = log
            .block_number
            .ok_or(BlockchainError::MissingBlockNumber)?;
        let block_hash = log.block_hash.ok_or(BlockchainError::MissingBlockHash)?;
        let tx_hash = log.transaction_hash.ok_or(BlockchainError::MissingTxHash)?;
        let log_index = log.log_index.ok_or(BlockchainError::MissingLogIndex)?;

        let details = RegistryEvent::decode_log(&log.inner)?.data;

        Ok(BlockchainEvent {
            block_number,
            block_hash: block_hash.into(),
            tx_hash: tx_hash.into(),
            log_index,
            details,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        primitives::{Address, Bytes, FixedBytes, Log, LogData, address},
        rpc::types::Log as RpcLog,
    };

    /// Helper to create a mock RPC log carrying the given topics and data.
    fn mock_rpc_log(topics: Vec<FixedBytes<32>>, data: Bytes) -> RpcLog {
        RpcLog {
            inner: Log {
                address: Address::ZERO,
                data: LogData::new_unchecked(topics, data),
            },
            block_hash: Some(FixedBytes::ZERO),
            block_number: Some(100),
            block_timestamp: None,
            transaction_hash: Some(FixedBytes::from([1u8; 32])),
            transaction_index: Some(0),
            log_index: Some(3),
            removed: false,
        }
    }

    #[test]
    fn decodes_account_created_with_metadata() {
        let leaf_index = 1u64;
        let recovery_address = address!("0x0000000000000000000000000000000000000011");
        let event = WorldIdRegistry::AccountCreated {
            leafIndex: leaf_index,
            recoveryAddress: recovery_address,
            authenticatorAddresses: vec![address!("0x0000000000000000000000000000000000000022")],
            authenticatorPubkeys: vec![U256::from(123)],
            offchainSignerCommitment: U256::from(456),
        };

        let log = mock_rpc_log(
            vec![
                WorldIdRegistry::AccountCreated::SIGNATURE_HASH,
                FixedBytes::from(U256::from(leaf_index)),
                recovery_address.into_word(),
            ],
            event.encode_data().into(),
        );

        let decoded = RegistryEvent::decode(&log).expect("decoding should succeed");
        assert_eq!(decoded.block_number, 100);
        assert_eq!(decoded.log_index, 3);
        match decoded.details {
            RegistryEvent::AccountCreated(ev) => {
                assert_eq!(ev.leafIndex, leaf_index);
                assert_eq!(ev.recoveryAddress, recovery_address);
                assert_eq!(ev.offchainSignerCommitment, U256::from(456));
            }
            other => panic!("expected AccountCreated, got {other:?}"),
        }
    }

    #[test]
    fn decodes_root_recorded() {
        let event = WorldIdRegistry::RootRecorded {
            root: U256::from(123456),
            timestamp: U256::from(1_000_000),
        };
        let log = mock_rpc_log(
            vec![
                WorldIdRegistry::RootRecorded::SIGNATURE_HASH,
                FixedBytes::from(U256::from(123456)),
            ],
            event.encode_data().into(),
        );

        let decoded = RegistryEvent::decode(&log).expect("decoding should succeed");
        match decoded.details {
            RegistryEvent::RootRecorded(ev) => {
                assert_eq!(ev.root, U256::from(123456));
                assert_eq!(ev.timestamp, U256::from(1_000_000));
            }
            other => panic!("expected RootRecorded, got {other:?}"),
        }
    }

    #[test]
    fn signatures_cover_all_variants() {
        assert_eq!(RegistryEvent::signatures().len(), 6);
    }

    #[test]
    fn decode_unknown_signature_errors() {
        let log = mock_rpc_log(vec![FixedBytes::from([0xFFu8; 32])], Bytes::new());
        assert!(RegistryEvent::decode(&log).is_err());
    }

    #[test]
    fn decode_missing_block_number_errors() {
        let event = WorldIdRegistry::RootRecorded {
            root: U256::from(1),
            timestamp: U256::from(2),
        };
        let mut log = mock_rpc_log(
            vec![
                WorldIdRegistry::RootRecorded::SIGNATURE_HASH,
                FixedBytes::from(U256::from(1)),
            ],
            event.encode_data().into(),
        );
        log.block_number = None;
        assert!(matches!(
            RegistryEvent::decode(&log),
            Err(BlockchainError::MissingBlockNumber)
        ));
    }
}
