#![allow(dead_code)]

use alloy::primitives::{Address, U256};
use world_id_indexer::blockchain::{BlockchainEvent, RegistryEvent};

/// Create a mock AccountCreated event for testing
pub fn mock_account_created_event(
    block_number: u64,
    log_index: u64,
    leaf_index: u64,
    recovery_address: Address,
    commitment: U256,
) -> BlockchainEvent<RegistryEvent> {
    mock_account_created_event_with_authenticators(
        block_number,
        log_index,
        leaf_index,
        recovery_address,
        vec![],
        vec![],
        commitment,
    )
}

/// Create a mock AccountCreated event with authenticators for testing
pub fn mock_account_created_event_with_authenticators(
    block_number: u64,
    log_index: u64,
    leaf_index: u64,
    recovery_address: Address,
    authenticator_addresses: Vec<Address>,
    authenticator_pubkeys: Vec<U256>,
    commitment: U256,
) -> BlockchainEvent<RegistryEvent> {
    BlockchainEvent {
        block_number,
        block_hash: U256::from(1),
        tx_hash: U256::from(1),
        log_index,
        details: RegistryEvent::AccountCreated(world_id_indexer::blockchain::AccountCreatedEvent {
            leaf_index,
            recovery_address,
            authenticator_addresses,
            authenticator_pubkeys,
            offchain_signer_commitment: commitment,
        }),
    }
}

/// Create a mock AccountUpdated event for testing
#[allow(clippy::too_many_arguments)]
pub fn mock_account_updated_event(
    block_number: u64,
    log_index: u64,
    leaf_index: u64,
    pubkey_id: u32,
    new_address: Address,
    new_pubkey: U256,
    old_commitment: U256,
    new_commitment: U256,
) -> BlockchainEvent<RegistryEvent> {
    BlockchainEvent {
        block_number,
        block_hash: U256::from(1),
        tx_hash: U256::from(1),
        log_index,
        details: RegistryEvent::AccountUpdated(world_id_indexer::blockchain::AccountUpdatedEvent {
            leaf_index,
            pubkey_id,
            new_authenticator_pubkey: new_pubkey,
            old_authenticator_address: Address::ZERO,
            new_authenticator_address: new_address,
            old_offchain_signer_commitment: old_commitment,
            new_offchain_signer_commitment: new_commitment,
        }),
    }
}

/// Create a mock AuthenticatorInserted event for testing
#[allow(clippy::too_many_arguments)]
pub fn mock_authenticator_inserted_event(
    block_number: u64,
    log_index: u64,
    leaf_index: u64,
    pubkey_id: u32,
    authenticator_address: Address,
    new_pubkey: U256,
    old_commitment: U256,
    new_commitment: U256,
) -> BlockchainEvent<RegistryEvent> {
    BlockchainEvent {
        block_number,
        block_hash: U256::from(1),
        tx_hash: U256::from(1),
        log_index,
        details: RegistryEvent::AuthenticatorInserted(
            world_id_indexer::blockchain::AuthenticatorInsertedEvent {
                leaf_index,
                pubkey_id,
                authenticator_address,
                new_authenticator_pubkey: new_pubkey,
                old_offchain_signer_commitment: old_commitment,
                new_offchain_signer_commitment: new_commitment,
            },
        ),
    }
}

/// Create a mock AuthenticatorRemoved event for testing
#[allow(clippy::too_many_arguments)]
pub fn mock_authenticator_removed_event(
    block_number: u64,
    log_index: u64,
    leaf_index: u64,
    pubkey_id: u32,
    authenticator_address: Address,
    pubkey: U256,
    old_commitment: U256,
    new_commitment: U256,
) -> BlockchainEvent<RegistryEvent> {
    BlockchainEvent {
        block_number,
        block_hash: U256::from(1),
        tx_hash: U256::from(1),
        log_index,
        details: RegistryEvent::AuthenticatorRemoved(
            world_id_indexer::blockchain::AuthenticatorRemovedEvent {
                leaf_index,
                pubkey_id,
                authenticator_address,
                authenticator_pubkey: pubkey,
                old_offchain_signer_commitment: old_commitment,
                new_offchain_signer_commitment: new_commitment,
            },
        ),
    }
}

/// Create a mock AccountRecovered event for testing
pub fn mock_account_recovered_event(
    block_number: u64,
    log_index: u64,
    leaf_index: u64,
    new_address: Address,
    new_pubkey: U256,
    old_commitment: U256,
    new_commitment: U256,
) -> BlockchainEvent<RegistryEvent> {
    BlockchainEvent {
        block_number,
        block_hash: U256::from(1),
        tx_hash: U256::from(1),
        log_index,
        details: RegistryEvent::AccountRecovered(
            world_id_indexer::blockchain::AccountRecoveredEvent {
                leaf_index,
                new_authenticator_address: new_address,
                new_authenticator_pubkey: new_pubkey,
                old_offchain_signer_commitment: old_commitment,
                new_offchain_signer_commitment: new_commitment,
            },
        ),
    }
}

/// Create a mock RootRecorded event for testing
pub fn mock_root_recorded_event(
    block_number: u64,
    log_index: u64,
    root: U256,
    timestamp: U256,
) -> BlockchainEvent<RegistryEvent> {
    BlockchainEvent {
        block_number,
        block_hash: U256::from(1),
        tx_hash: U256::from(1),
        log_index,
        details: RegistryEvent::RootRecorded(world_id_indexer::blockchain::RootRecordedEvent {
            root,
            timestamp,
        }),
    }
}
