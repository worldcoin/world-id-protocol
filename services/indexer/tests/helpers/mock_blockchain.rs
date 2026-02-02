use alloy::primitives::{Address, U256};
use world_id_indexer::blockchain::{BlockchainEvent, RegistryEvent};

/// Create a mock AccountCreated event for testing
#[allow(dead_code)]
pub fn mock_account_created_event(
    block_number: u64,
    log_index: u64,
    leaf_index: U256,
    recovery_address: Address,
    commitment: U256,
) -> BlockchainEvent<RegistryEvent> {
    BlockchainEvent {
        block_number,
        tx_hash: U256::from(1),
        log_index,
        details: RegistryEvent::AccountCreated(world_id_indexer::blockchain::AccountCreatedEvent {
            leaf_index,
            recovery_address,
            authenticator_addresses: vec![],
            authenticator_pubkeys: vec![],
            offchain_signer_commitment: commitment,
        }),
    }
}

/// Create a mock AccountUpdated event for testing
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub fn mock_account_updated_event(
    block_number: u64,
    log_index: u64,
    leaf_index: U256,
    pubkey_id: u32,
    new_address: Address,
    new_pubkey: U256,
    old_commitment: U256,
    new_commitment: U256,
) -> BlockchainEvent<RegistryEvent> {
    BlockchainEvent {
        block_number,
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
#[allow(dead_code)]
pub fn mock_authenticator_inserted_event(
    block_number: u64,
    log_index: u64,
    leaf_index: U256,
    pubkey_id: u32,
    authenticator_address: Address,
    new_pubkey: U256,
    old_commitment: U256,
    new_commitment: U256,
) -> BlockchainEvent<RegistryEvent> {
    BlockchainEvent {
        block_number,
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
#[allow(dead_code)]
pub fn mock_authenticator_removed_event(
    block_number: u64,
    log_index: u64,
    leaf_index: U256,
    pubkey_id: u32,
    authenticator_address: Address,
    pubkey: U256,
    old_commitment: U256,
    new_commitment: U256,
) -> BlockchainEvent<RegistryEvent> {
    BlockchainEvent {
        block_number,
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
#[allow(dead_code)]
pub fn mock_account_recovered_event(
    block_number: u64,
    log_index: u64,
    leaf_index: U256,
    new_address: Address,
    new_pubkey: U256,
    old_commitment: U256,
    new_commitment: U256,
) -> BlockchainEvent<RegistryEvent> {
    BlockchainEvent {
        block_number,
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
#[allow(dead_code)]
pub fn mock_root_recorded_event(
    block_number: u64,
    log_index: u64,
    root: U256,
    timestamp: U256,
) -> BlockchainEvent<RegistryEvent> {
    BlockchainEvent {
        block_number,
        tx_hash: U256::from(1),
        log_index,
        details: RegistryEvent::RootRecorded(world_id_indexer::blockchain::RootRecordedEvent {
            root,
            timestamp,
        }),
    }
}
