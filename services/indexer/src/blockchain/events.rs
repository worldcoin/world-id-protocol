use alloy::{
    primitives::{Address, FixedBytes, Log, U256},
    sol_types::SolEvent,
};
use world_id_core::world_id_registry::WorldIdRegistry;

#[derive(Debug, Clone)]
pub struct BlockchainEvent<T: Clone> {
    pub block_number: u64,
    pub tx_hash: U256,
    pub log_index: u64,
    pub details: T,
}

#[derive(Debug, Clone)]
pub struct AccountCreatedEvent {
    pub leaf_index: U256,
    pub recovery_address: Address,
    pub authenticator_addresses: Vec<Address>,
    pub authenticator_pubkeys: Vec<U256>,
    pub offchain_signer_commitment: U256,
}

#[derive(Debug, Clone)]
pub struct AccountUpdatedEvent {
    pub leaf_index: U256,
    pub pubkey_id: u32,
    pub new_authenticator_pubkey: U256,
    pub old_authenticator_address: Address,
    pub new_authenticator_address: Address,
    pub old_offchain_signer_commitment: U256,
    pub new_offchain_signer_commitment: U256,
}

#[derive(Debug, Clone)]
pub struct AuthenticatorInsertedEvent {
    pub leaf_index: U256,
    pub pubkey_id: u32,
    pub authenticator_address: Address,
    pub new_authenticator_pubkey: U256,
    pub old_offchain_signer_commitment: U256,
    pub new_offchain_signer_commitment: U256,
}

#[derive(Debug, Clone)]
pub struct AuthenticatorRemovedEvent {
    pub leaf_index: U256,
    pub pubkey_id: u32,
    pub authenticator_address: Address,
    pub authenticator_pubkey: U256,
    pub old_offchain_signer_commitment: U256,
    pub new_offchain_signer_commitment: U256,
}

#[derive(Debug, Clone)]
pub struct AccountRecoveredEvent {
    pub leaf_index: U256,
    pub new_authenticator_address: Address,
    pub new_authenticator_pubkey: U256,
    pub old_offchain_signer_commitment: U256,
    pub new_offchain_signer_commitment: U256,
}

#[derive(Debug, Clone)]
pub struct RootRecordedEvent {
    pub root: U256,
    pub timestamp: U256,
}

#[derive(Debug, Clone)]
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

    pub fn decode(lg: &alloy::rpc::types::Log) -> anyhow::Result<BlockchainEvent<RegistryEvent>> {
        if lg.topics().is_empty() {
            anyhow::bail!("log has no topics");
        }

        let event_sig = lg.topics()[0];

        let block_number = lg
            .block_number
            .ok_or(anyhow::anyhow!("missing block number"))?;
        let tx_hash = lg
            .transaction_hash
            .ok_or(anyhow::anyhow!("missing transaction hash"))?;
        let log_index = lg.log_index.ok_or(anyhow::anyhow!("missing log index"))?;

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
            _ => anyhow::bail!("unknown event signature: {event_sig:?}"),
        };

        Ok(BlockchainEvent {
            block_number,
            tx_hash: tx_hash.into(),
            log_index,
            details,
        })
    }

    fn decode_account_created(lg: &alloy::rpc::types::Log) -> anyhow::Result<AccountCreatedEvent> {
        let prim = Log::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
            .ok_or_else(|| anyhow::anyhow!("invalid log for decoding"))?;
        let typed = WorldIdRegistry::AccountCreated::decode_log(&prim)?;

        // TODO: Validate pubkey is valid affine compressed
        Ok(AccountCreatedEvent {
            leaf_index: typed.data.leafIndex,
            recovery_address: typed.data.recoveryAddress,
            authenticator_addresses: typed.data.authenticatorAddresses,
            authenticator_pubkeys: typed.data.authenticatorPubkeys,
            offchain_signer_commitment: typed.data.offchainSignerCommitment,
        })
    }

    fn decode_account_updated(lg: &alloy::rpc::types::Log) -> anyhow::Result<AccountUpdatedEvent> {
        let prim = Log::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
            .ok_or_else(|| anyhow::anyhow!("invalid log for decoding"))?;
        let typed = WorldIdRegistry::AccountUpdated::decode_log(&prim)?;

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
    ) -> anyhow::Result<AuthenticatorInsertedEvent> {
        let prim = Log::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
            .ok_or_else(|| anyhow::anyhow!("invalid log for decoding"))?;
        let typed = WorldIdRegistry::AuthenticatorInserted::decode_log(&prim)?;

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
    ) -> anyhow::Result<AuthenticatorRemovedEvent> {
        let prim = Log::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
            .ok_or_else(|| anyhow::anyhow!("invalid log for decoding"))?;
        let typed = WorldIdRegistry::AuthenticatorRemoved::decode_log(&prim)?;

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
    ) -> anyhow::Result<AccountRecoveredEvent> {
        let prim = Log::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
            .ok_or_else(|| anyhow::anyhow!("invalid log for decoding"))?;
        let typed = WorldIdRegistry::AccountRecovered::decode_log(&prim)?;

        Ok(AccountRecoveredEvent {
            leaf_index: typed.data.leafIndex,
            new_authenticator_address: typed.data.newAuthenticatorAddress,
            new_authenticator_pubkey: typed.data.newAuthenticatorPubkey,
            old_offchain_signer_commitment: typed.data.oldOffchainSignerCommitment,
            new_offchain_signer_commitment: typed.data.newOffchainSignerCommitment,
        })
    }

    fn decode_root_recorded(lg: &alloy::rpc::types::Log) -> anyhow::Result<RootRecordedEvent> {
        let prim = Log::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
            .ok_or_else(|| anyhow::anyhow!("invalid log for decoding"))?;
        let typed = WorldIdRegistry::RootRecorded::decode_log(&prim)?;

        Ok(RootRecordedEvent {
            root: typed.data.root,
            timestamp: typed.data.timestamp,
        })
    }
}
