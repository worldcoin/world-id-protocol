use crate::events::{
    AccountCreatedEvent, AccountRecoveredEvent, AccountUpdatedEvent, AuthenticatorInsertedEvent,
    AuthenticatorRemovedEvent, RegistryEvent,
};
use alloy::{primitives::Log, sol_types::SolEvent};
use world_id_core::world_id_registry::WorldIdRegistry;

pub fn decode_account_created(lg: &alloy::rpc::types::Log) -> anyhow::Result<AccountCreatedEvent> {
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

pub fn decode_account_updated(lg: &alloy::rpc::types::Log) -> anyhow::Result<AccountUpdatedEvent> {
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

pub fn decode_authenticator_inserted(
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

pub fn decode_authenticator_removed(
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

pub fn decode_account_recovered(
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

pub fn decode_registry_event(lg: &alloy::rpc::types::Log) -> anyhow::Result<RegistryEvent> {
    if lg.topics().is_empty() {
        anyhow::bail!("log has no topics");
    }

    let event_sig = lg.topics()[0];

    if event_sig == WorldIdRegistry::AccountCreated::SIGNATURE_HASH {
        Ok(RegistryEvent::AccountCreated(decode_account_created(lg)?))
    } else if event_sig == WorldIdRegistry::AccountUpdated::SIGNATURE_HASH {
        Ok(RegistryEvent::AccountUpdated(decode_account_updated(lg)?))
    } else if event_sig == WorldIdRegistry::AuthenticatorInserted::SIGNATURE_HASH {
        Ok(RegistryEvent::AuthenticatorInserted(
            decode_authenticator_inserted(lg)?,
        ))
    } else if event_sig == WorldIdRegistry::AuthenticatorRemoved::SIGNATURE_HASH {
        Ok(RegistryEvent::AuthenticatorRemoved(
            decode_authenticator_removed(lg)?,
        ))
    } else if event_sig == WorldIdRegistry::AccountRecovered::SIGNATURE_HASH {
        Ok(RegistryEvent::AccountRecovered(decode_account_recovered(
            lg,
        )?))
    } else {
        anyhow::bail!("unknown event signature: {event_sig:?}")
    }
}
