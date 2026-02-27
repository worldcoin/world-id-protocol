use alloy::{
    primitives::Address,
    providers::{DynProvider, Provider},
    rpc::types::Filter,
    sol_types::SolEvent,
};
use eyre::Result;
use futures::Stream;
use futures_util::StreamExt;
use tracing::info;

use crate::bindings::{
    ICredentialSchemaIssuerRegistry, IOprfKeyRegistry, IRpRegistry, IWorldIDSource,
};
use crate::proof::ChainCommitment;

/// Subscribes to `ChainCommitted` events on the WorldIDSource contract.
/// Returns a stream of `ChainCommitment` values ready for relay.
pub async fn watch_chain_committed(
    provider: &DynProvider,
    source_address: Address,
) -> Result<impl Stream<Item = Result<ChainCommitment>>> {
    let filter = Filter::new()
        .address(source_address)
        .event_signature(IWorldIDSource::ChainCommitted::SIGNATURE_HASH);

    let sub = provider.subscribe_logs(&filter).await?;

    info!(%source_address, "subscribed to ChainCommitted events");

    Ok(sub.into_stream().map(move |log| {
        let decoded = IWorldIDSource::ChainCommitted::decode_log(log.as_ref())?;
        Ok(ChainCommitment {
            chain_head: decoded.keccakChain,
            block_number: decoded.blockNumber.to::<u64>(),
            chain_id: decoded.chainId.to::<u64>(),
            commitment_payload: decoded.commitment.clone(),
        })
    }))
}

/// Watches the CredentialSchemaIssuerRegistry for any issuer changes and returns
/// the affected `issuerSchemaId` values.
///
/// Tracks: `IssuerSchemaRegistered`, `IssuerSchemaRemoved`, `IssuerSchemaPubkeyUpdated`.
/// These are the events that indicate a pubkey has changed and needs to be propagated.
pub async fn watch_issuer_changes(
    provider: &DynProvider,
    registry_address: Address,
) -> Result<impl Stream<Item = Result<u64>>> {
    let filter = Filter::new()
        .address(registry_address)
        .event_signature(vec![
            ICredentialSchemaIssuerRegistry::IssuerSchemaRegistered::SIGNATURE_HASH,
            ICredentialSchemaIssuerRegistry::IssuerSchemaRemoved::SIGNATURE_HASH,
            ICredentialSchemaIssuerRegistry::IssuerSchemaPubkeyUpdated::SIGNATURE_HASH,
        ]);

    let sub = provider.subscribe_logs(&filter).await?;

    info!(%registry_address, "subscribed to issuer registry events");

    Ok(sub.into_stream().map(move |log| {
        // All three events have issuerSchemaId as topic1 (indexed uint64).
        let topic1 = log
            .topics()
            .get(1)
            .ok_or_else(|| eyre::eyre!("missing topic1 on issuer registry event"))?;
        let id = u64::try_from(alloy_primitives::U256::from_be_bytes(topic1.0))
            .map_err(|e| eyre::eyre!("issuerSchemaId overflow: {e}"))?;
        Ok(id)
    }))
}

/// Watches the OprfKeyRegistry for finalized key generation and returns
/// the affected `oprfKeyId` values.
///
/// Tracks: `SecretGenFinalize` -- emitted when an OPRF key completes DKG.
pub async fn watch_oprf_key_changes(
    provider: &DynProvider,
    oprf_registry_address: Address,
) -> Result<impl Stream<Item = Result<u64>>> {
    let filter = Filter::new()
        .address(oprf_registry_address)
        .event_signature(IOprfKeyRegistry::SecretGenFinalize::SIGNATURE_HASH);

    let sub = provider.subscribe_logs(&filter).await?;

    info!(%oprf_registry_address, "subscribed to OPRF key finalization events");

    Ok(sub.into_stream().map(move |log| {
        let decoded = IOprfKeyRegistry::SecretGenFinalize::decode_log(log.as_ref())?;
        // oprfKeyId is uint160 but we return as u64. In practice the IDs are
        // uint160(rpId) or uint160(issuerSchemaId), which are small values today.
        let id = u64::try_from(decoded.oprfKeyId)
            .map_err(|e| eyre::eyre!("oprfKeyId overflow: {e}"))?;
        Ok(id)
    }))
}

/// Watches the RpRegistry for new RP registrations and returns the `oprfKeyId`
/// (which equals `uint160(rpId)`) for newly registered RPs.
///
/// This is needed because each RP registration triggers OPRF key generation,
/// and the relay needs to include these OPRF key IDs in `propagateState()`.
pub async fn watch_rp_registrations(
    provider: &DynProvider,
    rp_registry_address: Address,
) -> Result<impl Stream<Item = Result<u64>>> {
    let filter = Filter::new()
        .address(rp_registry_address)
        .event_signature(IRpRegistry::RpRegistered::SIGNATURE_HASH);

    let sub = provider.subscribe_logs(&filter).await?;

    info!(%rp_registry_address, "subscribed to RP registration events");

    Ok(sub.into_stream().map(move |log| {
        let decoded = IRpRegistry::RpRegistered::decode_log(log.as_ref())?;
        let id = u64::try_from(decoded.oprfKeyId)
            .map_err(|e| eyre::eyre!("oprfKeyId overflow: {e}"))?;
        Ok(id)
    }))
}
