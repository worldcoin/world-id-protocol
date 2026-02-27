use alloy::{
    primitives::Address,
    providers::{DynProvider, Provider},
    rpc::types::TransactionRequest,
    sol_types::SolCall,
};
use eyre::Result;
use tracing::info;

use crate::bindings::IWorldIDSource;

/// Calls `WorldIDSource.propagateState()` to create bridge commitments
/// from detected registry changes.
///
/// Returns the transaction hash if state was propagated, or `None` if nothing changed.
pub async fn propagate_state(
    provider: &DynProvider,
    source_address: Address,
    issuer_schema_ids: &[u64],
    oprf_key_ids: &[u64],
) -> Result<Option<alloy_primitives::B256>> {
    if issuer_schema_ids.is_empty() && oprf_key_ids.is_empty() {
        info!("no registry changes detected, skipping propagation");
        return Ok(None);
    }

    info!(
        issuer_count = issuer_schema_ids.len(),
        oprf_count = oprf_key_ids.len(),
        "propagating state"
    );

    let call = IWorldIDSource::propagateStateCall {
        issuerSchemaIds: issuer_schema_ids.to_vec(),
        oprfKeyIds: oprf_key_ids
            .iter()
            .map(|&id| alloy_primitives::U160::from(id))
            .collect(),
    };

    let tx = TransactionRequest::default()
        .to(source_address)
        .input(call.abi_encode().into());

    let pending = provider.send_transaction(tx).await?;
    let tx_hash = *pending.tx_hash();

    info!(%tx_hash, "propagateState transaction sent");

    let receipt = pending.get_receipt().await?;

    if !receipt.status() {
        eyre::bail!("propagateState transaction reverted: {tx_hash}");
    }

    info!(%tx_hash, "propagateState confirmed");
    Ok(Some(tx_hash))
}
