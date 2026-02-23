use alloy::{
    eips::BlockNumberOrTag,
    providers::{DynProvider, Provider},
};
use alloy_primitives::{Address, B256, Bytes};
use eyre::{Result, eyre};
/// MPT proof data for a single storage slot, ready for on-chain verification.
#[derive(Debug, Clone)]
pub struct MptProof {
    /// RLP-encoded account proof nodes.
    pub account_proof: Vec<Bytes>,
    /// RLP-encoded storage proof nodes for the requested slot.
    pub storage_proof: Vec<Bytes>,
    /// The proven storage value.
    pub storage_value: B256,
}

/// Fetches an MPT proof for a single storage slot via `eth_getProof`.
pub async fn fetch_storage_proof(
    provider: &DynProvider,
    address: Address,
    slot: B256,
    block: BlockNumberOrTag,
) -> Result<MptProof> {
    let proof_response = provider
        .get_proof(address, vec![slot])
        .block_id(block.into())
        .await?;

    let storage = proof_response
        .storage_proof
        .first()
        .ok_or(eyre!("no storage proof found for slot {slot:#x}"))?;
    let storage_value = B256::from(storage.value);

    Ok(MptProof {
        account_proof: proof_response.account_proof,
        storage_proof: storage.proof.clone(),
        storage_value,
    })
}

/// Fetches just the storage root for a contract via `eth_getProof` with no storage keys.
/// Used to get the L2ToL1MessagePasser storage root for output root reconstruction.
pub async fn fetch_storage_root(
    provider: &DynProvider,
    address: Address,
    block: BlockNumberOrTag,
) -> Result<B256> {
    let proof_response = provider
        .get_proof(address, vec![])
        .block_id(block.into())
        .await?;

    Ok(proof_response.storage_hash)
}
