pub mod ethereum_mpt;
// pub mod light_client;
pub mod mpt;
pub mod permissioned;

use alloy::sol_types::SolValue;
use alloy_primitives::{Bytes, B256};
use eyre::Result;

use crate::bindings::IWorldIDSource;

/// A decoded `ChainCommitted` event with everything needed for relay.
#[derive(Debug, Clone)]
pub struct ChainCommitment {
    /// The new keccak chain head after this commitment.
    pub chain_head: B256,
    /// The WC block number at which the commitment was made.
    pub block_number: u64,
    /// The WC chain ID.
    pub chain_id: u64,
    /// The raw ABI-encoded `Commitment[]` payload from the event.
    pub commitment_payload: Bytes,
}

/// Merges multiple sequential `ChainCommitment`s into a single commitment.
///
/// The satellite verifies that chaining all commitments from its current
/// local head produces the proven chain head. Multiple sequential
/// `ChainCommitted` events can therefore be merged: the relay concatenates
/// all individual `Commitment[]` payloads and uses the **last** chain head.
pub fn merge_commitments(batch: Vec<ChainCommitment>) -> Result<ChainCommitment> {
    let last = batch.last().ok_or_else(|| eyre::eyre!("empty batch"))?;

    let mut merged: Vec<IWorldIDSource::Commitment> = Vec::new();
    for c in &batch {
        let commits =
            Vec::<IWorldIDSource::Commitment>::abi_decode_params(&c.commitment_payload)?;
        merged.extend(commits);
    }

    Ok(ChainCommitment {
        chain_head: last.chain_head,
        block_number: last.block_number,
        chain_id: last.chain_id,
        commitment_payload: merged.abi_encode_params().into(),
    })
}
