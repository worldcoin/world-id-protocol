pub mod ethereum_mpt;
// pub mod light_client;
pub mod mpt;
pub mod permissioned;

use alloy_primitives::{B256, Bytes};

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



