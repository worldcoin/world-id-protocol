//! Relay-specific conversions for state bridge test types.

use world_id_relay::primitives::ChainCommitment;
use world_id_test_utils::anvil::RawChainCommitment;

/// Converts a test-utils [`RawChainCommitment`] into a relay [`ChainCommitment`].
pub fn into_chain_commitment(raw: RawChainCommitment) -> ChainCommitment {
    ChainCommitment {
        chain_head: raw.chain_head,
        block_number: raw.block_number,
        chain_id: raw.chain_id,
        commitment_payload: raw.commitment_payload,
        timestamp: raw.timestamp,
    }
}
