//! Thin re-export layer over `world_id_test_utils::anvil` for state bridge tests.
//!
//! Re-exports the shared state bridge test infrastructure and adds
//! relay-specific conversions (e.g. `RawChainCommitment` → `ChainCommitment`).

pub use world_id_test_utils::anvil::*;

use world_id_relay::primitives::ChainCommitment;

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
