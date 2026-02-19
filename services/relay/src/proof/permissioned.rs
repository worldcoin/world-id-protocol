use alloy::{primitives::Bytes, sol_types::SolValue};

use crate::proof::ChainCommitment;

/// Builds the Permissioned gateway proof attributes.
///
/// The simplest adapter: just encodes the chain head. The transaction must
/// be sent from the gateway owner's wallet.
pub fn build_permissioned_proof_attributes(commitment: &ChainCommitment) -> (Bytes, Bytes) {
    // ABI-encode the chain head
    let attribute_data = commitment.chain_head.abi_encode();

    // Prepend the attribute selector: bytes4(keccak256("chainHead(bytes32)"))
    let selector = alloy_primitives::keccak256(b"chainHead(bytes32)");
    let mut attribute = selector[..4].to_vec();
    attribute.extend_from_slice(&attribute_data);

    let payload = commitment.commitment_payload.clone();

    (Bytes::from(attribute), payload)
}
