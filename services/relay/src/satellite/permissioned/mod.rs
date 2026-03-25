mod default;
pub mod tempo;

pub use default::PermissionedSatellite;
pub use tempo::TempoSatellite;

use alloy::{
    primitives::{B256, Bytes, keccak256},
    sol_types::SolValue,
};

/// Builds the `chainHead(bytes32)` attribute shared by all permissioned
/// gateway variants (standard EVM, Tempo, etc.).
pub(crate) fn build_chain_head_attribute(chain_head: B256) -> Bytes {
    let selector = &keccak256(b"chainHead(bytes32)")[..4];
    let encoded_head = chain_head.abi_encode();
    let mut attribute = Vec::with_capacity(4 + encoded_head.len());
    attribute.extend_from_slice(selector);
    attribute.extend_from_slice(&encoded_head);
    attribute.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    #[test]
    fn build_attribute_encodes_correctly() {
        let head = B256::from([0xAB; 32]);
        let attr = build_chain_head_attribute(head);

        // First 4 bytes: selector
        let expected_selector = &keccak256(b"chainHead(bytes32)")[..4];
        assert_eq!(&attr[..4], expected_selector);

        // Remaining bytes: ABI-encoded bytes32
        let decoded = B256::abi_decode(&attr[4..]).expect("should decode");
        assert_eq!(decoded, head);
    }
}
