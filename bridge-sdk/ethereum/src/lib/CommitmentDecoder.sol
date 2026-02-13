// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title CommitmentDecoder
/// @author World Contributors
library CommitmentDecoder {
    /// @dev Decoded parameters for the `updateRoot` action.
    struct UpdateRootParams {
        uint256 root;
        uint256 timestamp;
        bytes32 proofId;
    }

    /// @dev Decoded parameters for the `setIssuerPubkey` action.
    struct SetIssuerPubkeyParams {
        uint64 issuerSchemaId;
        uint256 x;
        uint256 y;
        bytes32 proofId;
    }

    /// @dev Decoded parameters for the `setOprfKey` action.
    struct SetOprfKeyParams {
        uint160 oprfKeyId;
        uint256 x;
        uint256 y;
        bytes32 proofId;
    }

    /// @dev Decoded parameters for the `invalidateProofId` action.
    struct InvalidateProofIdParams {
        bytes32 proofId;
    }

    /// @notice Extracts the 4-byte action selector from commitment data.
    /// @dev Memory layout of `data` (bytes memory):
    ///   ┌──────────────┬──────────┬─────────────────┐
    ///   │ length (32)  │ sel (4)  │ args (var len)   │
    ///   └──────────────┴──────────┴─────────────────┘
    ///   Selector is read from offset 0x20 (skipping the length prefix).
    /// @param data The raw commitment data bytes.
    /// @return sel The 4-byte action selector.
    function extractSelector(bytes memory data) internal pure returns (bytes4 sel) {
        assembly {
            sel := mload(add(data, 0x20))
        }
    }

    /// @notice Decodes `updateRoot(uint256,uint256,bytes32)` commitment data.
    /// @dev Memory layout after length prefix:
    ///   ┌──────────┬──────────┬───────────┬──────────┐
    ///   │ sel (4)  │ root(32) │ ts (32)   │ pid (32) │
    ///   └──────────┴──────────┴───────────┴──────────┘
    /// @param data The raw commitment data bytes.
    /// @return params The decoded update root parameters.
    function decodeUpdateRoot(bytes memory data) internal pure returns (UpdateRootParams memory params) {
        assembly {
            let d := add(data, 0x24)
            mstore(params, mload(d)) // root
            mstore(add(params, 0x20), mload(add(d, 0x20))) // timestamp
            mstore(add(params, 0x40), mload(add(d, 0x40))) // proofId
        }
    }

    /// @notice Decodes `setIssuerPubkey(uint64,uint256,uint256,bytes32)` commitment data.
    /// @dev Memory layout after length prefix:
    ///   ┌──────────┬───────────────┬────────┬────────┬──────────┐
    ///   │ sel (4)  │ schemaId (32) │ x (32) │ y (32) │ pid (32) │
    ///   └──────────┴───────────────┴────────┴────────┴──────────┘
    /// @param data The raw commitment data bytes.
    /// @return params The decoded issuer pubkey parameters.
    function decodeSetIssuerPubkey(bytes memory data) internal pure returns (SetIssuerPubkeyParams memory params) {
        assembly {
            let d := add(data, 0x24) // length prefix (32) + selector (4) = 0x24
            mstore(params, mload(d)) // issuerSchemaId (left-padded uint64)
            mstore(add(params, 0x20), mload(add(d, 0x20))) // x
            mstore(add(params, 0x40), mload(add(d, 0x40))) // y
            mstore(add(params, 0x60), mload(add(d, 0x60))) // proofId
        }
    }

    /// @notice Decodes `setOprfKey(uint160,uint256,uint256,bytes32)` commitment data.
    /// @dev Memory layout after length prefix:
    ///   ┌──────────┬───────────────┬────────┬────────┬──────────┐
    ///   │ sel (4)  │ keyId (32)    │ x (32) │ y (32) │ pid (32) │
    ///   └──────────┴───────────────┴────────┴────────┴──────────┘
    /// @param data The raw commitment data bytes.
    /// @return params The decoded OPRF key parameters.
    function decodeSetOprfKey(bytes memory data) internal pure returns (SetOprfKeyParams memory params) {
        assembly {
            let d := add(data, 0x24) // length prefix (32) + selector (4) = 0x24
            mstore(params, mload(d)) // oprfKeyId (left-padded uint160)
            mstore(add(params, 0x20), mload(add(d, 0x20))) // x
            mstore(add(params, 0x40), mload(add(d, 0x40))) // y
            mstore(add(params, 0x60), mload(add(d, 0x60))) // proofId
        }
    }

    /// @notice Decodes `invalidateProofId(bytes32)` commitment data.
    /// @dev Memory layout after length prefix:
    ///   ┌──────────┬──────────┐
    ///   │ sel (4)  │ pid (32) │
    ///   └──────────┴──────────┘
    /// @param data The raw commitment data bytes.
    /// @return params The decoded invalidate proof ID parameters.
    function decodeInvalidateProofId(bytes memory data) internal pure returns (InvalidateProofIdParams memory params) {
        assembly {
            mstore(params, mload(add(data, 0x24))) // proofId (32 bytes at offset 0x24)
        }
    }
}
