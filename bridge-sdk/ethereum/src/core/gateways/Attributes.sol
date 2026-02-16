// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Attributes
/// @author World Contributors
/// @notice Shared ERC-7786 attribute selectors and decoding for World ID gateways.
///   Each attribute is encoded as `bytes4 selector ++ abi.encode(values)` per the ERC-7786 spec.
library Attributes {
    /// @dev 4-byte selector for `chainHead(bytes32)` attribute, which carries the proven World Chain head for the message.
    bytes4 internal constant OWNED_GATEWAY_ATTRIBUTES = bytes4(keccak256("chainHead(bytes32)"));

    /// @dev 4-byte selector for `l1ProofAttributes(uint32,bytes,bytes32[4],bytes[],bytes[])`
    bytes4 internal constant L1_GATEWAY_ATTRIBUTES =
        bytes4(keccak256("l1ProofAttributes(uint32,bytes,bytes32[4],bytes[],bytes[])"));

    /// @dev 4-byte selector for `zkProofGatewayAttributes(bytes,bytes,bytes[],bytes[])`
    bytes4 internal constant ZK_GATEWAY_ATTRIBUTES =
        bytes4(keccak256("zkProofGatewayAttributes(bytes,bytes,bytes[],bytes[])"));

    ////////////////////////////////////////////////////////////
    //                        SPLIT                            //
    ////////////////////////////////////////////////////////////

    /// @dev Splits a calldata attribute into its selector and data components.
    function split(bytes calldata attribute) internal pure returns (bytes4 selector, bytes memory data) {
        require(attribute.length >= 4, "Attribute too short");
        selector = bytes4(attribute[:4]);
        data = attribute[4:];
    }

    /// @dev Splits a memory attribute into its selector and data components.
    function splitMem(bytes memory attribute) internal pure returns (bytes4 selector, bytes memory data) {
        require(attribute.length >= 4, "Attribute too short");
        assembly {
            selector := mload(add(attribute, 0x20))
        }
        uint256 dataLen = attribute.length - 4;
        data = new bytes(dataLen);
        if (dataLen > 0) {
            assembly {
                let src := add(attribute, 0x24)
                let dst := add(data, 0x20)
                for { let i := 0 } lt(i, dataLen) { i := add(i, 0x20) } {
                    mstore(add(dst, i), mload(add(src, i)))
                }
            }
        }
    }
}
