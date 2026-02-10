// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SecureMerkleTrie} from "../vendored/optimism/trie/SecureMerkleTrie.sol";
import {RLPReader} from "../vendored/optimism/rlp/RLPReader.sol";

/// @title MptVerifier
/// @author World Contributors
/// @notice Library for verifying Ethereum MPT account and storage proofs. Extracted from the
///   bridge adapters for reuse across WorldChain, L1, and bridged destination chains.
library MptVerifier {
    ////////////////////////////////////////////////////////////
    //                  STORAGE SLOT CONSTANTS                //
    ////////////////////////////////////////////////////////////

    /// @dev Slot for `_validChainHeads` mapping in WorldIdStateBridge (slot 8).
    ///   Shared by all adapters (WorldChain, L1, Bridged) since they all inherit the same base.
    bytes32 internal constant _VALID_CHAIN_KECCAK_CHAIN_SLOT = bytes32(uint256(8));

    ////////////////////////////////////////////////////////////
    //                  PROOF VERIFICATION                    //
    ////////////////////////////////////////////////////////////

    /// @notice Verifies an MPT account proof and extracts the account's storage root.
    /// @param account The account address to verify.
    /// @param proof The Merkle proof nodes.
    /// @param stateRoot The state root to verify against.
    /// @return storageRoot The account's storage root.
    function verifyAccountAndGetStorageRoot(address account, bytes[] memory proof, bytes32 stateRoot)
        internal
        pure
        returns (bytes32 storageRoot)
    {
        bytes memory accountRlp = SecureMerkleTrie.get(abi.encodePacked(account), proof, stateRoot);
        require(accountRlp.length > 0, "MptVerifier: empty account proof");

        RLPReader.RLPItem[] memory accountFields = RLPReader.readList(accountRlp);
        require(accountFields.length == 4, "MptVerifier: invalid account fields");

        storageRoot = bytes32(RLPReader.readBytes(accountFields[2]));
    }

    /// @notice Proves a storage value via MPT proof and returns it as uint256.
    /// @dev The storage trie stores RLP-encoded values with leading zeros stripped.
    ///   This function handles the full decode: verify proof → RLP decode → right-align → uint256.
    function storageFromProof(bytes[] memory proof, bytes32 storageRoot, bytes32 slot)
        internal
        pure
        returns (uint256 value)
    {
        bytes memory rlpValue = SecureMerkleTrie.get(abi.encodePacked(slot), proof, storageRoot);
        bytes memory decoded = RLPReader.readBytes(rlpValue);
        uint256 len = decoded.length;
        require(len <= 32, "MptVerifier: storage value exceeds 32 bytes");
        assembly {
            // Load 32 bytes from the data pointer. For len < 32, the high bytes
            // contain our data and the low bytes are garbage from adjacent memory.
            // Shift right by (32 - len) * 8 bits to right-align and discard garbage.
            // For len == 0 the shift is 256 which yields 0 per EVM spec.
            value := shr(mul(sub(32, len), 8), mload(add(decoded, 0x20)))
        }
    }

    /// @dev Computes the storage slot for a key in a mapping.
    function _computeMappingSlot(bytes32 slot, bytes32 key) internal pure returns (bytes32 mappingSlot) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, key)
            mstore(add(ptr, 0x20), slot)
            mappingSlot := keccak256(ptr, 0x40)
        }
    }

    /// @notice Verifies an L1 block header against its expected hash and extracts the state root.
    /// @param headerRlp The RLP-encoded block header.
    /// @param expectedHash The expected block hash (`keccak256(headerRlp)`).
    /// @return stateRoot The state root from the block header (RLP index 3).
    function extractStateRootFromHeader(bytes memory headerRlp, bytes32 expectedHash)
        internal
        pure
        returns (bytes32 stateRoot)
    {
        require(keccak256(headerRlp) == expectedHash, "MptVerifier: block hash mismatch");

        RLPReader.RLPItem[] memory fields = RLPReader.readList(headerRlp);
        require(fields.length >= 4, "MptVerifier: invalid block header");

        stateRoot = bytes32(RLPReader.readBytes(fields[3]));
    }
}
