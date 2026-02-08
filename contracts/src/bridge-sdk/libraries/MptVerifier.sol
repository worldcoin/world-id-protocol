// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SecureMerkleTrie} from "../vendored/optimism/trie/SecureMerkleTrie.sol";
import {RLPReader} from "../vendored/optimism/rlp/RLPReader.sol";

/// @title MptVerifier
/// @author World Contributors
/// @notice Library for verifying Ethereum MPT account and storage proofs and computing World Chain
///   registry storage slots. Extracted from `WorldIDStateBridgeBase` for reuse across adapters.
library MptVerifier {
    ////////////////////////////////////////////////////////////
    //                  STORAGE SLOT CONSTANTS                //
    ////////////////////////////////////////////////////////////

    /// @dev Storage slot for `_latestRoot` in WorldIDRegistry.
    bytes32 internal constant LATEST_ROOT_SLOT = bytes32(uint256(0x11));

    /// @dev Storage slot base for `_rootToTimestamp` mapping in WorldIDRegistry.
    ///   Actual slot: `keccak256(abi.encode(root, ROOT_TO_TIMESTAMP_SLOT_BASE))`.
    bytes32 internal constant ROOT_TO_TIMESTAMP_SLOT_BASE = bytes32(uint256(0x10));

    /// @dev Storage slot for `_treeDepth` in WorldIDRegistry.
    bytes32 internal constant TREE_DEPTH_SLOT = bytes32(uint256(0x0e));

    /// @dev Storage slot base for `_idToPubkey` mapping in CredentialSchemaIssuerRegistry.
    ///   Pubkey.x is at `keccak256(abi.encode(id, SLOT_BASE))`, Pubkey.y is at `+1`.
    bytes32 internal constant ISSUER_PUBKEY_SLOT_BASE = bytes32(uint256(0x03));

    /// @dev Storage slot base for OPRF public keys in OprfKeyRegistry.
    bytes32 internal constant OPRF_PUBKEY_SLOT_BASE = bytes32(uint256(0x07));

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
        // Get account RLP from the trie
        bytes memory accountRlp = SecureMerkleTrie.get(abi.encodePacked(account), proof, stateRoot);
        require(accountRlp.length > 0, "MptVerifier: empty account proof");

        // Parse account RLP: [nonce, balance, storageRoot, codeHash]
        RLPReader.RLPItem[] memory accountFields = RLPReader.readList(accountRlp);
        require(accountFields.length == 4, "MptVerifier: invalid account fields");

        // Storage root is at index 2
        storageRoot = bytes32(RLPReader.readBytes(accountFields[2]));
    }

    function storageFromProof(bytes[] calldata proof, bytes32 storageRoot, bytes32 slot)
        internal
        pure
        returns (bytes memory value)
    {
        bytes[] memory memProof = _toMemory(proof);

        // Get value RLP from the trie (slot is hashed by SecureMerkleTrie)
        value = SecureMerkleTrie.get(abi.encodePacked(slot), memProof, storageRoot);
    }

    /// @dev Copies a calldata bytes array to memory. Required because SecureMerkleTrie expects
    ///   `bytes[] memory` but our interface uses `bytes[] calldata`.
    function _toMemory(bytes[] calldata calldataArr) private pure returns (bytes[] memory memArr) {
        memArr = new bytes[](calldataArr.length);
        for (uint256 i = 0; i < calldataArr.length;) {
            memArr[i] = calldataArr[i];
            unchecked {
                ++i;
            }
        }
    }

    /// @dev Computes the storage slot for a key in a mapping.
    function _computeMappingSlot(bytes32 slot, bytes32 key) internal pure returns (bytes32 mappingSlot) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, key)
            mstore(add(ptr, 0x20), slot)
            mstore(mappingSlot, keccak256(ptr, 0x40))
        }
    }
}
