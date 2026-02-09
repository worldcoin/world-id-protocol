// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title PackedAccountData
 * @dev Library for packing and unpacking a World ID. A World ID
 * is identified primarily by its `leaf_index` which is the index of the
 * leaf of the Merkle tree where it is stored. Additional metadata is encoded
 * in the packed format to support recovery and off-chain public key management.
 * @custom:format Packed format: [32 bits recoveryCounter][32 bits pubkeyId][128 bits reserved][64 bits leafIndex]
 * @custom:format _recoveryCounter bits [224, 256); _pubKeyId bits [192, 224); _leafIndex bits [0, 64)
 */
library PackedAccountData {
    /**
     * @dev Extracts the recovery counter from a `PackedAccountData`.
     * @param packed The `PackedAccountData` to parse
     * @return The recovery counter (top 32 bits) which counts the number of recoveries.
     */
    function recoveryCounter(uint256 packed) public pure returns (uint32) {
        return uint32(packed >> 224);
    }

    /**
     * @dev Extracts the pubkey ID from a `PackedAccountData`.
     * @param packed The `PackedAccountData` to parse
     * @return The pubkey ID (middle 32 bits) which is the index (identifier) of
     * specific authenticator for this World ID.
     */
    function pubkeyId(uint256 packed) public pure returns (uint32) {
        return uint32(packed >> 192);
    }

    /**
     * @dev Extracts the leaf index from a `PackedAccountData`.
     * @param packed The PackedAccountData
     * @return The leaf index (bottom 192 bits).
     */
    function leafIndex(uint256 packed) public pure returns (uint64) {
        return uint64(packed);
    }

    /**
     * @dev Packs the leaf index, recovery counter, and pubkey ID into a single `uint256` for storage.
     * @param _leafIndex The leaf index (64 bits).
     * @param _recoveryCounter The recovery counter (32 bits).
     * @param _pubkeyId The pubkey ID (32 bits).
     */
    function pack(uint64 _leafIndex, uint32 _recoveryCounter, uint32 _pubkeyId) public pure returns (uint256) {
        return (uint256(_recoveryCounter) << 224) | (uint256(_pubkeyId) << 192) | uint256(_leafIndex);
    }
}
