// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/**
 * @title PackedAccountData
 * @dev Library for packing and unpacking a World ID Account. A World ID Account
 * is identified primarily by its accountIndex (or `accountId`). Additional metadata is encoded in the packed format
 * to support recovery and off-chain public key management.
 * @custom:format Packed format: [32 bits recoveryCounter][32 bits pubkeyId][192 bits accountIndex]
 */
library PackedAccountData {
    error AccountIndexOverflow();

    /**
     * @dev Extracts the recovery counter from a packed account index.
     * @param packed The packed account index: [32 bits recoveryCounter][32 bits pubkeyId][192 bits accountIndex]
     * @return The recovery counter (top 32 bits).
     */
    function recoveryCounter(uint256 packed) public pure returns (uint32) {
        return uint32(packed >> 224);
    }

    /**
     * @dev Extracts the pubkey ID from a packed account index.
     * @param packed The packed account index: [32 bits recoveryCounter][32 bits pubkeyId][192 bits accountIndex]
     * @return The pubkey ID (middle 32 bits).
     */
    function pubkeyId(uint256 packed) public pure returns (uint32) {
        return uint32(packed >> 192);
    }

    /**
     * @dev Extracts the account index from a packed account index.
     * @param packed The packed account index: [32 bits recoveryCounter][32 bits pubkeyId][192 bits accountIndex]
     * @return The account index (bottom 192 bits).
     */
    function accountIndex(uint256 packed) public pure returns (uint256) {
        return uint256(uint192(packed));
    }

    /**
     * @dev Packs account index, recovery counter, and pubkey ID into a single uint256.
     * @param _accountIndex The account index (192 bits, must fit in 192 bits).
     * @param _recoveryCounter The recovery counter (32 bits).
     * @param _pubkeyId The pubkey ID (32 bits).
     * @return The packed value: [32 bits recoveryCounter][32 bits pubkeyId][192 bits accountIndex].
     */
    function pack(uint256 _accountIndex, uint32 _recoveryCounter, uint32 _pubkeyId) public pure returns (uint256) {
        if (_accountIndex >> 192 != 0) {
            revert AccountIndexOverflow();
        }
        return (uint256(_recoveryCounter) << 224) | (uint256(_pubkeyId) << 192) | _accountIndex;
    }
}
