// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {WorldIDRegistry} from "./WorldIDRegistry.sol";
import {IWorldIDRegistry} from "./interfaces/IWorldIDRegistry.sol";
import {PackedAccountData} from "./libraries/PackedAccountData.sol";

/**
 * @title WorldIDRegistryV2
 * @author World Contributors
 * @notice Upgraded World ID Registry that fixes the root validity race condition.
 * @dev In V1, `isValidRoot` checked `_rootToTimestamp` (when a root was created). If a root was
 *      created long before it was replaced, its TTL could expire almost immediately after being
 *      superseded, rejecting valid proofs. V2 introduces `_rootToValidityTimestamp` which records
 *      when a root stopped being the latest, so the full validity window applies from that moment.
 * @custom:repo https://github.com/world-id/world-id-protocol
 */
contract WorldIDRegistryV2 is WorldIDRegistry {
    /// @dev root -> timestamp when the root was replaced (i.e. stopped being the latest root).
    ///      Used by V2's `isValidRoot` to measure TTL from replacement time, not creation time.
    mapping(uint256 => uint256) internal _rootToValidityTimestamp;

    /**
     * @dev Captures `_latestRoot` before `super._recordCurrentRoot()` overwrites it, and stores
     *   `block.timestamp` in `_rootToValidityTimestamp` for that root.
     * @custom:override Overrides V1 to record the timestamp when the current root stops being the latest.
     */
    function _recordCurrentRoot() internal virtual override {
        // Take the currentRoot before we update the new root and
        // set the validity timestamp of that root.
        //
        // In `isValidRoot` this timestamp is checked.
        uint256 currentRoot = _latestRoot;
        _rootToValidityTimestamp[currentRoot] = block.timestamp;
        super._recordCurrentRoot();
    }

    /// @inheritdoc IWorldIDRegistry
    /// @custom:override Overrides V1 to use `_rootToValidityTimestamp` (when root was replaced) instead of
    ///   `_rootToTimestamp` (when root was created), fixing the race condition.
    function isValidRoot(uint256 root) external view virtual override onlyProxy onlyInitialized returns (bool) {
        // The latest root is always valid.
        if (root == _latestRoot) return true;
        // Check if the root is known and not expired
        // IMPORTANT: this uses another mapping than version 1
        uint256 ts = _rootToValidityTimestamp[root];
        if (ts == 0) return false;
        return block.timestamp <= ts + _rootValidityWindow;
    }

    /// @inheritdoc IWorldIDRegistry
    /// @custom:override Overrides V1 to allow inserting authenticators without on-chain management (WIP-104).
    function insertAuthenticator(
        uint64 leafIndex,
        address newAuthenticatorAddress,
        uint32 pubkeyId,
        uint256 newAuthenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        bytes memory signature,
        uint256 nonce
    ) external virtual override onlyProxy onlyInitialized {
        _validateNewAuthenticatorAddress(newAuthenticatorAddress);

        if (pubkeyId >= _maxAuthenticators) {
            revert PubkeyIdOutOfBounds();
        }

        uint256 bitmap = _getPubkeyBitmap(leafIndex);
        if ((bitmap & (1 << pubkeyId)) != 0) {
            revert PubkeyIdInUse();
        }

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    INSERT_AUTHENTICATOR_TYPEHASH,
                    leafIndex,
                    newAuthenticatorAddress,
                    pubkeyId,
                    newAuthenticatorPubkey,
                    newOffchainSignerCommitment,
                    nonce
                )
            )
        );

        (, uint256 packedAccountData) = _recoverAccountDataFromSignature(messageHash, signature);
        uint64 recoveredLeafIndex = PackedAccountData.leafIndex(packedAccountData);

        if (leafIndex != recoveredLeafIndex) {
            revert MismatchedLeafIndex(leafIndex, recoveredLeafIndex);
        }

        uint256 expectedNonce = _leafIndexToSignatureNonce[leafIndex];
        if (nonce != expectedNonce) {
            revert MismatchedSignatureNonce(leafIndex, expectedNonce, nonce);
        }
        _leafIndexToSignatureNonce[leafIndex]++;

        if (_leafIndexToRecoveryCounter[leafIndex] > type(uint32).max) {
            revert RecoveryCounterOverflow();
        }

        // Add new authenticator

        if (newAuthenticatorAddress != address(0)) {
            // only register the on-chain management address if provided
            _authenticatorAddressToPackedAccountData[newAuthenticatorAddress] =
                PackedAccountData.pack(leafIndex, uint32(_leafIndexToRecoveryCounter[leafIndex]), pubkeyId);
        }

        _setPubkeyBitmap(leafIndex, bitmap | (1 << uint256(pubkeyId)));

        emit AuthenticatorInserted(
            leafIndex,
            pubkeyId,
            newAuthenticatorAddress,
            newAuthenticatorPubkey,
            oldOffchainSignerCommitment,
            newOffchainSignerCommitment
        );
        _updateLeafAndRecord(leafIndex, oldOffchainSignerCommitment, newOffchainSignerCommitment);
    }

    /// @inheritdoc IWorldIDRegistry
    /// @custom:override Overrides V1 to allow handling authenticators without on-chain management (WIP-104).
    function removeAuthenticator(
        uint64 leafIndex,
        address authenticatorAddress,
        uint32 pubkeyId,
        uint256 authenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        bytes memory signature,
        uint256 nonce
    ) external virtual override onlyProxy onlyInitialized {
        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    REMOVE_AUTHENTICATOR_TYPEHASH,
                    leafIndex,
                    authenticatorAddress,
                    pubkeyId,
                    authenticatorPubkey,
                    newOffchainSignerCommitment,
                    nonce
                )
            )
        );

        (, uint256 packedAccountData) = _recoverAccountDataFromSignature(messageHash, signature);
        uint64 recoveredLeafIndex = PackedAccountData.leafIndex(packedAccountData);
        if (leafIndex != recoveredLeafIndex) {
            revert MismatchedLeafIndex(leafIndex, recoveredLeafIndex);
        }

        uint256 expectedNonce = _leafIndexToSignatureNonce[leafIndex];
        if (nonce != expectedNonce) {
            revert MismatchedSignatureNonce(leafIndex, expectedNonce, nonce);
        }
        _leafIndexToSignatureNonce[leafIndex]++;

        uint256 packedToRemove = _authenticatorAddressToPackedAccountData[authenticatorAddress];
        if (packedToRemove != 0) {
            uint64 actualLeafIndex = PackedAccountData.leafIndex(packedToRemove);
            if (actualLeafIndex != leafIndex) {
                revert AuthenticatorDoesNotBelongToAccount(leafIndex, actualLeafIndex);
            }

            uint256 actualPubkeyId = PackedAccountData.pubkeyId(packedToRemove);
            if (actualPubkeyId != pubkeyId) {
                revert MismatchedPubkeyId(pubkeyId, actualPubkeyId);
            }

            uint256 actualRecoveryCounter = PackedAccountData.recoveryCounter(packedToRemove);
            uint256 expectedRecoveryCounter = _leafIndexToRecoveryCounter[leafIndex];
            if (actualRecoveryCounter != expectedRecoveryCounter) {
                revert MismatchedRecoveryCounter(leafIndex, expectedRecoveryCounter, actualRecoveryCounter);
            }
        }

        // Delete authenticator
        delete _authenticatorAddressToPackedAccountData[authenticatorAddress];
        _setPubkeyBitmap(leafIndex, _getPubkeyBitmap(leafIndex) & ~(1 << pubkeyId));

        // Update tree
        emit AuthenticatorRemoved(
            leafIndex,
            pubkeyId,
            authenticatorAddress,
            authenticatorPubkey,
            oldOffchainSignerCommitment,
            newOffchainSignerCommitment
        );
        _updateLeafAndRecord(leafIndex, oldOffchainSignerCommitment, newOffchainSignerCommitment);
    }

    ////////////////////////////////////////////////////////////
    //                   INTERNAL FUNCTIONS                   //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Validates that a new authenticator address is not in use by another World ID,
     * or if it was previously used, the account has been recovered (recovery counter increased),
     * making the address available again. NOTE that `_registerAccount` still has an additional check
     * to ensure authenticators are not registered at account creation with a zero address.
     * @custom:override Overrides V1 by removing restriction that newAuthenticatorAddress must not equal 0 to
     * comply with WIP-104.
     * @param newAuthenticatorAddress The new authenticator address to validate.
     */
    function _validateNewAuthenticatorAddress(address newAuthenticatorAddress) internal view override {
        uint256 packedAccountData = _authenticatorAddressToPackedAccountData[newAuthenticatorAddress];
        // If the authenticatorAddress is non-zero, we could permit it to be used if the recovery counter is less than the
        // leafIndex's recovery counter. This means the account was recovered and the authenticator address is no longer in use.
        if (packedAccountData != 0) {
            uint64 existingLeafIndex = PackedAccountData.leafIndex(packedAccountData);
            uint256 existingRecoveryCounter = PackedAccountData.recoveryCounter(packedAccountData);
            if (existingRecoveryCounter >= _leafIndexToRecoveryCounter[existingLeafIndex]) {
                revert AuthenticatorAddressAlreadyInUse(newAuthenticatorAddress);
            }
        }
    }
}
