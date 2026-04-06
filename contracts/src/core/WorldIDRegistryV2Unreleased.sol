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
    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Thrown when the provided authenticator address does not match the type stored in the bitmap.
     *      For limited-signing authenticators (WIP-104), address must be zero. For management-key
     *      authenticators, address must be non-zero.
     */
    error AuthenticatorTypeMismatch(uint32 pubkeyId, bool isLimitedSigner);

    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    /// @dev root -> timestamp when the root was replaced (i.e. stopped being the latest root).
    ///      Used by V2's `isValidRoot` to measure TTL from replacement time, not creation time.
    mapping(uint256 => uint256) internal _rootToValidityTimestamp;

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    /// @dev The 96-bit bitmap representing the authenticators; off-chain public keys is now
    ///   split: bits [0-47] for occupancy (i.e. is the key id space), bits [48-95] for the type
    ///   of authenticator (i.e. is it a limited signer authenticator or a full authenticator).
    ///   V1 accounts with pubkeyId < 48 are backward-compatible (upper bits default to 0,
    ///   meaning full authenticator).
    /// @custom:override "Overrides" V1 as the hard limit is lowered by half, because the upper half is used
    ///   to store the type of authenticator.
    uint256 public constant MAX_AUTHENTICATORS_V2_HARD_LIMIT = 48;

    /// @dev Bit offset within the 96-bit bitmap where limited-signing flags begin.
    uint256 internal constant _LIMITED_SIGNING_OFFSET = 48;

    ////////////////////////////////////////////////////////////
    //                    ROOT VALIDITY                       //
    ////////////////////////////////////////////////////////////

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

    ////////////////////////////////////////////////////////////
    //              AUTHENTICATOR MANAGEMENT                  //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IWorldIDRegistry
    /// @custom:override Overrides V1 to allow inserting limited-signing authenticators without on-chain
    ///   management keys (WIP-104). When `newAuthenticatorAddress` is `address(0)`, the authenticator's
    ///   limited-signing flag is set in the bitmap and no `_authenticatorAddressToPackedAccountData`
    ///   entry is created.
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
        if (newAuthenticatorAddress != address(0)) {
            _validateNewAuthenticatorAddress(newAuthenticatorAddress);
        }

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

        // Set occupancy bit
        uint256 newBitmap = bitmap | (1 << uint256(pubkeyId));

        if (newAuthenticatorAddress != address(0)) {
            // Management-key authenticator: store on-chain mapping
            if (_leafIndexToRecoveryCounter[leafIndex] > type(uint32).max) {
                revert RecoveryCounterOverflow();
            }
            _authenticatorAddressToPackedAccountData[newAuthenticatorAddress] =
                PackedAccountData.pack(leafIndex, uint32(_leafIndexToRecoveryCounter[leafIndex]), pubkeyId);
        } else {
            // Limited-signing authenticator: set type flag in bitmap upper half
            newBitmap |= (1 << (_LIMITED_SIGNING_OFFSET + uint256(pubkeyId)));
        }

        _setPubkeyBitmap(leafIndex, newBitmap);

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
    /// @custom:override Overrides V1 to handle limited-signing authenticators (WIP-104). The bitmap's
    ///   upper half encodes authenticator type: if the limited-signing flag is set, `authenticatorAddress`
    ///   must be `address(0)`; otherwise it must match the on-chain mapping.
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

        uint256 bitmap = _getPubkeyBitmap(leafIndex);
        bool isLimitedSigning = (bitmap & (1 << (_LIMITED_SIGNING_OFFSET + pubkeyId))) != 0;

        if (isLimitedSigning) {
            // For limited-signing authenticator, the address must be 0
            if (authenticatorAddress != address(0)) {
                revert AuthenticatorTypeMismatch(pubkeyId, true);
            }
        } else {
            if (authenticatorAddress == address(0)) {
                revert AuthenticatorTypeMismatch(pubkeyId, false);
            }

            uint256 packedToRemove = _authenticatorAddressToPackedAccountData[authenticatorAddress];
            if (packedToRemove == 0) {
                revert AuthenticatorDoesNotExist(authenticatorAddress);
            }

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

            delete _authenticatorAddressToPackedAccountData[authenticatorAddress];
        }

        // Clear both occupancy and type of authenticator bits
        _setPubkeyBitmap(leafIndex, bitmap & ~(1 << pubkeyId) & ~(1 << (_LIMITED_SIGNING_OFFSET + pubkeyId)));

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
    //                    OWNER FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IWorldIDRegistry
    /// @custom:override Overrides V1 to enforce V2 hard limit of 48 (bitmap split between occupancy
    ///   and limited-signing flags).
    function setMaxAuthenticators(uint256 newMaxAuthenticators)
        external
        virtual
        override
        onlyOwner
        onlyProxy
        onlyInitialized
    {
        if (newMaxAuthenticators > MAX_AUTHENTICATORS_V2_HARD_LIMIT) {
            revert OwnerMaxAuthenticatorsOutOfBounds();
        }
        uint256 old = _maxAuthenticators;
        _maxAuthenticators = newMaxAuthenticators;
        emit MaxAuthenticatorsUpdated(old, _maxAuthenticators);
    }
}
