// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {WorldIDRegistry} from "./WorldIDRegistry.sol";
import {IWorldIDRegistry} from "./interfaces/IWorldIDRegistry.sol";
import {IWorldIDRegistryV2} from "./interfaces/IWorldIDRegistryV2.sol";
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
contract WorldIDRegistryV2 is IWorldIDRegistryV2, WorldIDRegistry {
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
    ///   split: bits [0-47] for occupancy (i.e. is the key id space), bits [48-95] for the class
    ///   of authenticator (i.e. is it a Proving Authenticator or an Admin Authenticator).
    ///   V1 accounts with pubkeyId < 48 are backward-compatible (upper bits default to 0,
    ///   meaning full authenticator).
    /// @custom:override "Overrides" V1 as the hard limit is lowered by half, because the upper half is used
    ///   to store the class of authenticator.
    uint256 public constant MAX_AUTHENTICATORS_V2_HARD_LIMIT = 48;

    /// @dev Bit offset within the 96-bit pubkey bitmap where the flag for the class of authenticator begins.
    uint256 internal constant _AUTHENTICATOR_CLASS_OFFSET = 48;

    ////////////////////////////////////////////////////////////
    //                    ROOT VALIDITY                       //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Captures `_latestRoot` before `super._recordCurrentRoot()` overwrites it, and stores
     *   `block.timestamp` in `_rootToValidityTimestamp` for that root.
     * @custom:override Overrides V1 to record the timestamp when the current root stops being the latest.
     */
    function _recordCurrentRoot() internal virtual override {
        uint256 currentRoot = _latestRoot;
        _rootToValidityTimestamp[currentRoot] = block.timestamp;
        super._recordCurrentRoot();
    }

    /// @inheritdoc IWorldIDRegistry
    /// @custom:override Overrides V1 to use `_rootToValidityTimestamp` (when root was replaced) instead of
    ///   `_rootToTimestamp` (when root was created), fixing the race condition.
    function isValidRoot(uint256 root)
        external
        view
        virtual
        override(IWorldIDRegistry, WorldIDRegistry)
        onlyProxy
        onlyInitialized
        returns (bool)
    {
        // The latest root is always valid.
        if (root == _latestRoot) return true;
        // Check if the root is known and not expired
        // IMPORTANT: this uses another mapping than version 1
        uint256 ts = _rootToValidityTimestamp[root];
        if (ts == 0) return false;
        return block.timestamp <= ts + _rootValidityWindow;
    }

    /// @dev Gets the expiration timestamp of a root. Returns 0 for the current latest unreplaced root.
    /// Reverts with `UnknownRoot` if the root was never recorded.
    function getRootExpiration(uint256 root) external view virtual onlyProxy onlyInitialized returns (uint256) {
        if (root == _latestRoot) return 0;
        uint256 ts = _rootToValidityTimestamp[root];
        if (ts == 0) revert UnknownRoot(root);
        return ts + _rootValidityWindow;
    }

    ////////////////////////////////////////////////////////////
    //              AUTHENTICATOR MANAGEMENT                  //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IWorldIDRegistry
    /// @custom:override Overrides V1 to allow inserting Proving Authenticators without on-chain
    ///   management keys (WIP-104). When `newAuthenticatorAddress` is `address(0)`, the authenticator's
    ///   class flag is set in the bitmap and no `_authenticatorAddressToPackedAccountData`
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
    ) external virtual override(IWorldIDRegistry, WorldIDRegistry) onlyProxy onlyInitialized {
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
            // Proving Authenticator: set class flag in bitmap upper half
            newBitmap |= (1 << (_AUTHENTICATOR_CLASS_OFFSET + uint256(pubkeyId)));
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
    /// @custom:override Overrides V1 to handle Proving Authenticators (WIP-104). The bitmap's
    ///   upper half encodes authenticator class: if the class flag is set, `authenticatorAddress`
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
    ) external virtual override(IWorldIDRegistry, WorldIDRegistry) onlyProxy onlyInitialized {
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
        bool isProvingAuthenticator = (bitmap & (1 << (_AUTHENTICATOR_CLASS_OFFSET + pubkeyId))) != 0;

        if (isProvingAuthenticator) {
            // For Proving Authenticator, the address must be 0
            if (authenticatorAddress != address(0)) {
                revert AuthenticatorClassMismatch(pubkeyId, true);
            }
        } else {
            if (authenticatorAddress == address(0)) {
                revert AuthenticatorClassMismatch(pubkeyId, false);
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

        // Clear both occupancy and class of authenticator bits
        uint256 newBitmap = bitmap & ~(1 << pubkeyId) & ~(1 << (_AUTHENTICATOR_CLASS_OFFSET + pubkeyId));

        // Prevent orphaning proving authenticators without any admin to manage them
        if (!isProvingAuthenticator) {
            uint256 occupancy = newBitmap & ((1 << _AUTHENTICATOR_CLASS_OFFSET) - 1);
            uint256 provingFlags = newBitmap >> _AUTHENTICATOR_CLASS_OFFSET;
            if (occupancy != 0 && (occupancy & ~provingFlags) == 0) {
                revert UnmanageableNotAllowed();
            }
        }

        _setPubkeyBitmap(leafIndex, newBitmap);

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

    /// @inheritdoc IWorldIDRegistry
    /// @custom:override Overrides V1 to remove this functionality. The path introduces significant surface
    /// area and doesn't have very concrete use cases. Key rotation can be accomplished with a multi-call.
    function updateAuthenticator(uint64, address, address, uint32, uint256, uint256, uint256, bytes memory, uint256)
        external
        virtual
        override(WorldIDRegistry, IWorldIDRegistry)
        onlyProxy
        onlyInitialized
    {
        revert MethodUnsupported();
    }

    ////////////////////////////////////////////////////////////
    //                    OWNER FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IWorldIDRegistry
    /// @custom:override Overrides V1 to enforce V2 hard limit of 48 (bitmap split between occupancy
    ///   and authenticator class flags).
    function setMaxAuthenticators(uint256 newMaxAuthenticators)
        external
        virtual
        override(IWorldIDRegistry, WorldIDRegistry)
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
