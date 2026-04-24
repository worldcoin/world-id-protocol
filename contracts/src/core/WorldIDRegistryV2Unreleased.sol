// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {WorldIDRegistry} from "./WorldIDRegistry.sol";
import {IWorldIDRegistry} from "./interfaces/IWorldIDRegistry.sol";
import {IWorldIDRegistryV2} from "./interfaces/IWorldIDRegistryV2.sol";
import {PackedAccountData} from "./libraries/PackedAccountData.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

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

    /// @dev leafIndex -> previous Recovery Agent captured during an active update's revert window (WIP-102).
    ///      `invalidAfter == 0` means no active update.
    mapping(uint256 => PreviousRecoveryAgentUpdate) internal _prevRecoveryAgentUpdates;

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

    /// @dev EIP-712 typehash for `updateRecoveryAgent` (WIP-102).
    bytes32 public constant UPDATE_RECOVERY_AGENT_TYPEHASH =
        keccak256("UpdateRecoveryAgent(uint64 leafIndex,address newRecoveryAgent,uint256 nonce)");

    /// @dev EIP-712 typehash for `revertRecoveryAgentUpdate` (WIP-102).
    bytes32 public constant REVERT_RECOVERY_AGENT_UPDATE_TYPEHASH =
        keccak256("RevertRecoveryAgentUpdate(uint64 leafIndex,uint256 nonce)");

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
    //              RECOVERY AGENT MANAGEMENT                 //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IWorldIDRegistryV2
    /// @dev WIP-102. Authorization model matches V1's removed `initiateRecoveryAgentUpdate`:
    ///     any valid authenticator signs the EIP-712 payload.
    function updateRecoveryAgent(uint64 leafIndex, address newRecoveryAgent, bytes memory signature, uint256 nonce)
        external
        virtual
        onlyProxy
        onlyInitialized
    {
        if (leafIndex == 0 || _nextLeafIndex <= leafIndex) {
            revert AccountDoesNotExist(leafIndex);
        }

        PreviousRecoveryAgentUpdate memory prev = _prevRecoveryAgentUpdates[leafIndex];
        if (prev.invalidAfter != 0 && block.timestamp < prev.invalidAfter) {
            revert RecoveryAgentUpdateStillActive(leafIndex, prev.invalidAfter);
        }

        bytes32 messageHash =
            _hashTypedDataV4(keccak256(abi.encode(UPDATE_RECOVERY_AGENT_TYPEHASH, leafIndex, newRecoveryAgent, nonce)));

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

        address oldAgent = _getRecoveryAgent(leafIndex);
        uint256 invalidAfter = block.timestamp + _recoveryAgentUpdateCooldown;

        // Record the previous agent for the revert window, then apply the new agent on-chain immediately.
        // Until `invalidAfter`, `oldAgent` remains the sole valid signer for `recoverAccount`.
        _prevRecoveryAgentUpdates[leafIndex] =
            PreviousRecoveryAgentUpdate({prevRecoveryAgent: oldAgent, invalidAfter: invalidAfter});
        _setRecoveryAddressAndBitmap(leafIndex, newRecoveryAgent, _getPubkeyBitmap(leafIndex));

        emit RecoveryAgentUpdated(leafIndex, oldAgent, newRecoveryAgent, invalidAfter);
    }

    /// @inheritdoc IWorldIDRegistryV2
    /// @dev WIP-102. Authorization model matches V1's removed `cancelRecoveryAgentUpdate`:
    ///     any valid authenticator signs the EIP-712 payload.
    function revertRecoveryAgentUpdate(uint64 leafIndex, bytes memory signature, uint256 nonce)
        external
        virtual
        onlyProxy
        onlyInitialized
    {
        if (leafIndex == 0 || _nextLeafIndex <= leafIndex) {
            revert AccountDoesNotExist(leafIndex);
        }

        PreviousRecoveryAgentUpdate memory prev = _prevRecoveryAgentUpdates[leafIndex];
        if (prev.invalidAfter == 0) {
            revert NoActiveRecoveryAgentUpdate(leafIndex);
        }
        if (block.timestamp >= prev.invalidAfter) {
            revert RecoveryAgentUpdateWindowExpired(leafIndex, prev.invalidAfter);
        }

        bytes32 messageHash =
            _hashTypedDataV4(keccak256(abi.encode(REVERT_RECOVERY_AGENT_UPDATE_TYPEHASH, leafIndex, nonce)));

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

        // Restore the previous agent on-chain and close the revert window by clearing the entry.
        address revertedAgent = _getRecoveryAgent(leafIndex);
        _setRecoveryAddressAndBitmap(leafIndex, prev.prevRecoveryAgent, _getPubkeyBitmap(leafIndex));
        delete _prevRecoveryAgentUpdates[leafIndex];

        emit RecoveryAgentUpdateReverted(leafIndex, prev.prevRecoveryAgent, revertedAgent);
    }

    /// @inheritdoc IWorldIDRegistryV2
    function getPreviousRecoveryAgentUpdate(uint64 leafIndex)
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (address prevRecoveryAgent, uint256 invalidAfter)
    {
        PreviousRecoveryAgentUpdate memory prev = _prevRecoveryAgentUpdates[leafIndex];
        return (prev.prevRecoveryAgent, prev.invalidAfter);
    }

    /// @inheritdoc IWorldIDRegistry
    /// @custom:override Overrides V1 (WIP-102) to return the effective Recovery Agent — the signer
    ///     currently authorized to recover this account. During an active revert window the previous
    ///     agent remains effective; after `invalidAfter` elapses the newly-set agent takes over.
    ///     The scheduled new agent during a window is discoverable via the `RecoveryAgentUpdated` event.
    function getRecoveryAgent(uint64 leafIndex)
        external
        view
        virtual
        override(IWorldIDRegistry, WorldIDRegistry)
        onlyProxy
        onlyInitialized
        returns (address)
    {
        return _getEffectiveRecoveryAgent(leafIndex);
    }

    /// @dev Returns the effective Recovery Agent with WIP-102 revert-window semantics applied.
    function _getEffectiveRecoveryAgent(uint64 leafIndex) internal view virtual returns (address) {
        PreviousRecoveryAgentUpdate memory prev = _prevRecoveryAgentUpdates[leafIndex];
        if (prev.invalidAfter != 0 && block.timestamp < prev.invalidAfter) {
            return prev.prevRecoveryAgent;
        }
        return _getRecoveryAgent(leafIndex);
    }

    /// @inheritdoc IWorldIDRegistry
    /// @custom:override Overrides V1 (WIP-102): during an active revert window, the valid recovery
    ///     signer is the previous Recovery Agent, not the newly-set one. On success, clears any
    ///     active update so that a malicious update by a compromised authenticator is undone when
    ///     the true owner recovers the account.
    function recoverAccount(
        uint64 leafIndex,
        address newAuthenticatorAddress,
        uint256 newAuthenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        bytes memory signature,
        uint256 nonce
    ) external virtual override(IWorldIDRegistry, WorldIDRegistry) onlyProxy onlyInitialized {
        if (leafIndex == 0 || _nextLeafIndex <= leafIndex) {
            revert AccountDoesNotExist(leafIndex);
        }

        uint256 expectedNonce = _leafIndexToSignatureNonce[leafIndex];

        if (nonce != expectedNonce) {
            revert MismatchedSignatureNonce(leafIndex, expectedNonce, nonce);
        }
        _leafIndexToSignatureNonce[leafIndex]++;

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    RECOVER_ACCOUNT_TYPEHASH,
                    leafIndex,
                    newAuthenticatorAddress,
                    newAuthenticatorPubkey,
                    newOffchainSignerCommitment,
                    nonce
                )
            )
        );

        // Effective signer applies WIP-102 window semantics: previous agent during an active window,
        // newly-set agent once `invalidAfter` has elapsed.
        address recoverySigner = _getEffectiveRecoveryAgent(leafIndex);
        if (recoverySigner == address(0)) {
            revert RecoveryNotEnabled();
        }
        if (!SignatureChecker.isValidSignatureNow(recoverySigner, messageHash, signature)) {
            revert InvalidSignature();
        }

        _validateNewAuthenticatorAddress(newAuthenticatorAddress);

        _leafIndexToRecoveryCounter[leafIndex]++;

        if (_leafIndexToRecoveryCounter[leafIndex] > type(uint32).max) {
            revert RecoveryCounterOverflow();
        }
        _authenticatorAddressToPackedAccountData[newAuthenticatorAddress] =
            PackedAccountData.pack(leafIndex, uint32(_leafIndexToRecoveryCounter[leafIndex]), uint32(0));
        _setPubkeyBitmap(leafIndex, 1); // Reset to only pubkeyId 0

        // Clear any active Recovery Agent update so a malicious update by a compromised
        // authenticator is undone as part of the true owner's recovery (WIP-102 attack mitigation).
        delete _prevRecoveryAgentUpdates[leafIndex];

        emit AccountRecovered(
            leafIndex,
            newAuthenticatorAddress,
            newAuthenticatorPubkey,
            oldOffchainSignerCommitment,
            newOffchainSignerCommitment
        );
        _updateLeafAndRecord(leafIndex, oldOffchainSignerCommitment, newOffchainSignerCommitment);
    }

    /// @inheritdoc IWorldIDRegistry
    /// @custom:override Overrides V1 to remove this functionality (WIP-102). Replaced by `updateRecoveryAgent`.
    function initiateRecoveryAgentUpdate(uint64, address, bytes memory, uint256)
        external
        virtual
        override(IWorldIDRegistry, WorldIDRegistry)
        onlyProxy
        onlyInitialized
    {
        revert MethodUnsupported();
    }

    /// @inheritdoc IWorldIDRegistry
    /// @custom:override Overrides V1 to remove this functionality (WIP-102). Replaced by `revertRecoveryAgentUpdate`.
    function cancelRecoveryAgentUpdate(uint64, bytes memory, uint256)
        external
        virtual
        override(IWorldIDRegistry, WorldIDRegistry)
        onlyProxy
        onlyInitialized
    {
        revert MethodUnsupported();
    }

    /// @inheritdoc IWorldIDRegistry
    /// @custom:override Overrides V1 to remove this functionality (WIP-102). No follow-up execute
    ///     transaction is needed — `updateRecoveryAgent` applies the change immediately.
    function executeRecoveryAgentUpdate(uint64)
        external
        virtual
        override(IWorldIDRegistry, WorldIDRegistry)
        onlyProxy
        onlyInitialized
    {
        revert MethodUnsupported();
    }

    /// @inheritdoc IWorldIDRegistry
    /// @custom:override Overrides V1 (WIP-102) to translate V2 active-update state into the
    ///     legacy V1 shape. `newRecoveryAgent` is the scheduled agent sitting in the packed
    ///     slot awaiting window elapse; the second return value is the timestamp at which
    ///     that agent becomes the effective recovery signer (equal to V2's `invalidAfter`).
    ///     Renamed from V1's `executeAfter` because WIP-102 removes the explicit execute
    ///     step — the new agent becomes valid automatically once the timestamp elapses.
    ///     Returns `(address(0), 0)` when no active update exists or when the window has
    ///     already elapsed — matching V1's "no pending update" contract. Orphaned V1
    ///     `_pendingRecoveryAgentUpdates` entries are correctly invisible (we read the V2
    ///     mapping, not the V1 one); the indexer notifies affected users off-chain.
    function getPendingRecoveryAgentUpdate(uint64 leafIndex)
        external
        view
        virtual
        override(IWorldIDRegistry, WorldIDRegistry)
        onlyProxy
        onlyInitialized
        returns (address newRecoveryAgent, uint256 validAfter)
    {
        PreviousRecoveryAgentUpdate memory prev = _prevRecoveryAgentUpdates[leafIndex];
        if (prev.invalidAfter == 0 || block.timestamp >= prev.invalidAfter) {
            return (address(0), 0);
        }
        return (_getRecoveryAgent(leafIndex), prev.invalidAfter);
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
