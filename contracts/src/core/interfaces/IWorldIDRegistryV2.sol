// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IWorldIDRegistry} from "./IWorldIDRegistry.sol";

/**
 * @title IWorldIDRegistry
 * @author World Contributors
 * @notice Interface for the World ID Registry contract.
 * @dev Manages World IDs and the authenticators which are authorized to perform operations on behalf of them.
 */
interface IWorldIDRegistryV2 is IWorldIDRegistry {
    ////////////////////////////////////////////////////////////
    //                        STRUCTS                         //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Previous Recovery Agent retained during the optimistic revert window after an
     *      `updateRecoveryAgent` call (WIP-102). `invalidAfter == 0` means no active update.
     */
    struct PreviousRecoveryAgentUpdate {
        address prevRecoveryAgent;
        uint256 invalidAfter;
    }

    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Thrown when the provided authenticator address does not match the class stored in the bitmap.
     *      For Proving Authenticators (WIP-104), address must be zero. For Admin Authenticators,
     *      address must be non-zero.
     */
    error AuthenticatorClassMismatch(uint32 pubkeyId, bool isProvingAuthenticator);

    /**
     * @dev The requested method is no longer supported.
     */
    error MethodUnsupported();

    /**
     * @dev Thrown when removing an Admin Authenticator would leave only Proving Authenticators
     *      on the account, making it unmanageable.
     */
    error UnmanageableNotAllowed();

    /**
     * @dev Thrown when querying expiration for a root that was never recorded.
     */
    error UnknownRoot(uint256 root);

    /**
     * @dev Thrown when `updateRecoveryAgent` is called while a previous Recovery Agent update
     *      is still within its revert window (WIP-102).
     */
    error RecoveryAgentUpdateStillActive(uint64 leafIndex, uint256 invalidAfter);

    /**
     * @dev Thrown when `revertRecoveryAgentUpdate` is called with no active update to revert (WIP-102).
     */
    error NoActiveRecoveryAgentUpdate(uint64 leafIndex);

    /**
     * @dev Thrown when `revertRecoveryAgentUpdate` is called after the revert window has elapsed (WIP-102).
     */
    error RecoveryAgentUpdateWindowExpired(uint64 leafIndex, uint256 invalidAfter);

    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Emitted when a Recovery Agent is updated (WIP-102). The change takes effect
     *      immediately on-chain but recovery operations continue to honor `prevRecoveryAgent`
     *      until `invalidAfter` elapses.
     */
    event RecoveryAgentUpdated(
        uint64 indexed leafIndex,
        address indexed prevRecoveryAgent,
        address indexed newRecoveryAgent,
        uint256 invalidAfter
    );

    /**
     * @dev Emitted when a Recovery Agent update is reverted within the revert window (WIP-102).
     *      `revertedRecoveryAgent` is the Recovery Agent that was set by the update and is now
     *      being displaced; `restoredRecoveryAgent` is the previous agent being restored.
     */
    event RecoveryAgentUpdateReverted(
        uint64 indexed leafIndex,
        address indexed restoredRecoveryAgent,
        address indexed revertedRecoveryAgent
    );

    ////////////////////////////////////////////////////////////
    //                   PUBLIC FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Updates the Recovery Agent for a World ID account (WIP-102). The change is applied
     *      immediately, while the previous Recovery Agent remains valid for recovery until
     *      `invalidAfter` (= now + `_recoveryAgentUpdateCooldown`) elapses. During that window
     *      any authenticator can revert via `revertRecoveryAgentUpdate`.
     * @param leafIndex The leaf index of the World ID account.
     * @param newRecoveryAgent The new Recovery Agent address.
     * @param signature The EIP-712 signature from an existing authenticator authorizing the update.
     * @param nonce The signature nonce for replay protection.
     */
    function updateRecoveryAgent(
        uint64 leafIndex,
        address newRecoveryAgent,
        bytes memory signature,
        uint256 nonce
    ) external;

    /**
     * @dev Reverts a pending Recovery Agent update, restoring the previous Recovery Agent (WIP-102).
     *      Callable by any valid authenticator up until `invalidAfter`.
     * @param leafIndex The leaf index of the World ID account.
     * @param signature The EIP-712 signature from an existing authenticator authorizing the revert.
     * @param nonce The signature nonce for replay protection.
     */
    function revertRecoveryAgentUpdate(uint64 leafIndex, bytes memory signature, uint256 nonce) external;

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Returns the previous Recovery Agent retained during an active update's revert window (WIP-102).
     *      Returns `(address(0), 0)` when no update is in flight.
     * @param leafIndex The leaf index to query.
     */
    function getPreviousRecoveryAgentUpdate(uint64 leafIndex)
        external
        view
        returns (address prevRecoveryAgent, uint256 invalidAfter);
}
