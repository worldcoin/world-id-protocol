// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IWorldIDVerifier} from "./IWorldIDVerifier.sol";

/**
 * @title IWorldIDVerifierV2
 * @author World Contributors
 * @notice Interface for verifying World ID proofs (Uniqueness and Session proofs).
 * @dev V2 enforces the action-prefix convention on the convenience entry points:
 *  `verify` requires the action's most significant byte to be `0x00` (RP-signed Uniqueness
 *  actions) and `verifySession` requires `0x02` (randomized Session actions).
 */
interface IWorldIDVerifierV2 is IWorldIDVerifier {
    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Thrown when the action is not valid for the type of proof. The prefix is enforced
     *  to ensure any nullifier request for a Uniqueness Proof is signed by the RP (actions
     *  without this prefix, i.e. for sessions, it doesn't need to be signed).
     */
    error InvalidAction();
}
