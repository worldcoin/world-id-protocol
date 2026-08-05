// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IWorldIDVerifier} from "./IWorldIDVerifier.sol";

/**
 * @title IWorldIDVerifierV3
 * @author World Contributors
 * @notice Interface for verifying World ID proofs (Uniqueness and Session proofs).
 * @dev V3 rejects a zero `sessionId` on every session-carrying entry point.
 */
interface IWorldIDVerifierV3 is IWorldIDVerifier {
    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Thrown when a session-carrying verification is attempted with `sessionId == 0`. Zero is
     *  the circuit's "no session" sentinel and is satisfiable by any World ID, so it proves nothing.
     */
    error InvalidSessionId();
}
