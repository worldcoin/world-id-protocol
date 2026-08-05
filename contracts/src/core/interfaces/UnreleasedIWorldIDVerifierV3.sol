// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IWorldIDVerifier} from "./IWorldIDVerifier.sol";

/**
 * @title IWorldIDVerifierV3
 * @author World Contributors
 * @notice Interface for verifying World ID proofs (Uniqueness and Session proofs).
 * @dev V3 adds `verifyWithSession` for Uniqueness Proofs bound to a session commitment, and rejects
 *  a zero `sessionId` on every session-carrying entry point.
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

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Verifies a Uniqueness Proof that is bound to an existing session.
     * @dev Same as `verify`, except the proof's `session_id` public signal is checked against the
     *   provided session commitment instead of being pinned to 0. Bound proofs are rejected by
     *   `verify` and unbound proofs are rejected here. Hence, binding is explicit in both directions.
     * @dev Public inputs refer to the ZK-circuit public inputs.
     * @param nullifier Public output. A unique, one-time identifier derived from (user, rpId, action) that
     *   lets RPs detect duplicate actions without learning who the user is.
     * @param action Public input. An RP-defined context that scopes what the user is proving uniqueness on.
     *  This parameter generally expects a hashed version reduced to the field.
     * @param rpId Public input. Registered RP identifier from the `RpRegistry`.
     * @param nonce Public input. Unique nonce for this request provided by the RP.
     * @param signalHash Public input. Hash of arbitrary data provided by the RP that gets cryptographically bound into the proof.
     * @param expiresAtMin Public input. The minimum expiration required for the Credential used in the proof. If the constraint is not required,
     *   it should use the current time as the minimum expiration. The Authenticator will normally expose the effective input used in the proof.
     * @param issuerSchemaId Public input. Unique identifier for the credential schema and issuer pair.
     * @param credentialGenesisIssuedAtMin Public input. Minimum `genesis_issued_at` timestamp that the used credential
     *   must meet. Can be set to 0 to skip.
     * @param sessionId Public input. Commitment of the session the proof is bound to. Must be non-zero;
     *   use `verify` for unbound Uniqueness Proofs.
     * @param zeroKnowledgeProof Encoded World ID Proof. Internally, the first 4 elements are a
     *   compressed Groth16 proof [a (G1), b (G2), b (G2), c (G1)], and the last element is the Merkle root from the `WorldIDRegistry`.
     */
    function verifyWithSession(
        uint256 nullifier,
        uint256 action,
        uint64 rpId,
        uint256 nonce,
        uint256 signalHash,
        uint64 expiresAtMin,
        uint64 issuerSchemaId,
        uint256 credentialGenesisIssuedAtMin,
        uint256 sessionId,
        uint256[5] calldata zeroKnowledgeProof
    ) external view;
}
