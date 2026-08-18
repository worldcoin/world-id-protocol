// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Verifier} from "../Verifier.sol";

/**
 * @title WorldIDVerification
 * @author World Contributors
 * @notice Shared World ID proof verification logic, used by every verifier regardless of where its
 *  state comes from: `WorldIDVerifier` reads live registries on World Chain, `WorldIDSatellite`
 *  reads state bridged to a destination chain.
 * @dev The caller resolves its own state into a `Context` and then hands off, so the public signal
 *  layout, the action-domain convention and the validity checks exist in exactly one place. Only
 *  root validity stays with the caller: the two verifiers answer it from genuinely different state
 *  (a registry call versus a bridged root plus a local validity window).
 * @dev These are `internal` functions, so they are inlined into the calling contract. The library is
 *  not deployed and introduces no delegatecall and no linking.
 */
library WorldIDVerification {
    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Thrown when the action is not valid for the type of proof. The prefix is enforced
     *  to ensure any nullifier request for a Uniqueness Proof is signed by the RP (actions
     *  without this prefix, i.e. for sessions, it doesn't need to be signed).
     */
    error InvalidAction();

    /**
     * @dev Thrown when a session-carrying verification is attempted with `sessionId == 0`. Zero is
     *  the circuit's "no session" sentinel and is satisfiable by any World ID, so it proves nothing.
     */
    error InvalidSessionId();

    /**
     * @dev Thrown when the credential minimum expiration constraint is too old. A new proof should
     *  be requested with a fresher expiration.
     */
    error ExpirationTooOld();

    /**
     * @dev Thrown when the credential issuer schema ID is not registered.
     */
    error UnregisteredIssuerSchemaId();

    /**
     * @dev Thrown when the OPRF key ID is not registered.
     */
    error UnregisteredOprfKeyId();

    ////////////////////////////////////////////////////////////
    //                       CONSTANTS                        //
    ////////////////////////////////////////////////////////////

    /// @dev Bit offset of an action's most significant byte, which carries the OPRF input domain.
    uint256 internal constant ACTION_DOMAIN_OFFSET = 248;

    /// @dev Action domain for Uniqueness Proofs. Mirrors `OprfPrefix::Uniqueness` in `world-id-primitives`.
    uint8 internal constant UNIQUENESS_DOMAIN = 0x00;

    /// @dev Action domain for Session Proofs. Mirrors `OprfPrefix::SessionAction` in `world-id-primitives`.
    uint8 internal constant SESSION_DOMAIN = 0x02;

    ////////////////////////////////////////////////////////////
    //                        TYPES                           //
    ////////////////////////////////////////////////////////////

    /**
     * @notice The verifier state a proof is checked against, resolved by the caller.
     * @param verifier The Groth16 verifier the proof is submitted to.
     * @param treeDepth Depth of the World ID Merkle tree, as a circuit public input.
     * @param minExpirationThreshold How far in the past `expiresAtMin` may be, in seconds.
     * @param issuerPubkeyX Credential issuer public key, x coordinate. Zero when unregistered.
     * @param issuerPubkeyY Credential issuer public key, y coordinate. Zero when unregistered.
     * @param oprfPubkeyX OPRF public key for the `rpId`, x coordinate. Zero when unregistered.
     * @param oprfPubkeyY OPRF public key for the `rpId`, y coordinate. Zero when unregistered.
     */
    struct Context {
        Verifier verifier;
        uint256 treeDepth;
        uint256 minExpirationThreshold;
        uint256 issuerPubkeyX;
        uint256 issuerPubkeyY;
        uint256 oprfPubkeyX;
        uint256 oprfPubkeyY;
    }

    /**
     * @notice The circuit public signals carried by a verification request.
     * @dev Field order is presentation only; `_publicSignals` fixes the order the circuit expects.
     */
    struct Signals {
        uint256 nullifier;
        uint256 action;
        uint64 rpId;
        uint256 nonce;
        uint256 signalHash;
        uint64 expiresAtMin;
        uint64 issuerSchemaId;
        uint256 credentialGenesisIssuedAtMin;
        uint256 sessionId;
    }

    ////////////////////////////////////////////////////////////
    //                    DOMAIN CHECKS                       //
    ////////////////////////////////////////////////////////////

    /// @notice Requires `action` to be in the uniqueness domain (most significant byte `0x00`).
    function requireUniquenessDomain(uint256 action) internal pure {
        if (uint8(action >> ACTION_DOMAIN_OFFSET) != UNIQUENESS_DOMAIN) revert InvalidAction();
    }

    /// @notice Requires `action` to be in the session domain (most significant byte `0x02`).
    function requireSessionDomain(uint256 action) internal pure {
        if (uint8(action >> ACTION_DOMAIN_OFFSET) != SESSION_DOMAIN) revert InvalidAction();
    }

    /// @notice Requires a session-carrying verification to name an actual session.
    function requireSessionId(uint256 sessionId) internal pure {
        if (sessionId == 0) revert InvalidSessionId();
    }

    ////////////////////////////////////////////////////////////
    //                     VERIFICATION                       //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Checks the resolved state and public signals, then verifies the Groth16 proof.
     * @dev The caller MUST have already rejected an invalid Merkle root; `zeroKnowledgeProof[4]` is
     *  taken as valid here and packed as the root public input.
     * @param ctx The verifier state to check against.
     * @param signals The circuit public signals.
     * @param zeroKnowledgeProof Compressed Groth16 proof in the first 4 elements, Merkle root in the last.
     */
    function verify(Context memory ctx, Signals memory signals, uint256[5] calldata zeroKnowledgeProof) internal view {
        // A pubkey is "empty" when either coordinate is zero, matching `_isEmptyPubkey` in
        // `CredentialSchemaIssuerRegistry`, which refuses to register such a key.
        if (ctx.issuerPubkeyX == 0 || ctx.issuerPubkeyY == 0) revert UnregisteredIssuerSchemaId();

        // The circuit does not constrain `oprf_pk` to be a valid curve point (see the note in
        // `oprf_nullifier.circom`), so an unregistered key must never reach the public signals.
        // Unreachable where the OPRF registry itself reverts on an unknown id.
        if (ctx.oprfPubkeyX == 0 || ctx.oprfPubkeyY == 0) revert UnregisteredOprfKeyId();

        // The proof guarantees the credential's private `expires_at` is greater than
        // the public `expiresAtMin` input. Reject if that lower bound is more than
        // `minExpirationThreshold` older than the current block timestamp, preventing
        // proofs that only show the credential expires after a timestamp too far in the past.
        if (uint256(signals.expiresAtMin) + ctx.minExpirationThreshold < block.timestamp) {
            revert ExpirationTooOld();
        }

        uint256[4] memory groth16CompressedProof;
        for (uint256 i = 0; i < 4; i++) {
            groth16CompressedProof[i] = zeroKnowledgeProof[i];
        }

        ctx.verifier.verifyCompressedProof(groth16CompressedProof, _publicSignals(ctx, signals, zeroKnowledgeProof[4]));
    }

    /**
     * @dev Builds the circuit public signals. The order is fixed by the circuit and is the single
     *  most important invariant in this file: see `component main` in `OPRFNullifierProof.circom`.
     */
    function _publicSignals(Context memory ctx, Signals memory signals, uint256 merkleRoot)
        private
        pure
        returns (uint256[15] memory pubSignals)
    {
        pubSignals[0] = signals.nullifier;
        pubSignals[1] = signals.issuerSchemaId;
        pubSignals[2] = ctx.issuerPubkeyX;
        pubSignals[3] = ctx.issuerPubkeyY;
        pubSignals[4] = uint256(signals.expiresAtMin);
        pubSignals[5] = signals.credentialGenesisIssuedAtMin;
        pubSignals[6] = merkleRoot;
        pubSignals[7] = ctx.treeDepth;
        pubSignals[8] = uint256(signals.rpId);
        pubSignals[9] = signals.action;
        pubSignals[10] = ctx.oprfPubkeyX;
        pubSignals[11] = ctx.oprfPubkeyY;
        pubSignals[12] = signals.signalHash;
        pubSignals[13] = signals.nonce;
        pubSignals[14] = signals.sessionId;
    }
}
