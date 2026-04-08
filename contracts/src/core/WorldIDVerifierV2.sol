// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {WorldIDVerifier} from "./WorldIDVerifier.sol";
import {IWorldIDVerifier} from "./interfaces/IWorldIDVerifier.sol";

/**
 * @title WorldIDVerifier
 * @author World Contributors
 * @notice Verifies World ID proofs (Uniqueness and Session proofs).
 * @dev In addition to verifying the Groth16 Proof, it verifies relevant public inputs to the
 *  circuits through checks with the WorldIDRegistry, CredentialSchemaIssuerRegistry, and OprfKeyRegistry.
 * @custom:repo https://github.com/world-id/world-id-protocol
 */
contract WorldIDVerifierV2 is WorldIDVerifier {
    /**
     * @dev Thrown when the inner action of the sessionNullifier is not valid. The prefix is enforced
     *  to ensure any nullifier request for a Uniqueness Proof is signed by the RP (actions
     *  without this prefix, i.e. for sessions, don't need to be signed).
     */
    error InvalidAction();

    /// @inheritdoc IWorldIDVerifier
    function verify(
        uint256 nullifier,
        uint256 action,
        uint64 rpId,
        uint256 nonce,
        uint256 signalHash,
        uint64 expiresAtMin,
        uint64 issuerSchemaId,
        uint256 credentialGenesisIssuedAtMin,
        uint256[5] calldata zeroKnowledgeProof
    ) external view virtual override onlyProxy onlyInitialized {
        if (uint8(action >> 248) != uint8(0)) {
            revert InvalidAction();
        }

        verifyProofAndSignals(
            nullifier,
            action,
            rpId,
            nonce,
            signalHash,
            expiresAtMin,
            issuerSchemaId,
            credentialGenesisIssuedAtMin,
            // For Uniqueness Proofs, the `session_id` is not used, hence the constraint defaults to 0
            // To verify a Session Proof use `verifySession` instead.
            0,
            zeroKnowledgeProof
        );
    }
}
