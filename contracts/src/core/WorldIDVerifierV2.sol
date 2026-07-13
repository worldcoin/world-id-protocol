// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {WorldIDVerifier} from "./WorldIDVerifier.sol";
import {IWorldIDVerifier} from "./interfaces/IWorldIDVerifier.sol";
import {IWorldIDVerifierV2} from "./interfaces/IWorldIDVerifierV2.sol";

/**
 * @title WorldIDVerifierV2
 * @author World Contributors
 * @notice Verifies World ID proofs (Uniqueness and Session proofs).
 * @dev In addition to verifying the Groth16 Proof, it verifies relevant public inputs to the
 *  circuits through checks with the WorldIDRegistry, CredentialSchemaIssuerRegistry, and OprfKeyRegistry.
 * @custom:repo https://github.com/world-id/world-id-protocol
 */
contract WorldIDVerifierV2 is IWorldIDVerifierV2, WorldIDVerifier {
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
    ) external view virtual override(IWorldIDVerifier, WorldIDVerifier) onlyProxy onlyInitialized {
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

    /// @inheritdoc IWorldIDVerifierV2
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
    ) external view virtual override onlyProxy onlyInitialized {
        if (uint8(action >> 248) != uint8(0)) {
            revert InvalidAction();
        }
        if (sessionId == 0) {
            revert InvalidSessionId();
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
            sessionId,
            zeroKnowledgeProof
        );
    }

    /// @inheritdoc IWorldIDVerifier
    function verifySession(
        uint64 rpId,
        uint256 nonce,
        uint256 signalHash,
        uint64 expiresAtMin,
        uint64 issuerSchemaId,
        uint256 credentialGenesisIssuedAtMin,
        uint256 sessionId,
        uint256[2] calldata sessionNullifier,
        uint256[5] calldata zeroKnowledgeProof
    ) external view virtual override(IWorldIDVerifier, WorldIDVerifier) onlyProxy onlyInitialized {
        uint256 action = sessionNullifier[1];
        if (uint8(action >> 248) != uint8(2)) {
            revert InvalidAction();
        }

        verifyProofAndSignals(
            sessionNullifier[0],
            action,
            rpId,
            nonce,
            signalHash,
            expiresAtMin,
            issuerSchemaId,
            credentialGenesisIssuedAtMin,
            sessionId,
            zeroKnowledgeProof
        );
    }
}
