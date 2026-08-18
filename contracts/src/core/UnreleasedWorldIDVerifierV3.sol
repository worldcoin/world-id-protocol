// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {WorldIDVerifierV2} from "./WorldIDVerifierV2.sol";
import {IWorldIDVerifier} from "./interfaces/IWorldIDVerifier.sol";
import {IWorldIDVerifierV3} from "./interfaces/UnreleasedIWorldIDVerifierV3.sol";
import {WorldIDVerification} from "./libraries/WorldIDVerification.sol";

/**
 * @title WorldIDVerifierV3
 * @author World Contributors
 * @notice Verifies World ID proofs (Uniqueness and Session proofs).
 * @dev In addition to verifying the Groth16 Proof, it verifies relevant public inputs to the
 *  circuits through checks with the WorldIDRegistry, CredentialSchemaIssuerRegistry, and OprfKeyRegistry.
 * @custom:repo https://github.com/world-id/world-id-protocol
 */
contract WorldIDVerifierV3 is IWorldIDVerifierV3, WorldIDVerifierV2 {
    /// @inheritdoc IWorldIDVerifierV3
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
        WorldIDVerification.requireUniquenessDomain(action);
        WorldIDVerification.requireSessionId(sessionId);

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
    /// @dev Reverts with `InvalidSessionId` when `sessionId` is zero. The action prefix check is
    ///  repeated from V2 because Solidity cannot `super`-call an `external` function.
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
    ) external view virtual override(IWorldIDVerifier, WorldIDVerifierV2) onlyProxy onlyInitialized {
        uint256 action = sessionNullifier[1];
        WorldIDVerification.requireSessionDomain(action);
        WorldIDVerification.requireSessionId(sessionId);

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
