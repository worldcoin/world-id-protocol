// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Verifier} from "@world-id/Verifier.sol";
import {WorldIdBridge} from "./WorldIdBridge.sol";
import {ProvenPubKeyInfo} from "../interfaces/IWorldIdBridge.sol";

/// @dev Thrown when the provided root is not valid.
error InvalidRoot();

/// @dev Thrown when a proof ID used by a root or key has been invalidated.
error InvalidatedProofId();

/// @title CrossDomainWorldIdVerifier
/// @author World Contributors
/// @notice Abstract base for cross-domain World ID proof verification. Extends `WorldIdBridge`
///   with Groth16 ZK proof verification. Concrete implementations are named by their host domain
///   (e.g. `EthereumWorldIdVerifier`, `UniversalWorldIdVerifier`).
abstract contract CrossDomainWorldIdVerifier is WorldIdBridge {
    ////////////////////////////////////////////////////////////
    //                         STATE                          //
    ////////////////////////////////////////////////////////////

    /// @dev Contract for proof verification (Groth16).
    Verifier internal _verifier;

    ////////////////////////////////////////////////////////////
    //                      CONSTRUCTOR                       //
    ////////////////////////////////////////////////////////////

    constructor(address verifier, uint256 rootValidityWindow_, uint256 treeDepth_, uint64 minExpirationThreshold_)
        WorldIdBridge(rootValidityWindow_, treeDepth_, minExpirationThreshold_)
    {
        _verifier = Verifier(verifier);
    }

    ////////////////////////////////////////////////////////////
    //                     VERIFICATION                       //
    ////////////////////////////////////////////////////////////

    /// @notice Verifies a World ID proof against the current state of the bridge. Reverts if proof is invalid or any referenced state (root, pubkeys) has been invalidated.
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
    ) external view virtual {
        _verifyProofAndSignals(
            nullifier,
            action,
            rpId,
            nonce,
            signalHash,
            expiresAtMin,
            issuerSchemaId,
            credentialGenesisIssuedAtMin,
            0,
            zeroKnowledgeProof
        );
    }

    /// @notice Verifies a session key proof, which includes an additional `sessionId` signal and uses the nullifier pair as (sessionNullifier, action) instead of (nullifier, action).
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
    ) external view virtual {
        _verifyProofAndSignals(
            sessionNullifier[0],
            sessionNullifier[1],
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

    /// @dev Internal function to verify proofs for both regular and session-based verification.
    function _verifyProofAndSignals(
        uint256 nullifier,
        uint256 action,
        uint64 rpId,
        uint256 nonce,
        uint256 signalHash,
        uint64 expiresAtMin,
        uint64 issuerSchemaId,
        uint256 credentialGenesisIssuedAtMin,
        uint256 sessionId,
        uint256[5] calldata proofExt
    ) internal view virtual {
        uint256 root = proofExt[4];

        if (!isValidRoot(root)) revert InvalidRoot();

        bytes32 rootProofId = rootToTimestampAndProofId[bytes32(root)].proofId;
        if (invalidatedProofIds[rootProofId]) revert InvalidatedProofId();

        ProvenPubKeyInfo storage issuerPubKeyInfo = issuerSchemaIdToPubkeyAndProofId[issuerSchemaId];
        if (invalidatedProofIds[issuerPubKeyInfo.proofId]) revert InvalidatedProofId();

        ProvenPubKeyInfo storage oprfPubKeyInfo = oprfKeyIdToPubkeyAndProofId[uint160(rpId)];
        if (invalidatedProofIds[oprfPubKeyInfo.proofId]) revert InvalidatedProofId();

        uint256[4] memory proof = [proofExt[0], proofExt[1], proofExt[2], proofExt[3]];
        uint256[15] memory input = [
            nullifier,
            action,
            rpId,
            nonce,
            signalHash,
            expiresAtMin,
            issuerSchemaId,
            credentialGenesisIssuedAtMin,
            sessionId,
            issuerPubKeyInfo.pubKey.x,
            issuerPubKeyInfo.pubKey.y,
            oprfPubKeyInfo.pubKey.x,
            oprfPubKeyInfo.pubKey.y,
            root,
            treeDepth
        ];

        _verifier.verifyCompressedProof(proof, input);
    }

    /// @notice Returns the address of the verifier contract.
    function VERIFIER() public view virtual returns (address) {
        return address(_verifier);
    }
}
