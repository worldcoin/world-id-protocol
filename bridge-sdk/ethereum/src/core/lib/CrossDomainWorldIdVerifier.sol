// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IWorldIDVerifier} from "@world-id/interfaces/IWorldIDVerifier.sol";
import {Verifier} from "@world-id/Verifier.sol";
import {WorldIdBridge} from "./WorldIdBridge.sol";
import {ProvenPubKeyInfo} from "../../lib/BridgeTypes.sol";
import {InvalidRoot, InvalidatedProofId} from "../../lib/BridgeErrors.sol";

/// @title ProofVerifier
/// @author World Contributors
/// @notice ZK proof verification layer on top of `WorldIdBridge`. Reads proven state from
///   the inherited bridge and verifies Groth16 proofs against it. Domain-agnostic — can be
///   composed with any context via multiple inheritance.
abstract contract CrossDomainWorldIdVerifier is IWorldIDVerifier, WorldIdBridge {
    ////////////////////////////////////////////////////////////
    //                         STATE                          //
    ////////////////////////////////////////////////////////////

    /// @dev Contract for proof verification (Groth16). Packs into slot 11 with `_minExpirationThreshold` (uint64 + address = 28 bytes).
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
    //                  IWorldIDVerifier                       //
    ////////////////////////////////////////////////////////////

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
    ) external view virtual {
        this._verifyProofAndSignals(
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
        this._verifyProofAndSignals(
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

    /// @inheritdoc IWorldIDVerifier
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
    ) external view virtual {
        uint256 root = proofExt[4];

        if (!isValidRoot(root)) revert InvalidRoot();

        bytes32 rootProofId = rootToTimestampAndProofId[bytes32(root)].proofId;
        if (invalidatedProofIds[rootProofId]) revert InvalidatedProofId();

        ProvenPubKeyInfo memory issuerPubKeyInfo = issuerSchemaIdToPubkeyAndProofId[issuerSchemaId];
        if (invalidatedProofIds[issuerPubKeyInfo.proofId]) revert InvalidatedProofId();

        ProvenPubKeyInfo memory oprfPubKeyInfo = oprfKeyIdToPubkeyAndProofId[uint160(rpId)];
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

    /// @inheritdoc IWorldIDVerifier
    function getVerifier() external view virtual returns (address) {
        return address(_verifier);
    }

    /// @inheritdoc IWorldIDVerifier
    function getMinExpirationThreshold() external view virtual returns (uint256) {
        return minExpirationThreshold;
    }

    /// @inheritdoc IWorldIDVerifier
    function getTreeDepth() external view virtual returns (uint256) {
        return treeDepth;
    }
}
