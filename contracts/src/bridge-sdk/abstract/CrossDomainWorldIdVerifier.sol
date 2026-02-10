// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IWorldIDVerifier} from "../../interfaces/IWorldIDVerifier.sol";
import {IWorldIdStateBridge} from "../interfaces/IWorldIdStateBridge.sol";
import {Verifier} from "../../Verifier.sol";
import {WorldIdStateBridge} from "./WorldIdStateBridge.sol";

/// @title CrossDomainWorldIdVerifier
/// @author World Contributors
/// @notice ZK proof verification layer on top of `WorldIdStateBridge`. Reads proven state from
///   the inherited bridge and verifies Groth16 proofs against it.
abstract contract CrossDomainWorldIdVerifier is IWorldIDVerifier, WorldIdStateBridge {
    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    /// @dev Thrown when the provided root is invalid or expired.
    error InvalidRoot();

    /// @dev Thrown when a proof ID referenced by state has been invalidated.
    error InvalidatedProofId();
    ////////////////////////////////////////////////////////////
    //                         STATE                          //
    ////////////////////////////////////////////////////////////

    /// @dev Contract for proof verification (Groth16). Slot 11.
    Verifier internal _verifier;

    ////////////////////////////////////////////////////////////
    //                      CONSTRUCTOR                       //
    ////////////////////////////////////////////////////////////

    constructor(address verifier, uint256 rootValidityWindow_, uint256 treeDepth_, uint64 minExpirationThreshold_)
        WorldIdStateBridge(rootValidityWindow_, treeDepth_, minExpirationThreshold_)
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

        bytes32 rootProofId = _rootToTimestampAndProofId[bytes32(root)].proofId;
        if (_invalidatedProofIds[rootProofId]) revert InvalidatedProofId();

        ProvenPubKeyInfo memory issuerPubKeyInfo = _issuerSchemaIdToPubkeyAndProofId[issuerSchemaId];
        if (_invalidatedProofIds[issuerPubKeyInfo.proofId]) revert InvalidatedProofId();

        ProvenPubKeyInfo memory oprfPubKeyInfo = _oprfKeyIdToPubkeyAndProofId[uint160(rpId)];
        if (_invalidatedProofIds[oprfPubKeyInfo.proofId]) revert InvalidatedProofId();

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
            _treeDepth
        ];

        _verifier.verifyCompressedProof(proof, input);
    }
}
