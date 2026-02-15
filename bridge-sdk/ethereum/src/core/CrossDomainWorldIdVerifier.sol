// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {WorldIDBridge} from "./bridges/WorldIdBridge.sol";
import {ProvenPubKeyInfo} from "./interfaces/IWorldIDBridge.sol";
import {IWorldIDVerifier} from "@world-id/interfaces/IWorldIDVerifier.sol";
import {Verifier} from "@world-id/Verifier.sol";
import {ProvenRootInfo} from "./interfaces/IWorldIDBridge.sol";

/// @title CrossDomainWorldID
/// @author World Contributors
/// @notice A cross-chain World ID verifier contract capable of verifying proofs against the WorldIDRegistry.
///   Extends WorldIDBridge with IWorldIDVerifier to allow direct ZK proof verification on destination chains.
contract CrossDomainWorldID is IWorldIDVerifier, WorldIDBridge {
    /// @dev Thrown when a proof ID used by a root or key has been invalidated.
    error InvalidRoot();

    error InvalidatedProofId();

    Verifier public verifier;

    /// @dev Root validity window in seconds.
    uint256 public rootValidityWindow;
    /// @dev Merkle tree depth for ZK proof verification.
    uint256 public treeDepth;
    /// @dev Minimum expiration threshold in seconds.
    uint64 public minExpirationThreshold;

    function initialize(
        string memory name_,
        string memory version_,
        address owner_,
        address[] memory initialGateways_,
        address verifier_,
        uint256 rootValidityWindow_,
        uint256 treeDepth_,
        uint64 minExpirationThreshold_
    ) public virtual reinitializer(VERSION) {
        __WorldIdBridge_init(name_, version_, owner_, initialGateways_);

        require(verifier_ != address(0), "Verifier address cannot be zero");
        require(rootValidityWindow_ > 0, "Root validity window must be greater than zero");
        require(treeDepth_ > 0, "Tree depth must be greater than zero");
        require(minExpirationThreshold_ > 0, "Minimum expiration threshold must be greater than zero");

        verifier = Verifier(verifier_);

        rootValidityWindow = rootValidityWindow_;
        treeDepth = treeDepth_;
        minExpirationThreshold = minExpirationThreshold_;
    }

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
        verifyProofAndSignals(
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
    ) external view virtual {
        verifyProofAndSignals(
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
    function verifyProofAndSignals(
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
    ) public view virtual {
        uint256 root = proofExt[4];

        if (!isValidRoot(root)) revert InvalidRoot();

        ProvenPubKeyInfo memory issuerPubKeyInfo = issuerSchemaIdToPubkeyAndProofId(issuerSchemaId);

        ProvenPubKeyInfo memory oprfPubKeyInfo = oprfKeyIdToPubkeyAndProofId(rpId); // OPRF key ID is not used in this implementation, so we use a default value

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

        verifier.verifyCompressedProof(proof, input);
    }

    /// @inheritdoc IWorldIDVerifier
    function updateCredentialSchemaIssuerRegistry(address) external virtual onlyOwner {}

    /// @inheritdoc IWorldIDVerifier
    function updateWorldIDRegistry(address) external virtual onlyOwner {}

    /// @inheritdoc IWorldIDVerifier
    function updateOprfKeyRegistry(address) external virtual onlyOwner {}

    function updateMinExpirationThreshold(uint64 newThreshold) external virtual onlyOwner {
        require(newThreshold > 0, "Minimum expiration threshold must be greater than zero");
        minExpirationThreshold = newThreshold;
    }

    /// @inheritdoc IWorldIDVerifier
    function updateVerifier(address newVerifier) external onlyOwner {
        require(newVerifier != address(0), "Verifier address cannot be zero");
        verifier = Verifier(newVerifier);
    }

    /// @inheritdoc IWorldIDVerifier
    function getCredentialSchemaIssuerRegistry() external pure returns (address) {
        revert("Not implemented - credential schema issuer registry is not used in this implementation");
    }

    /// @inheritdoc IWorldIDVerifier
    function getWorldIDRegistry() external pure returns (address) {
        revert("Not implemented - WorldID registry is not used in this implementation");
    }

    /// @inheritdoc IWorldIDVerifier
    function getOprfKeyRegistry() external pure returns (address) {
        revert("Not implemented - OPRF key registry is not used in this implementation");
    }

    /// @inheritdoc IWorldIDVerifier
    function getVerifier() external view returns (address) {
        return address(verifier);
    }

    /// @inheritdoc IWorldIDVerifier
    function getMinExpirationThreshold() external view returns (uint256) {
        return minExpirationThreshold;
    }

    /// @notice Returns the tree depth.
    function getTreeDepth() external view returns (uint256) {
        return treeDepth;
    }

    function isValidRoot(uint256 root) public view virtual returns (bool) {
        ProvenRootInfo memory info = rootToTimestampAndProofId(root);

        if (info.timestamp == 0) return false;

        return (root == LATEST_ROOT() || block.timestamp <= info.timestamp + rootValidityWindow);
    }
}
