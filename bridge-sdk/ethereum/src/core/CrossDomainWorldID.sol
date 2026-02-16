// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IWorldID} from "./interfaces/IWorldID.sol";
import {ProofsLib, InvalidChainHead} from "./lib/ProofsLib.sol";
import {Verifier} from "@world-id/Verifier.sol";
import {ERC7786Recipient} from "@openzeppelin/contracts/crosschain/ERC7786Recipient.sol";
import {StateBridge} from "./lib/StateBridge.sol";

import "./Error.sol";

/// @title CrossDomainWorldID
/// @author World Contributors
/// @notice Cross-chain World ID verifier. Receives bridge state via ERC-7786 gateways
///   and verifies Groth16 proofs against the bridged WorldIDRegistry Merkle root.
contract CrossDomainWorldID is IWorldID, ERC7786Recipient, StateBridge {
    using ProofsLib for *;

    /// @inheritdoc IWorldID
    Verifier public immutable VERIFIER;

    /// @inheritdoc IWorldID
    uint256 public immutable ROOT_VALIDITY_WINDOW;

    /// @inheritdoc IWorldID
    uint256 public immutable TREE_DEPTH;

    /// @inheritdoc IWorldID
    uint64 public immutable MIN_EXPIRATION_THRESHOLD;

    constructor(address verifier_, uint256 rootValidityWindow_, uint256 treeDepth_, uint64 minExpirationThreshold_) {
        require(verifier_ != address(0), "Verifier address cannot be zero");
        require(rootValidityWindow_ > 0, "Root validity window must be greater than zero");
        require(treeDepth_ > 0, "Tree depth must be greater than zero");
        require(minExpirationThreshold_ > 0, "Minimum expiration threshold must be greater than zero");

        VERIFIER = Verifier(verifier_);
        ROOT_VALIDITY_WINDOW = rootValidityWindow_;
        TREE_DEPTH = treeDepth_;
        MIN_EXPIRATION_THRESHOLD = minExpirationThreshold_;

        _disableInitializers();
    }

    /// @inheritdoc IWorldID
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

    /// @inheritdoc IWorldID
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

    /// @inheritdoc IWorldID
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

        if (!isValidRoot(root)) revert InvalidMerkleRoot();

        ProvenPubKeyInfo memory issuerPubKeyInfo = issuerSchemaIdToPubkeyAndProofId(issuerSchemaId);

        ProvenPubKeyInfo memory oprfPubKeyInfo = oprfKeyIdToPubkeyAndProofId(rpId);

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
            TREE_DEPTH
        ];

        VERIFIER.verifyCompressedProof(proof, input);
    }

    /// @inheritdoc IWorldID
    function isValidRoot(uint256 root) public view virtual returns (bool) {
        ProvenRootInfo memory info = rootToTimestampAndProofId(root);

        if (info.timestamp == 0) return false;

        return (root == LATEST_ROOT() || block.timestamp <= info.timestamp + ROOT_VALIDITY_WINDOW);
    }

    ////////////////////////////////////////////////////////////
    //                       ERC-7786                        //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc ERC7786Recipient
    function _isAuthorizedGateway(address gateway, bytes calldata) internal view virtual override returns (bool) {
        return _authorized(gateway);
    }

    /// @inheritdoc ERC7786Recipient
    /// @dev We offload the trust assumptions to the gateway, here we simply commit "gateway verified" commitments.
    function _processMessage(address, bytes32, bytes calldata, bytes calldata payload) internal virtual override {
        (bytes32 provenChainHead, bytes memory commitPayload) = abi.decode(payload, (bytes32, bytes));

        ProofsLib.Commitment[] memory commits = abi.decode(commitPayload, (ProofsLib.Commitment[]));
        if (commits.length == 0) revert EmptyChainedCommits();

        // Verify the commitments hash to the proven chain head
        ProofsLib.Chain memory chain = KECCAK_CHAIN();

        bytes32 expectedHead = ProofsLib.hashChained(chain, commits);
        if (expectedHead != provenChainHead) revert InvalidChainHead();

        _applyAndCommit(commits);
    }

    ////////////////////////////////////////////////////////////
    //                        OWNER                         //
    ////////////////////////////////////////////////////////////

    /// @notice Authorizes a new gateway to submit state.
    function addGateway(address gateway) external onlyOwner {
        _addGateway(gateway);
    }

    /// @notice Revokes a gateway's authorization to submit state.
    function removeGateway(address gateway) external onlyOwner {
        _removeGateway(gateway);
    }
}
