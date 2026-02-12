// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {
    IWorldIdBridge,
    ProvenRootInfo,
    ProvenPubKeyInfo,
    UnknownAction,
    InvalidChainSlot,
    ProofIdInvalidated
} from "../interfaces/IWorldIdBridge.sol";
import {BabyJubJub} from "lib/oprf-key-registry/src/BabyJubJub.sol";
import {ProofsLib} from "../../lib/ProofsLib.sol";
import {CommitmentDecoder} from "../../lib/CommitmentDecoder.sol";

/// @title BridgeState
/// @author World Contributors
/// @notice Abstract base contract inherited by all bridged World ID state contexts (World Chain, L1,
///   and bridged destinations). Manages the rolling keccak state chain, root validity tracking,
///   issuer/OPRF key storage, and commitment decoding. Uses `CommitmentDecoder` for typed
///   deserialization of commitment data.
abstract contract WorldIdBridge is IWorldIdBridge {
    using ProofsLib for ProofsLib.Chain;
    using CommitmentDecoder for bytes;

    /// @dev Current head of the rolling keccak state chain.
    ProofsLib.Chain public keccakChain;

    /// @dev Holds a mapping of invalidated Proof IDs. Slot 2.
    mapping(bytes32 => bool) public invalidatedProofIds;

    /// @notice The latest proven Merkle root. Slot 3.
    uint256 public latestRoot;

    /// @dev Root validity window in seconds. Slot 4.
    uint256 public rootValidityWindow;

    /// @dev Merkle tree depth. Slot 5.
    uint256 public treeDepth;

    /// @dev Minimum expiration threshold.
    uint64 public minExpirationThreshold;

    /// @dev Maps root → (timestamp, proofId).
    mapping(bytes32 root => ProvenRootInfo rootInfo) internal rootToTimestampAndProofId;

    /// @dev Maps issuerSchemaId → (pubKey, proofId).
    mapping(uint64 schemaId => ProvenPubKeyInfo issuerPubKeyInfo) public issuerSchemaIdToPubkeyAndProofId;

    /// @dev Maps oprfKeyId → (pubKey, proofId). Slot 8.
    mapping(uint160 oprfKeyId => ProvenPubKeyInfo oprfPubKeyInfo) internal oprfKeyIdToPubkeyAndProofId;

    ////////////////////////////////////////////////////////////
    //                      CONSTRUCTOR                       //
    ////////////////////////////////////////////////////////////

    constructor(uint256 rootValidityWindow_, uint256 treeDepth_, uint64 minExpirationThreshold_) {
        // keccakChain.head must live at slot 0 — remote MPT proofs rely on this.
        bytes32 slot;
        assembly {
            slot := keccakChain.slot
        }
        if (slot != bytes32(0)) revert InvalidChainSlot();

        rootValidityWindow = rootValidityWindow_;
        treeDepth = treeDepth_;
        minExpirationThreshold = minExpirationThreshold_;
    }

    /// @inheritdoc IWorldIdBridge
    function commitChained(ProofsLib.CommitmentWithProof calldata commitWithProof) external virtual;

    /// @inheritdoc IWorldIdBridge
    function isValidRoot(uint256 root) public view virtual returns (bool) {
        bytes32 proofId = rootToTimestampAndProofId[bytes32(root)].proofId;
        if (invalidatedProofIds[proofId]) return false;

        uint256 timestamp = rootToTimestampAndProofId[bytes32(root)].timestamp;
        if (timestamp == 0) return false;

        return (root == latestRoot || (block.timestamp <= timestamp + rootValidityWindow));
    }

    /// @notice Writes a proven root into bridge state.
    /// @param root The new Merkle root.
    /// @param timestamp The timestamp at which the root was proven.
    /// @param proofId The proof ID associated with this root.
    function updateRoot(uint256 root, uint256 timestamp, bytes32 proofId) internal virtual {
        latestRoot = root;
        rootToTimestampAndProofId[bytes32(root)] = ProvenRootInfo({timestamp: timestamp, proofId: proofId});
    }

    /// @notice Writes a proven issuer public key into bridge state.
    /// @param issuerSchemaId The credential schema ID.
    /// @param x The x-coordinate of the BabyJubJub public key.
    /// @param y The y-coordinate of the BabyJubJub public key.
    /// @param proofId The proof ID associated with this key.
    function setIssuerPubkey(uint64 issuerSchemaId, uint256 x, uint256 y, bytes32 proofId) internal virtual {
        issuerSchemaIdToPubkeyAndProofId[issuerSchemaId] =
            ProvenPubKeyInfo({pubKey: BabyJubJub.Affine({x: x, y: y}), proofId: proofId});
    }

    /// @notice Writes a proven OPRF key into bridge state.
    /// @param oprfKeyId The OPRF key ID.
    /// @param x The x-coordinate of the BabyJubJub public key.
    /// @param y The y-coordinate of the BabyJubJub public key.
    /// @param proofId The proof ID associated with this key.
    function setOprfKey(uint160 oprfKeyId, uint256 x, uint256 y, bytes32 proofId) internal virtual {
        oprfKeyIdToPubkeyAndProofId[oprfKeyId] =
            ProvenPubKeyInfo({pubKey: BabyJubJub.Affine({x: x, y: y}), proofId: proofId});
    }

    /// @notice Marks a proof ID as invalidated.
    function invalidateProofId(bytes32 proofId) internal virtual {
        invalidatedProofIds[proofId] = true;
        emit ProofIdInvalidated(proofId);
    }

    /// @dev Applies an array of commitments in order, dispatching each to the appropriate state writer.
    /// @param commits The commitments to apply.
    function applyCommitments(ProofsLib.Commitment[] memory commits) internal {
        for (uint256 i; i < commits.length; ++i) {
            applyCommitment(commits[i]);
        }
    }

    /// @dev Applies a single commitment's state change based on its action selector.
    ///   Uses `CommitmentDecoder` for typed decoding, replacing inline assembly dispatch.
    function applyCommitment(ProofsLib.Commitment memory commit) internal virtual {
        bytes memory data = commit.data;
        bytes4 sel = CommitmentDecoder.extractSelector(data);

        if (sel == ProofsLib.UPDATE_ROOT_SELECTOR) {
            CommitmentDecoder.UpdateRootParams memory p = data.decodeUpdateRoot();
            updateRoot(p.root, p.timestamp, p.proofId);
        } else if (sel == ProofsLib.SET_ISSUER_PUBKEY_SELECTOR) {
            CommitmentDecoder.SetIssuerPubkeyParams memory p = data.decodeSetIssuerPubkey();
            setIssuerPubkey(p.issuerSchemaId, p.x, p.y, p.proofId);
        } else if (sel == ProofsLib.SET_OPRF_KEY_SELECTOR) {
            CommitmentDecoder.SetOprfKeyParams memory p = data.decodeSetOprfKey();
            setOprfKey(p.oprfKeyId, p.x, p.y, p.proofId);
        } else if (sel == ProofsLib.INVALIDATE_PROOF_ID_SELECTOR) {
            CommitmentDecoder.InvalidateProofIdParams memory p = data.decodeInvalidateProofId();
            invalidateProofId(p.proofId);
        } else {
            revert UnknownAction(uint8(uint32(sel)));
        }
    }
}
