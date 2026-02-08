// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IBridgedStateAdapter} from "../interfaces/IBridgedStateAdapter.sol";
import {IWorldIDVerifier} from "../../interfaces/IWorldIDVerifier.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IBridgeAdapter} from "../interfaces/IBridgeAdapter.sol";
import {BabyJubJub} from "oprf-key-registry/src/BabyJubJub.sol";
import {Verifier} from "../../Verifier.sol";

/// @title ICrossDomainWorldIdVerifier
/// @author World Contributors
/// @notice The destination-chain World ID verifier. Caches bridged state, exposes
///   `ICrossDomainRegistryState` getters over the cache, and implements the full
///   `IWorldIDVerifier` interface for cross-chain proof verification.
/// @dev Supports state invalidation via `proofId`. Every piece of state delivered to the
///   verifier carries an opaque `bytes32 proofId`. The verifier stores it alongside the cached
///   value and checks `_invalidatedProofIds[proofId]` at verification time.
///
///   - **MPT storage proofs:** `proofId` is derived from the dispute game address.
///   - **Relay paths** (canonical L1->L2, third-party bridges): `proofId` is `bytes32(0)`.
///     This state cannot be individually invalidated — it expires naturally via
///     `rootValidityWindow`.
///
///   The verifier never interprets `proofId`. It's an opaque handle that lets adapters
///   retroactively invalidate state without leaking transport semantics into the verifier.
abstract contract CrossDomainWorldIdVerifier is IWorldIDVerifier, IBridgedStateAdapter {
    mapping(bytes32 => bool) internal _invalidatedProofIds;

    /// @dev Contract for proof verification (Groth16)
    Verifier internal _verifier;

    uint256 latestRoot;
    uint256 rootValidityWindow;
    uint256 treeDepth;

    struct ProvenRootInfo {
        uint256 timestamp;
        bytes32 proofId;
    }

    struct ProvenPubKeyInfo {
        BabyJubJub.Affine pubKey;
        bytes32 proofId;
    }

    mapping(bytes32 root => ProvenRootInfo rootInfo) internal _rootToTimestampAndProofId;
    mapping(uint64 schemaId => ProvenPubKeyInfo issuerPubKeyInfo) internal _issuerSchemaIdToPubkeyAndProofId;
    mapping(uint160 oprfKeyId => ProvenPubKeyInfo oprfPubKeyInfo) internal _oprfKeyIdToPubkeyAndProofId;

    constructor(address verifier, uint256 _rootValidityWindow, uint256 _treeDepth) {
        _verifier = Verifier(verifier);
        latestRoot = 0;
        rootValidityWindow = _rootValidityWindow;
        treeDepth = _treeDepth;
    }

    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    /// @dev Thrown when a non-adapter address attempts to call an adapter-only function.
    error UnauthorizedAdapter();

    /// @dev Thrown when attempting to invalidate a proof ID that has already been invalidated.
    error ProofIdAlreadyInvalidated(bytes32 proofId);

    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
    ////////////////////////////////////////////////////////////

    /// @notice Emitted when a proof ID is invalidated, rendering all state proven against it
    ///   invalid.
    /// @param proofId The invalidated proof identifier.
    event ProofIdInvalidated(bytes32 indexed proofId);

    /// @notice Emitted when the bridged state adapter address is updated.
    /// @param oldAdapter The previous adapter address.
    /// @param newAdapter The new adapter address.
    event AdapterUpdated(address indexed oldAdapter, address indexed newAdapter);

    ////////////////////////////////////////////////////////////
    //                  ADAPTER FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @notice Invalidates a single proof ID, marking all state proven against the
    ///   corresponding dispute game as invalid.
    /// @dev Only callable by an authorized adapter. If the dispute game resolves
    ///   `CHALLENGER_WINS`, the adapter calls this to invalidate all state that was proven
    ///   against that output root in one operation.
    /// @param proofId The opaque proof identifier to invalidate.
    function invalidateProofId(bytes32 proofId) external virtual {
        if (_invalidatedProofIds[proofId]) {
            revert ProofIdAlreadyInvalidated(proofId);
        }
        _invalidatedProofIds[proofId] = true;
        emit ProofIdInvalidated(proofId);
    }

    /// @notice Invalidates multiple proof IDs in a single transaction.
    /// @dev Only callable by an authorized adapter. Batch variant of `invalidateProofId`.
    /// @param proofIds The array of opaque proof identifiers to invalidate.
    function invalidateProofIds(bytes32[] calldata proofIds) external virtual {
        uint256 length = proofIds.length;
        for (uint256 i = 0; i < length; i++) {
            bytes32 proofId = proofIds[i];
            if (_invalidatedProofIds[proofId]) {
                revert ProofIdAlreadyInvalidated(proofId);
            }
            _invalidatedProofIds[proofId] = true;
            emit ProofIdInvalidated(proofId);
        }
    }

    ////////////////////////////////////////////////////////////
    //                    OWNER FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    function receiveRoot(uint256 root, uint256 worldChainTimestamp, bytes32 proofId) external virtual {
        _rootToTimestampAndProofId[bytes32(root)] = ProvenRootInfo({timestamp: worldChainTimestamp, proofId: proofId});
    }

    function receiveIssuerPubkey(uint64 issuerSchemaId, uint256 x, uint256 y, bytes32 proofId) external virtual {
        _issuerSchemaIdToPubkeyAndProofId[issuerSchemaId] =
            ProvenPubKeyInfo({pubKey: BabyJubJub.Affine({x: x, y: y}), proofId: proofId});
    }

    function receiveOprfKey(uint160 oprfKeyId, uint256 x, uint256 y, bytes32 proofId) external virtual {
        _oprfKeyIdToPubkeyAndProofId[oprfKeyId] =
            ProvenPubKeyInfo({pubKey: BabyJubJub.Affine({x: x, y: y}), proofId: proofId});
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
        this._verifyProofAndSignals(
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

        if (!isValidRoot(root)) {
            revert("Invalid or expired root");
        }

        bytes32 rootProofId = _rootToTimestampAndProofId[bytes32(root)].proofId;
        if (_invalidatedProofIds[rootProofId]) {
            revert("Root proof ID has been invalidated");
        }

        ProvenPubKeyInfo memory issuerPubKeyInfo = _issuerSchemaIdToPubkeyAndProofId[issuerSchemaId];
        if (_invalidatedProofIds[issuerPubKeyInfo.proofId]) {
            revert("Issuer pubkey proof ID has been invalidated");
        }

        ProvenPubKeyInfo memory oprfPubKeyInfo = _oprfKeyIdToPubkeyAndProofId[uint160(rpId)];
        if (_invalidatedProofIds[oprfPubKeyInfo.proofId]) {
            revert("OPRF pubkey proof ID has been invalidated");
        }

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

    function isValidRoot(uint256 root) public view returns (bool) {
        bytes32 proofId = _rootToTimestampAndProofId[bytes32(root)].proofId;
        if (_invalidatedProofIds[proofId]) {
            return false;
        }

        uint256 timestamp = _rootToTimestampAndProofId[bytes32(root)].timestamp;
        if (timestamp == 0) {
            return false;
        }

        return (root == latestRoot || (block.timestamp <= timestamp + rootValidityWindow));
    }
}
