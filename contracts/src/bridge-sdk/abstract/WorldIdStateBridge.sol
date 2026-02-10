// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IWorldIdStateBridge} from "../interfaces/IWorldIdStateBridge.sol";
import {IBridgeAdapter} from "../interfaces/IBridgeAdapter.sol";
import {BabyJubJub} from "../../../lib/oprf-key-registry/src/BabyJubJub.sol";
import {IL1Block} from "../vendored/optimism/IL1Block.sol";

import {MptVerifier} from "../libraries/MptVerifier.sol";

/// @title WorldIdStateBridge
/// @author World Contributors
/// @notice Abstract base for cross-chain for World ID state bridges
abstract contract WorldIdStateBridge is IWorldIdStateBridge {
    /// @dev Action: a new Merkle root was proven. Data: `abi.encode(root, timestamp, proofId)`.
    bytes4 internal constant UPDATE_ROOT_SELECTOR = bytes4(keccak256("updateRoot(uint256,uint256,bytes32)"));

    /// @dev Action: a credential issuer public key was proven.
    ///   Data: `abi.encode(issuerSchemaId, x, y, proofId)`.
    bytes4 internal constant SET_ISSUER_PUBKEY_SELECTOR =
        bytes4(keccak256("setIssuerPubkey(uint64,uint256,uint256,bytes32)"));

    /// @dev Action: an OPRF key was proven. Data: `abi.encode(oprfKeyId, x, y, proofId)`.
    bytes4 internal constant SET_OPRF_KEY_SELECTOR = bytes4(keccak256("setOprfKey(uint160,uint256,uint256,bytes32)"));

    /// @dev Action: a proof ID was invalidated. Data: `abi.encode(proofId)`.
    bytes4 internal constant INVALIDATE_PROOF_ID_SELECTOR = bytes4(keccak256("invalidateProofId(bytes32)"));

    /// @dev A commitment to the sequence of updates.
    struct Commitment {
        bytes32 blockHash;
        bytes data;
    }

    /// @notice A single commit in a keccak chain verifiable via `proof`.
    ///       represents a scritclly-ordered sequence of state transitions to the verifier's state
    ///       that whith an MPT against Ethereum L1s state.
    struct CommitmentWithProof {
        bytes mptProof;
        Commitment[] commits;
    }

    /// @dev Current head of the rolling keccak state chain.
    ///     Updated with each new commitment.
    bytes32 public keccakChain;

    /// @dev Holds a mapping of invalidated Proof IDs.
    ///      Any root or pubkey relying on an invalidated proof ID is rejected by `isValidRoot` and WorldIDVerifier functions.
    mapping(bytes32 => bool) internal _invalidatedProofIds; // slot 0

    uint256 public latestRoot; // slot 1
    uint256 internal _rootValidityWindow; // slot 2
    uint256 internal _treeDepth; // slot 3

    struct ProvenRootInfo {
        uint256 timestamp;
        bytes32 proofId;
    }

    struct ProvenPubKeyInfo {
        BabyJubJub.Affine pubKey;
        bytes32 proofId;
    }

    mapping(bytes32 root => ProvenRootInfo rootInfo) internal _rootToTimestampAndProofId; // slot 4
    mapping(uint64 schemaId => ProvenPubKeyInfo issuerPubKeyInfo) public _issuerSchemaIdToPubkeyAndProofId; // slot 5
    mapping(uint160 oprfKeyId => ProvenPubKeyInfo oprfPubKeyInfo) internal _oprfKeyIdToPubkeyAndProofId; // slot 6

    IBridgeAdapter[] internal _adapters; // slot 10

    uint64 internal _minExpirationThreshold; // slot 12

    /// @notice The oracle that attests to known L1 block hashes on this chain.
    IL1Block public immutable L1_BLOCK_HASH_ORACLE;

    /// @notice The L1StateAdapter contract address on Ethereum L1.
    address public immutable L1_BRIDGE;

    ////////////////////////////////////////////////////////////
    //                      CONSTRUCTOR                       //
    ////////////////////////////////////////////////////////////

    constructor(
        uint256 rootValidityWindow_,
        uint256 treeDepth_,
        uint64 minExpirationThreshold_,
        IL1Block l1BlockHashOracle,
        address l1Bridge
    ) {
        L1_BLOCK_HASH_ORACLE = l1BlockHashOracle;
        L1_BRIDGE = l1Bridge;
        _rootValidityWindow = rootValidityWindow_;
        _treeDepth = treeDepth_;
        _minExpirationThreshold = minExpirationThreshold_;
    }

    /// @notice Commits a sequence of state transitions to the bridge's keccak chain, verifies the new head against L1, and dispatches to adapters.
    /// @dev Each commit in `commitWithProof.commits` is applied in order.
    function commitChained(CommitmentWithProof memory commitWithProof) public virtual {
        if (commitWithProof.commits.length == 0) revert EmptyChainedCommits();

        for (uint256 i; i < commitWithProof.commits.length; ++i) {
            keccakChain = commitChain(commitWithProof.commits[i]);
        }

        verifyChainedCommitment(keccakChain, commitWithProof.mptProof);
    }

    /// @notice Commits a transition to the hash chain. _Does not verify the commitment's validity_
    function commitChain(Commitment memory commit) internal returns (bytes32 chainedHead) {
        chainedHead = keccak256(abi.encodePacked(keccakChain, commit.blockHash, commit.data));
        applyCommitment(commit);
    }

    /// @notice Writes a proven root into bridge state.
    function updateRoot(uint256 root, uint256 timestamp, bytes32 proofId) internal virtual {
        latestRoot = root;
        _rootToTimestampAndProofId[bytes32(root)] = ProvenRootInfo({timestamp: timestamp, proofId: proofId});
    }

    /// @notice Writes a proven issuer public key into bridge state.
    function setIssuerPubkey(uint64 issuerSchemaId, uint256 x, uint256 y, bytes32 proofId) internal virtual {
        _issuerSchemaIdToPubkeyAndProofId[issuerSchemaId] =
            ProvenPubKeyInfo({pubKey: BabyJubJub.Affine({x: x, y: y}), proofId: proofId});
    }

    /// @notice Writes a proven OPRF key into bridge state.
    function setOprfKey(uint160 oprfKeyId, uint256 x, uint256 y, bytes32 proofId) internal virtual {
        _oprfKeyIdToPubkeyAndProofId[oprfKeyId] =
            ProvenPubKeyInfo({pubKey: BabyJubJub.Affine({x: x, y: y}), proofId: proofId});
    }

    /// @notice Invalidates a proof ID by marking it in bridge state. Invalidated proof IDs cause roots and pubkeys relying on them to be rejected by `isValidRoot` and WorldIDVerifier functions.
    function invalidateProofId(bytes32 proofId) internal virtual {
        _invalidatedProofIds[proofId] = true;
        emit ProofIdInvalidated(proofId);
    }

    /// @dev Applies a single chained commit's state change based on its action type.
    function applyCommitment(Commitment memory commit) internal virtual {
        bytes memory data = commit.data;
        bytes4 sel;
        assembly {
            sel := mload(add(data, 0x20))
        }

        if (sel == UPDATE_ROOT_SELECTOR) {
            uint256 root;
            uint256 timestamp_;
            bytes32 proofId;
            assembly {
                let d := add(data, 0x24)
                root := mload(d)
                timestamp_ := mload(add(d, 0x20))
                proofId := mload(add(d, 0x40))
            }
            updateRoot(root, timestamp_, proofId);
        } else if (sel == SET_ISSUER_PUBKEY_SELECTOR) {
            uint64 schemaId;
            uint256 x;
            uint256 y;
            bytes32 proofId;
            assembly {
                let d := add(data, 0x24)
                schemaId := mload(d)
                x := mload(add(d, 0x20))
                y := mload(add(d, 0x40))
                proofId := mload(add(d, 0x60))
            }
            setIssuerPubkey(schemaId, x, y, proofId);
        } else if (sel == SET_OPRF_KEY_SELECTOR) {
            uint160 oprfKeyId;
            uint256 x;
            uint256 y;
            bytes32 proofId;
            assembly {
                let d := add(data, 0x24)
                oprfKeyId := mload(d)
                x := mload(add(d, 0x20))
                y := mload(add(d, 0x40))
                proofId := mload(add(d, 0x60))
            }
            setOprfKey(oprfKeyId, x, y, proofId);
        } else if (sel == INVALIDATE_PROOF_ID_SELECTOR) {
            bytes32 proofId;
            assembly {
                proofId := mload(add(data, 0x24))
            }
            invalidateProofId(proofId);
        } else {
            revert IWorldIdStateBridge.UnknownAction(uint8(uint32(sel)));
        }
    }

    /// @notice Hashes a sequence of commitments with a given chain head
    function hashChainedCommitment(Commitment[] memory commits, bytes32 _chain)
        internal
        pure
        returns (bytes32 _chained)
    {
        _chained = _chain;
        for (uint256 i; i < commits.length; ++i) {
            _chained = keccak256(abi.encodePacked(_chained, commits[i].blockHash, commits[i].data));
        }
    }

    /// @dev Verifies that `keccakChain` is a valid chain head by proving the
    ///   `_validChainHeads[keccakChain]` mapping value is `true` on L1 via MPT storage proof.
    /// @param keccakChain_ The chain head to verify.
    /// @param proof ABI-encoded `(bytes l1HeaderRlp, bytes[] l1AccountProof, bytes[] chainHeadValidityProof)`.
    function verifyChainedCommitment(bytes32 keccakChain_, bytes memory proof) internal view virtual {
        (bytes memory l1HeaderRlp, bytes[] memory l1AccountProof, bytes[] memory chainHeadValidityProof) =
            abi.decode(proof, (bytes, bytes[], bytes[]));

        bytes32 l1BlockHash = keccak256(l1HeaderRlp);

        if (!(L1_BLOCK_HASH_ORACLE.hash() == l1BlockHash)) {
            revert IWorldIdStateBridge.UnknownL1BlockHash();
        }

        bytes32 l1StateRoot = MptVerifier.extractStateRootFromHeader(l1HeaderRlp, l1BlockHash);
        bytes32 storageRoot = MptVerifier.verifyAccountAndGetStorageRoot(L1_BRIDGE, l1AccountProof, l1StateRoot);

        bytes32 validitySlot = MptVerifier._computeMappingSlot(MptVerifier._VALID_CHAIN_KECCAK_CHAIN_SLOT, keccakChain_);
        uint256 isValid = MptVerifier.storageFromProof(chainHeadValidityProof, storageRoot, validitySlot);

        if (isValid != 1) revert InvalidChainHead();
    }

    /// @inheritdoc IWorldIdStateBridge
    function isValidRoot(uint256 root) public view virtual returns (bool) {
        bytes32 proofId = _rootToTimestampAndProofId[bytes32(root)].proofId;
        if (_invalidatedProofIds[proofId]) return false;

        uint256 timestamp = _rootToTimestampAndProofId[bytes32(root)].timestamp;
        if (timestamp == 0) return false;

        return (root == latestRoot || (block.timestamp <= timestamp + _rootValidityWindow));
    }

    /// @inheritdoc IWorldIdStateBridge
    function registerAdapter(IBridgeAdapter adapter) external virtual {
        _adapters.push(adapter);
        emit AdapterRegistered(_adapters.length - 1, address(adapter));
    }

    /// @inheritdoc IWorldIdStateBridge
    function removeAdapter(uint256 index) external virtual {
        uint256 lastIndex = _adapters.length - 1;
        address removed = address(_adapters[index]);

        if (index != lastIndex) {
            _adapters[index] = _adapters[lastIndex];
        }
        _adapters.pop();

        emit AdapterRemoved(index, removed);
    }

    function dispatch(bytes calldata message) internal virtual {
        for (uint256 i; i < _adapters.length; ++i) {
            (bool success,) = address(_adapters[i]).call(message);
            if (!success) revert("Adapter call failed");
        }
    }
}
