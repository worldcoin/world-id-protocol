// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IWorldIdStateBridge} from "../interfaces/IWorldIdStateBridge.sol";
import {IBridgeAdapter} from "../interfaces/IBridgeAdapter.sol";
import {BabyJubJub} from "lib/oprf-key-registry/src/BabyJubJub.sol";
import {ProofsLib} from "../libraries/Proofs.sol";
import {IL1Block} from "../vendored/optimism/IL1Block.sol";

/// @title WorldIdStateBridge
/// @author World Contributors
/// @notice Abstract base for cross-chain World ID state bridges. Owns all shared state
///   and commitment dispatch logic. Domain-specific verification and chain extension
///   are handled by context contracts (Source, Relay, Destination).
abstract contract WorldIdStateBridge is IWorldIdStateBridge {
    using ProofsLib for ProofsLib.Chain;

    ////////////////////////////////////////////////////////////
    //                    ACTION SELECTORS                     //
    ////////////////////////////////////////////////////////////

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

    /// @notice The oracle that attests to known L1 block hashes on this chain.
    IL1Block public immutable L1_BLOCK_HASH_ORACLE;

    /// @notice The RelayContext contract address on Ethereum L1.
    address public immutable L1_BRIDGE;

    ////////////////////////////////////////////////////////////
    //                        STRUCTS                         //
    ////////////////////////////////////////////////////////////

    struct ProvenRootInfo {
        uint256 timestamp;
        bytes32 proofId;
    }

    struct ProvenPubKeyInfo {
        BabyJubJub.Affine pubKey;
        bytes32 proofId;
    }

    ////////////////////////////////////////////////////////////
    //                   STORAGE LAYOUT                       //
    //  Slot positions matter for MPT proof verification.     //
    ////////////////////////////////////////////////////////////

    /// @dev Current head of the rolling keccak state chain. Slot 0-1.
    ProofsLib.Chain public keccakChain;

    /// @dev Holds a mapping of invalidated Proof IDs. Slot 2.
    mapping(bytes32 => bool) internal _invalidatedProofIds;

    /// @notice The latest proven Merkle root. Slot 3.
    uint256 public latestRoot;

    /// @dev Root validity window in seconds. Slot 4.
    uint256 internal _rootValidityWindow;

    /// @dev Merkle tree depth. Slot 5.
    uint256 internal _treeDepth;

    /// @dev Maps root → (timestamp, proofId). Slot 6.
    mapping(bytes32 root => ProvenRootInfo rootInfo) internal _rootToTimestampAndProofId;

    /// @dev Maps issuerSchemaId → (pubKey, proofId). Slot 7.
    mapping(uint64 schemaId => ProvenPubKeyInfo issuerPubKeyInfo) public _issuerSchemaIdToPubkeyAndProofId;

    /// @dev Maps oprfKeyId → (pubKey, proofId). Slot 8.
    mapping(uint160 oprfKeyId => ProvenPubKeyInfo oprfPubKeyInfo) internal _oprfKeyIdToPubkeyAndProofId;

    /// @dev Maps chain head → validity. Slot 9.
    ///   Must match `MptVerifier._VALID_CHAIN_KECCAK_CHAIN_SLOT`.
    mapping(bytes32 => bool) internal _validChainHeads;

    /// @dev Registered bridge adapters for cross-chain dispatch. Slot 10.
    IBridgeAdapter[] internal _adapters;

    /// @dev Minimum expiration threshold. Slot 11.
    uint64 internal _minExpirationThreshold;

    ////////////////////////////////////////////////////////////
    //                      CONSTRUCTOR                       //
    ////////////////////////////////////////////////////////////

    constructor(
        IL1Block l1BlockHashOracle,
        address l1Bridge,
        uint256 rootValidityWindow_,
        uint256 treeDepth_,
        uint64 minExpirationThreshold_
    ) {
        L1_BLOCK_HASH_ORACLE = l1BlockHashOracle;
        L1_BRIDGE = l1Bridge;
        _rootValidityWindow = rootValidityWindow_;
        _treeDepth = treeDepth_;
        _minExpirationThreshold = minExpirationThreshold_;
    }

    ////////////////////////////////////////////////////////////
    //                    STATE WRITERS                        //
    ////////////////////////////////////////////////////////////

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

    /// @notice Marks a proof ID as invalidated.
    function invalidateProofId(bytes32 proofId) internal virtual {
        _invalidatedProofIds[proofId] = true;
        emit ProofIdInvalidated(proofId);
    }

    ////////////////////////////////////////////////////////////
    //                 COMMITMENT DISPATCH                    //
    ////////////////////////////////////////////////////////////

    /// @dev Applies a single commitment's state change based on its action selector.
    function applyCommitment(ProofsLib.Commitment memory commit) internal virtual {
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

    /// @dev Applies an array of commitments in order.
    function _applyCommitments(ProofsLib.Commitment[] memory commits) internal {
        for (uint256 i; i < commits.length; ++i) {
            applyCommitment(commits[i]);
        }
    }

    ////////////////////////////////////////////////////////////
    //                         VIEWS                          //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IWorldIdStateBridge
    function isValidRoot(uint256 root) public view virtual returns (bool) {
        bytes32 proofId = _rootToTimestampAndProofId[bytes32(root)].proofId;
        if (_invalidatedProofIds[proofId]) return false;

        uint256 timestamp = _rootToTimestampAndProofId[bytes32(root)].timestamp;
        if (timestamp == 0) return false;

        return (root == latestRoot || (block.timestamp <= timestamp + _rootValidityWindow));
    }

    /// @notice Commits a sequence of state transitions by verifying them against L1 state
    ///   via MPT proof. The L1 block hash is read from the oracle for trust anchoring.
    /// @param commitWithProof The commitment batch with MPT proof data.
    function commitChained(ProofsLib.CommitmentWithProof calldata commitWithProof) external virtual {
        if (commitWithProof.commits.length == 0) revert EmptyChainedCommits();

        bytes32 trustedL1BlockHash = L1_BLOCK_HASH_ORACLE.hash();

        ProofsLib.Chain memory chain = keccakChain;
        ProofsLib.verifyProof(chain, commitWithProof, L1_BRIDGE, trustedL1BlockHash);

        _applyCommitments(commitWithProof.commits);
        keccakChain.commitChained(commitWithProof.commits);
        _validChainHeads[keccakChain.head] = true;

        emit ChainCommitted(keccakChain.head, block.number, abi.encode(commitWithProof));
    }

    ////////////////////////////////////////////////////////////
    //                   ADAPTER MANAGEMENT                   //
    ////////////////////////////////////////////////////////////

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
}
