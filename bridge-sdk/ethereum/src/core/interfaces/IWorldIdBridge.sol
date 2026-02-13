// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BabyJubJub} from "lib/oprf-key-registry/src/BabyJubJub.sol";
import {ProofsLib} from "../../lib/ProofsLib.sol";

/// @notice Shared struct definitions for the World ID state bridge.
struct ProvenRootInfo {
    uint256 timestamp;
    bytes32 proofId;
}

struct ProvenPubKeyInfo {
    BabyJubJub.Affine pubKey;
    bytes32 proofId;
}

/// @notice Thrown when no chained commits are provided.
error EmptyChainedCommits();

/// @notice Thrown when a chained commit has an unknown action type.
error UnknownAction(uint8 action);

/// @notice Thrown when the keccakChain slot check fails during construction.
error InvalidChainSlot();

/// @notice Thrown when an unsupported operation is invoked on a context.
error UnsupportedOperation();

/// @notice Thrown when propagateState is called but no state has changed.
error NothingChanged();

/// @notice Thrown when the output root fails acceptance criteria.
error InvalidOutputRoot();

/// @notice Emitted when a proof ID is invalidated.
event ProofIdInvalidated(bytes32 indexed proofId);

/// @notice Emitted when the native World Chain state is updated and propagated into the bridge.
event ChainCommitted(bytes32 indexed keccakChain, uint256 indexed blockNumber, bytes commitment);

/// @title IWorldIdBridge
/// @author World Contributors
/// @notice Interface for cross-chain World ID state bridges. Defines state getters, chained
///   commit processing, and adapter management shared by all adapter types (WorldChain, L1,
///   and bridged destinations).
interface IWorldIdBridge {
    /// @notice Checks if a root is currently valid.
    function isValidRoot(uint256 root) external view returns (bool);

    /// @notice Verifies, and commits a sequence of state changes to the Bridge.
    /// @param commitWithProof The commitment batch with domain specific MPT proof data.
    function commitChained(ProofsLib.CommitmentWithProof calldata commitWithProof) external;
}
