// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BabyJubJub} from "lib/oprf-key-registry/src/BabyJubJub.sol";

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

/// @notice Thrown when propagateState is called but no state has changed.
error NothingChanged();

/// @notice Thrown when a zero address is provided where one is not allowed.
error ZeroAddress();

/// @notice Emitted when the native World Chain state is updated and propagated into the bridge.
event ChainCommitted(bytes32 indexed keccakChain, uint256 indexed blockNumber, bytes commitment);
