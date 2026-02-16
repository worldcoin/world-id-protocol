// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title BridgeEvents
/// @notice Events emitted by the World ID state bridge.

/// @notice Emitted when a proof ID is invalidated.
event ProofIdInvalidated(bytes32 indexed proofId);

/// @notice Emitted when a new bridge adapter is registered.
event AdapterRegistered(uint256 indexed index, address adapter);

/// @notice Emitted when a bridge adapter is removed.
event AdapterRemoved(uint256 indexed index, address adapter);

/// @notice Emitted when the native World Chain state is updated and propagated into the bridge.
event ChainCommitted(bytes32 indexed keccakChain, uint256 indexed blockNumber, bytes commitment);

/// @notice Emitted when commitments are published via Wormhole.
event WormholeMessagePublished(uint64 indexed sequence, uint32 nonce, uint256 numCommits);
