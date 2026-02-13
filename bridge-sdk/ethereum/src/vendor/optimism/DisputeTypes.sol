// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title DisputeTypes
/// @notice Minimal type definitions for dispute game interactions. Derived from Optimism's
///         contracts-bedrock/src/dispute/lib/Types.sol — only the types needed by
///         MptStorageProofAdapter are included.

/// @notice The status of a dispute game.
enum GameStatus {
    /// @dev The game is in progress and has not been resolved.
    IN_PROGRESS,
    /// @dev The game has resolved in favor of the challenger.
    CHALLENGER_WINS,
    /// @dev The game has resolved in favor of the defender.
    DEFENDER_WINS
}

/// @notice A `Claim` represents a 32-byte commitment (typically an output root).
type Claim is bytes32;

/// @notice A `GameType` represents the type of proof system used for the dispute game.
type GameType is uint32;

/// @notice A `Timestamp` represents a point in time, encoded as a uint64.
type Timestamp is uint64;
