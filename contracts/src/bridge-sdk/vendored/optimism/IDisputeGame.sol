// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {GameStatus, Claim} from "./DisputeTypes.sol";

/// @title IDisputeGame
/// @notice Minimal interface for an Optimism dispute game proxy. Only includes the functions
///         needed by MptStorageProofAdapter.
interface IDisputeGame {
    /// @notice Returns the current status of the dispute game.
    /// @return The game's status (IN_PROGRESS, CHALLENGER_WINS, or DEFENDER_WINS).
    function status() external view returns (GameStatus);

    /// @notice Returns the root claim of the dispute game — the output root being disputed.
    /// @return The root claim as a `Claim` (bytes32).
    function rootClaim() external pure returns (Claim);
}
