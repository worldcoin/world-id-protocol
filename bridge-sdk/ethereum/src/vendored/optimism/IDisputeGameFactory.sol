// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {GameType, Timestamp} from "./DisputeTypes.sol";
import {IDisputeGame} from "./IDisputeGame.sol";

/// @title IDisputeGameFactory
/// @notice Minimal interface for the Optimism DisputeGameFactory. Only includes the functions
///         needed by MptStorageProofAdapter.
interface IDisputeGameFactory {
    /// @notice Returns the dispute game at a given index.
    /// @param _index The index of the dispute game.
    /// @return gameType_ The type of the dispute game.
    /// @return timestamp_ The timestamp when the game was created.
    /// @return proxy_ The dispute game proxy contract.
    function gameAtIndex(uint256 _index)
        external
        view
        returns (GameType gameType_, Timestamp timestamp_, IDisputeGame proxy_);

    /// @notice Returns the total number of dispute games created.
    /// @return The number of dispute games.
    function gameCount() external view returns (uint256);
}
