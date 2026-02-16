// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ProofsLib} from "../lib/ProofsLib.sol";

/// @title IStateBridge
/// @author World Contributors
/// @notice Interface for cross-chain World ID state bridges. Defines state getters, chained
///   commit processing, and adapter management shared by all adapter types (WorldChain, L1,
///   and bridged destinations).
interface IStateBridge {
    /// @notice Checks if a root is currently valid.
    function isValidRoot(uint256 root) external view returns (bool);

    /// @notice Verifies, and commits a sequence of state changes to the Bridge.
    /// @param commitWithProof The commitment batch with domain specific MPT proof data.
    function commitChained(ProofsLib.CommitmentWithProof calldata commitWithProof) external;
}
