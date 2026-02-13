// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IL1BlockHashOracle
/// @notice Interface for L1 block hash validation oracles used by universal bridge receivers.
interface IL1BlockHashOracle {
    function isValid(bytes32 blockHash) external view returns (bool);
}
