// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Minimal interface for the OP Stack L1Block predeploy at 0x4200000000000000000000000000000000000015.
/// @dev Provides access to the L1 origin block hash deposited by L1→L2 derivation.
interface IL1Block {
    /// @notice Returns the hash of the current L1 origin block.
    function hash() external view returns (bytes32);

    /// @notice Returns the number of the current L1 origin block.
    function number() external view returns (uint64);
}
