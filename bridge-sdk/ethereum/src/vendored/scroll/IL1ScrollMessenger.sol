// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IL1ScrollMessenger
/// @notice Minimal interface for the Scroll L1 messenger contract.
///   Used to send messages from L1 to Scroll L2.
interface IL1ScrollMessenger {
    /// @notice Sends a cross-domain message from L1 to L2.
    /// @param target The L2 contract address to call.
    /// @param value The msg.value to pass with the L2 call (in wei).
    /// @param message The calldata for the L2 transaction.
    /// @param gasLimit The gas limit for the L2 execution.
    function sendMessage(address target, uint256 value, bytes calldata message, uint256 gasLimit) external payable;
}
