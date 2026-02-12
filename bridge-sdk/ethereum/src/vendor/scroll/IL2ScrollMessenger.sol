// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IL2ScrollMessenger
/// @notice Minimal interface for the Scroll L2 messenger contract.
///   Used by the L2 receiver to verify the cross-domain sender.
interface IL2ScrollMessenger {
    /// @notice Returns the address of the sender of the currently executing cross-domain message.
    /// @dev Only valid during the execution of a relayed message.
    function xDomainMessageSender() external view returns (address);
}
