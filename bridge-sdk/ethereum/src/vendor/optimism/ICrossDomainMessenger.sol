// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title ICrossDomainMessenger
/// @notice Minimal interface for the OP Stack cross-domain messenger. Used by OpStackBridgeAdapter
///   to send messages and by receiving adapters to verify the cross-domain sender.
interface ICrossDomainMessenger {
    /// @notice Sends a cross-domain message to the target address on the other chain.
    /// @param _target Address of the contract to call on the other chain.
    /// @param _message Encoded function call data.
    /// @param _minGasLimit Minimum gas limit for the message execution on the other chain.
    function sendMessage(address _target, bytes calldata _message, uint32 _minGasLimit) external payable;

    /// @notice Returns the address of the sender of the currently executing cross-domain message.
    /// @dev Only valid during the execution of a relayed message.
    function xDomainMessageSender() external view returns (address);
}
