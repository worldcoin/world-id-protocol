// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title ITransport
/// @author World Contributors
/// @notice An immutable wrapper around a single cross-chain transport targeting a single
///   destination chain.
/// @dev The state bridge calls `sendMessage(bytes)` and the transport handles encoding, fee
///   payment, and domain routing internally. Transports MAY require `msg.value` for fees.
interface ITransport {
    /// @notice Dispatches an encoded state update to the destination chain.
    /// @dev The transport MUST forward `message` unmodified.
    /// @param message The ABI-encoded state update payload.
    function sendMessage(bytes calldata message) external payable;
}
