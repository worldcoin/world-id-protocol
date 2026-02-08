// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IBridgeAdapter
/// @author World Contributors
/// @notice An immutable wrapper around a single cross-chain transport targeting a single
///   destination chain.
/// @dev The state bridge calls `sendMessage(bytes)` and the adapter handles encoding, fee
///   payment, and domain routing internally. `TARGET` and `GAS_LIMIT` are set at construction
///   and never change. `sendMessage` is a passthrough — it MUST NOT modify the payload.
///   Adapters MAY require `msg.value` for transport fees.
interface IBridgeAdapter {
    /// @notice Returns the address of the receive-side contract on the destination chain that
    ///   this adapter delivers messages to.
    /// @return The destination target address.
    function TARGET() external view returns (address);

    /// @notice Returns the gas limit allocated for message execution on the destination chain.
    /// @return The gas limit for cross-chain message execution.
    function GAS_LIMIT() external view returns (uint64);

    /// @notice Dispatches an encoded state update to the destination chain via the underlying
    ///   cross-chain transport.
    /// @dev The adapter MUST forward `message` unmodified. It MUST NOT interpret or alter the
    ///   payload. The adapter MAY require `msg.value` to cover bridge transport fees.
    /// @param message The ABI-encoded state update payload to deliver to the destination.
    function sendMessage(bytes calldata message) external payable;
}
