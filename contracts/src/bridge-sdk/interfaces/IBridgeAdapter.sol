// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IBridgeAdapter
/// @author World Contributors
/// @notice An immutable wrapper around a single cross-chain transport targeting a single
///   destination chain.
/// @dev The state bridge calls `sendMessage(bytes)` and the adapter handles encoding, fee
///   payment, and domain routing internally. Adapters MAY require `msg.value` for transport fees.
interface IBridgeAdapter {
    /// @notice The address of the cross-chain messenger contract used by this adapter (if any).
    function MESSENGER() external view returns (address);

    /// @notice The minimum gas limit that should be forwarded to the messenger for _any_ message.
    function GAS_LIMIT() external view returns (uint32);

    /// @notice Dispatches an encoded state update to the destination chain.
    /// @dev The adapter MUST forward `message` unmodified.
    /// @param message The ABI-encoded state update payload.
    function sendMessage(bytes calldata message) external payable;
}
