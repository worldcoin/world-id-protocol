// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IInbox
/// @notice Minimal interface for the Arbitrum Inbox contract on L1.
///   Used to create retryable tickets that execute on Arbitrum L2.
interface IInbox {
    /// @notice Creates a retryable ticket to send a message from L1 to L2.
    /// @param to The L2 destination address.
    /// @param l2CallValue The callvalue for the L2 message (in wei).
    /// @param maxSubmissionCost The maximum amount of ETH to pay for L2 submission.
    /// @param excessFeeRefundAddress The L2 address to refund excess fees to.
    /// @param callValueRefundAddress The L2 address to refund callvalue to if the ticket times out.
    /// @param gasLimit The max gas for the L2 execution.
    /// @param maxFeePerGas The max fee per gas for the L2 execution.
    /// @param data The calldata for the L2 message.
    /// @return The unique ID of the retryable ticket.
    function createRetryableTicket(
        address to,
        uint256 l2CallValue,
        uint256 maxSubmissionCost,
        address excessFeeRefundAddress,
        address callValueRefundAddress,
        uint256 gasLimit,
        uint256 maxFeePerGas,
        bytes calldata data
    ) external payable returns (uint256);
}
