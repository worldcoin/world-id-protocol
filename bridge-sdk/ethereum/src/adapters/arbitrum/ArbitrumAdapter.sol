// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IBridgeAdapter} from "../../interfaces/IBridgeAdapter.sol";
import {IInbox} from "../../vendored/arbitrum/IInbox.sol";

/// @title ArbitrumAdapter
/// @author World Contributors
/// @notice Concrete `IBridgeAdapter` for Arbitrum One. Wraps the Arbitrum Inbox to create
///   retryable tickets that deliver encoded `commitFromL1` calls to the L2 receiver.
/// @dev Permissionless — auth is enforced on the L2 side via address aliasing.
contract ArbitrumAdapter is IBridgeAdapter {
    /// @notice The Arbitrum Inbox contract on L1.
    IInbox public immutable INBOX;

    /// @notice The target contract on Arbitrum L2 (ArbitrumReceiver).
    address public immutable TARGET;

    /// @notice Maximum submission cost for the retryable ticket.
    uint256 public immutable MAX_SUBMISSION_COST;

    /// @notice Gas limit for the L2 execution.
    uint256 public immutable GAS_LIMIT;

    /// @notice Maximum fee per gas for the L2 execution.
    uint256 public immutable MAX_FEE_PER_GAS;

    constructor(IInbox inbox, address target, uint256 maxSubmissionCost, uint256 gasLimit, uint256 maxFeePerGas) {
        INBOX = inbox;
        TARGET = target;
        MAX_SUBMISSION_COST = maxSubmissionCost;
        GAS_LIMIT = gasLimit;
        MAX_FEE_PER_GAS = maxFeePerGas;
    }

    /// @inheritdoc IBridgeAdapter
    function sendMessage(bytes calldata message) external payable virtual {
        INBOX.createRetryableTicket{value: msg.value}(
            TARGET,
            0, // l2CallValue
            MAX_SUBMISSION_COST,
            msg.sender, // excessFeeRefundAddress
            msg.sender, // callValueRefundAddress
            GAS_LIMIT,
            MAX_FEE_PER_GAS,
            message
        );
    }
}
