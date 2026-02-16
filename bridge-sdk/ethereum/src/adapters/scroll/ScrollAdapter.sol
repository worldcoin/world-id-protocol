// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IBridgeAdapter} from "../../interfaces/IBridgeAdapter.sol";
import {IL1ScrollMessenger} from "../../vendored/scroll/IL1ScrollMessenger.sol";

/// @title ScrollAdapter
/// @author World Contributors
/// @notice Concrete `IBridgeAdapter` for Scroll. Wraps the Scroll L1 messenger to deliver
///   encoded `commitFromL1` calls to the L2 receiver.
/// @dev Permissionless — auth is enforced on the L2 side via `xDomainMessageSender`.
contract ScrollAdapter is IBridgeAdapter {
    /// @notice The Scroll L1 messenger contract.
    IL1ScrollMessenger public immutable MESSENGER;

    /// @notice The target contract on Scroll L2 (ScrollReceiver).
    address public immutable TARGET;

    /// @notice Gas limit for the L2 execution.
    uint256 public immutable GAS_LIMIT;

    constructor(IL1ScrollMessenger messenger, address target, uint256 gasLimit) {
        MESSENGER = messenger;
        TARGET = target;
        GAS_LIMIT = gasLimit;
    }

    /// @inheritdoc IBridgeAdapter
    function sendMessage(bytes calldata message) external payable virtual {
        MESSENGER.sendMessage{value: msg.value}(TARGET, 0, message, GAS_LIMIT);
    }
}
