// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IBridgeAdapter} from "../../interfaces/IBridgeAdapter.sol";
import {ICrossDomainMessenger} from "../../vendored/optimism/ICrossDomainMessenger.sol";

/// @title OpStackBridgeAdapter
/// @author World Contributors
/// @notice Concrete `IBridgeAdapter` for OP Stack chains. Wraps a cross-domain messenger to
///   deliver encoded `receiveChainedCommit` calls to a fixed target on the other chain.
/// @dev Permissionless — auth is enforced on the receiving side via `_authorizeReceive`.
contract OpStackBridgeAdapter is IBridgeAdapter {
    /// @notice The OP Stack cross-domain messenger used to relay messages.
    ICrossDomainMessenger public immutable MESSENGER;

    /// @notice The target contract on the destination chain (e.g. the receiving adapter).
    address public immutable TARGET;

    /// @notice Minimum gas limit forwarded to the messenger for message execution.
    uint32 public immutable MIN_GAS_LIMIT;

    constructor(ICrossDomainMessenger messenger, address target, uint32 minGasLimit) {
        MESSENGER = messenger;
        TARGET = target;
        MIN_GAS_LIMIT = minGasLimit;
    }

    /// @inheritdoc IBridgeAdapter
    function sendMessage(bytes calldata message) external payable virtual {
        MESSENGER.sendMessage{value: msg.value}(TARGET, message, MIN_GAS_LIMIT);
    }
}
