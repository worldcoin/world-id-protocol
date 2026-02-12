// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BridgeAdapter} from "../../lib/BridgeAdapter.sol";
import {Unauthorized} from "../../interfaces/INativeReceiver.sol";
import {IL2ScrollMessenger} from "../../../vendor/scroll/IL2ScrollMessenger.sol";

/// @title ScrollReceiver
/// @author World Contributors
/// @notice L2 receiver for World ID state on Scroll. Validates that the cross-chain
///   message originates from the L1StateBridge via the Scroll messenger.
contract ScrollReceiver is BridgeAdapter {
    /// @notice The Scroll L2 messenger contract.
    IL2ScrollMessenger public immutable MESSENGER;

    /// @notice The L1StateBridge contract address on Ethereum L1.
    address public immutable L1_STATE_BRIDGE;

    constructor(
        address verifier,
        address l1StateBridge,
        IL2ScrollMessenger messenger,
        uint256 rootValidityWindow_,
        uint256 treeDepth_,
        uint64 minExpirationThreshold_
    ) BridgeAdapter("ScrollReceiver", verifier, rootValidityWindow_, treeDepth_, minExpirationThreshold_) {
        L1_STATE_BRIDGE = l1StateBridge;
        MESSENGER = messenger;
    }

    /// @dev Validates that the message came through the Scroll messenger from L1_STATE_BRIDGE.
    function _validateCrossChainSender() internal view virtual override {
        if (msg.sender != address(MESSENGER)) revert Unauthorized();
        if (MESSENGER.xDomainMessageSender() != L1_STATE_BRIDGE) revert Unauthorized();
    }
}
