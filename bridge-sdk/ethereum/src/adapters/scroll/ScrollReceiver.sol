// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeWorldId} from "../../core/lib/NativeWorldId.sol";
import {Unauthorized} from "../../lib/BridgeErrors.sol";
import {IL2ScrollMessenger} from "../../vendored/scroll/IL2ScrollMessenger.sol";

/// @title ScrollReceiver
/// @author World Contributors
/// @notice L2 receiver for World ID state on Scroll. Validates that the cross-chain
///   message originates from the L1StateBridge via the Scroll messenger.
contract ScrollReceiver is NativeWorldId {
    /// @notice The Scroll L2 messenger contract.
    IL2ScrollMessenger public immutable MESSENGER;

    constructor(
        address verifier,
        address l1StateBridge,
        IL2ScrollMessenger messenger,
        uint256 rootValidityWindow_,
        uint256 treeDepth_,
        uint64 minExpirationThreshold_
    ) NativeWorldId(verifier, l1StateBridge, rootValidityWindow_, treeDepth_, minExpirationThreshold_) {
        MESSENGER = messenger;
    }

    /// @dev Validates that the message came through the Scroll messenger from L1_STATE_BRIDGE.
    function _validateCrossChainSender() internal view virtual override {
        if (msg.sender != address(MESSENGER)) revert Unauthorized();
        if (MESSENGER.xDomainMessageSender() != L1_STATE_BRIDGE) revert Unauthorized();
    }
}
