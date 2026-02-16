// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeWorldId} from "../../core/lib/NativeWorldId.sol";
import {Unauthorized} from "../../lib/BridgeErrors.sol";

/// @title ArbitrumReceiver
/// @author World Contributors
/// @notice L2 receiver for World ID state on Arbitrum One. Validates that the cross-chain
///   message originates from the L1StateBridge by checking the Arbitrum address alias.
contract ArbitrumReceiver is NativeWorldId {
    /// @dev Arbitrum aliases L1 sender addresses by adding this offset.
    ///   See: https://docs.arbitrum.io/arbos/l1-to-l2-messaging#address-aliasing
    uint160 internal constant _ALIAS_OFFSET = uint160(0x1111000000000000000000000000000000001111);

    constructor(
        address verifier,
        address l1StateBridge,
        uint256 rootValidityWindow_,
        uint256 treeDepth_,
        uint64 minExpirationThreshold_
    ) NativeWorldId(verifier, l1StateBridge, rootValidityWindow_, treeDepth_, minExpirationThreshold_) {}

    /// @dev Validates that msg.sender is the aliased L1StateBridge address.
    function _validateCrossChainSender() internal view virtual override {
        if (msg.sender != address(uint160(L1_STATE_BRIDGE) + _ALIAS_OFFSET)) {
            revert Unauthorized();
        }
    }
}
