// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BridgeAdapter} from "../../lib/BridgeAdapter.sol";
import {Unauthorized} from "../../interfaces/INativeReceiver.sol";

/// @title ZkSyncReceiver
/// @author World Contributors
/// @notice L2 receiver for World ID state on ZkSync Era. Validates that the cross-chain
///   message originates from the L1StateBridge by checking the ZkSync address alias.
contract ZkSyncReceiver is BridgeAdapter {
    /// @dev ZkSync aliases L1 sender addresses by adding this offset (same as Arbitrum).
    ///   See: https://docs.zksync.io/build/developer-reference/l1-l2-interop#address-aliasing
    uint160 internal constant _ALIAS_OFFSET = uint160(0x1111000000000000000000000000000000001111);

    /// @notice The L1StateBridge contract address on Ethereum L1.
    address public immutable L1_STATE_BRIDGE;

    constructor(
        address verifier,
        address l1StateBridge,
        uint256 rootValidityWindow_,
        uint256 treeDepth_,
        uint64 minExpirationThreshold_
    ) BridgeAdapter("ZkSyncReceiver", verifier, rootValidityWindow_, treeDepth_, minExpirationThreshold_) {
        L1_STATE_BRIDGE = l1StateBridge;
    }

    /// @dev Validates that msg.sender is the aliased L1StateBridge address.
    function _validateCrossChainSender() internal view virtual override {
        if (msg.sender != address(uint160(L1_STATE_BRIDGE) + _ALIAS_OFFSET)) {
            revert Unauthorized();
        }
    }
}
