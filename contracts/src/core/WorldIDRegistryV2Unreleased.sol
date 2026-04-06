// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {WorldIDRegistry} from "./WorldIDRegistry.sol";
import {IWorldIDRegistry} from "./interfaces/IWorldIDRegistry.sol";

/**
 * @title WorldIDRegistryV2
 * @author World Contributors
 * @notice Upgraded World ID Registry that fixes the root validity race condition.
 * @dev In V1, `isValidRoot` checked `_rootToTimestamp` (when a root was created). If a root was
 *      created long before it was replaced, its TTL could expire almost immediately after being
 *      superseded, rejecting valid proofs. V2 introduces `_rootToValidityTimestamp` which records
 *      when a root stopped being the latest, so the full validity window applies from that moment.
 * @custom:repo https://github.com/world-id/world-id-protocol
 */
contract WorldIDRegistryV2 is WorldIDRegistry {
    /// @dev Thrown when querying expiration for a root that was never recorded.
    error UnknownRoot(uint256 root);

    /// @dev root -> timestamp when the root was replaced (i.e. stopped being the latest root).
    ///      Used by V2's `isValidRoot` to measure TTL from replacement time, not creation time.
    mapping(uint256 => uint256) internal _rootToValidityTimestamp;

    /**
     * @dev Overrides V1 to record the timestamp when the current root stops being the latest.
     *      Captures `_latestRoot` before `super._recordCurrentRoot()` overwrites it, and stores
     *      `block.timestamp` in `_rootToValidityTimestamp` for that root.
     */
    function _recordCurrentRoot() internal virtual override {
        // We take the currentRoot before we update the new root and
        // set the validity timestamp of that root.
        //
        // In isValidRoot we now check this timestamp and not the other one
        uint256 currentRoot = _latestRoot;
        _rootToValidityTimestamp[currentRoot] = block.timestamp;
        super._recordCurrentRoot();
    }

    /// @inheritdoc IWorldIDRegistry
    /// @dev Overrides V1 to use `_rootToValidityTimestamp` (when root was replaced) instead of
    ///      `_rootToTimestamp` (when root was created), fixing the race condition.
    function isValidRoot(uint256 root) external view virtual override onlyProxy onlyInitialized returns (bool) {
        // The latest root is always valid.
        if (root == _latestRoot) return true;
        // Check if the root is known and not expired
        // IMPORTANT: this uses another mapping than version 1
        uint256 ts = _rootToValidityTimestamp[root];
        if (ts == 0) return false;
        return block.timestamp <= ts + _rootValidityWindow;
    }

    /// @dev Gets the replacement timestamp of a root. Returns 0 for the current latest root
    ///   (not yet replaced). Reverts with `UnknownRoot` if the root was never recorded.
    function getRootExpiration(uint256 root) external view virtual onlyProxy onlyInitialized returns (uint256) {
        if (root == _latestRoot) return 0;
        uint256 ts = _rootToValidityTimestamp[root];
        if (ts == 0) revert UnknownRoot(root);
        return ts;
    }
}
