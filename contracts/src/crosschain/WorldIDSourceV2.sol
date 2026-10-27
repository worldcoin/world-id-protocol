// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {WorldIDSource} from "./WorldIDSource.sol";
import {Lib} from "./lib/Lib.sol";
import {NothingChanged} from "./Error.sol";

/// @notice Bounds source events so each batch can be relayed in one destination transaction.
contract WorldIDSourceV2 is WorldIDSource {
    /// @notice Reserves one of the relay's 64 commitments for the root.
    uint256 public constant MAX_KEY_UPDATES = 63;

    error TooManyKeyUpdates();

    constructor(address registry, address issuerRegistry, address oprfRegistry)
        WorldIDSource(registry, issuerRegistry, oprfRegistry)
    {}

    /// @inheritdoc WorldIDSource
    function VERSION() external pure virtual override returns (uint8) {
        return 2;
    }

    /// @notice Propagates at most 63 key IDs plus the root; repeated IDs count toward the limit.
    function propagateState(uint64[] calldata issuerSchemaIds, uint160[] calldata oprfKeyIds)
        external
        virtual
        override
        onlyProxy
    {
        if (issuerSchemaIds.length + oprfKeyIds.length > MAX_KEY_UPDATES) revert TooManyKeyUpdates();
        (Lib.Commitment[] memory commits, uint256 count) = _buildCommitments(issuerSchemaIds, oprfKeyIds);
        if (count == 0) revert NothingChanged();
        _applyAndCommit(commits);
    }
}
