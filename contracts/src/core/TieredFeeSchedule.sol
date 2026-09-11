// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IFeeSchedule} from "./interfaces/IFeeSchedule.sol";

/**
 * @title TieredFeeSchedule
 * @author World Contributors
 * @notice Two-tier volume pricing for a {WorldIDFeeEscrow} channel.
 * @dev The first `tierSize` verifications cost `priceInTier` each, every one after costs
 *      `priceAfterTier`. Immutable and non-upgradeable; see {FixedFeeSchedule}.
 */
contract TieredFeeSchedule is IFeeSchedule {
    /// @notice Number of verifications priced at `priceInTier`.
    uint256 public immutable tierSize;

    /// @notice Per-verification fee inside the first tier.
    uint256 public immutable priceInTier;

    /// @notice Per-verification fee beyond the first tier.
    uint256 public immutable priceAfterTier;

    constructor(uint256 tierSize_, uint256 priceInTier_, uint256 priceAfterTier_) {
        tierSize = tierSize_;
        priceInTier = priceInTier_;
        priceAfterTier = priceAfterTier_;
    }

    /// @inheritdoc IFeeSchedule
    function cumulativeFee(uint256 count) external view returns (uint256) {
        uint256 size = tierSize;
        if (count <= size) {
            return count * priceInTier;
        }
        return size * priceInTier + (count - size) * priceAfterTier;
    }
}
