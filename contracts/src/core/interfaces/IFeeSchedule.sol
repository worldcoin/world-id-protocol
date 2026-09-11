// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title IFeeSchedule
 * @notice Prices cumulative work on a YABS channel.
 * @dev `cumulativeFee` MUST be monotonic non-decreasing in `count`. The escrow charges
 *      `cumulativeFee(settledCount) - paid` at each settlement, so a decreasing schedule
 *      would let the collector be overpaid then never clawed back.
 */
interface IFeeSchedule {
    /// @notice Total fee owed after `count` verifications have been settled on a channel.
    function cumulativeFee(uint256 count) external view returns (uint256);
}
