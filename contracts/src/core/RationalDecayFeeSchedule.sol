// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IFeeSchedule} from "./interfaces/IFeeSchedule.sol";

/**
 * @title RationalDecayFeeSchedule
 * @author World Contributors
 * @notice Full price per verification up to `threshold`, then a rational tail whose marginal fee
 *         falls as ~`pricePerVerification * threshold^2 / n^2` toward zero.
 * @dev Total is bounded by {maxFee} = `2 * pricePerVerification * threshold`, approached but never
 *      reached. A channel funded to {maxFee} can therefore never become insolvent.
 *      Immutable and non-upgradeable: a channel pins its schedule address at open, so the terms
 *      must not be mutable after the RP signs them.
 *      Arithmetic is checked; an overflow reverts, which `WorldIDFeeEscrow.closeChannel` tolerates.
 */
contract RationalDecayFeeSchedule is IFeeSchedule {
    /// @notice Fee per verification below `threshold`.
    uint256 public immutable pricePerVerification;

    /// @notice Verification count at which the decaying tail begins.
    uint256 public immutable threshold;

    error ZeroPrice();
    error ZeroThreshold();

    constructor(uint256 pricePerVerification_, uint256 threshold_) {
        if (pricePerVerification_ == 0) revert ZeroPrice();
        if (threshold_ == 0) revert ZeroThreshold();
        pricePerVerification = pricePerVerification_;
        threshold = threshold_;
    }

    /// @inheritdoc IFeeSchedule
    /// @dev Monotonic: `(n - T) / n = 1 - T / n` is increasing in `n`, and flooring preserves non-decreasing.
    function cumulativeFee(uint256 count) external view returns (uint256) {
        uint256 p = pricePerVerification;
        uint256 t = threshold;

        if (count <= t) return count * p;

        // tail(n) = p * T * (n - T) / n, which approaches p * T from below as n grows.
        return t * p + (p * t * (count - t)) / count;
    }

    /// @notice Strict upper bound on the total fee this schedule can ever charge.
    function maxFee() external view returns (uint256) {
        return 2 * pricePerVerification * threshold;
    }
}
