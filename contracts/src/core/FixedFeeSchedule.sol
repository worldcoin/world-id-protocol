// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IFeeSchedule} from "./interfaces/IFeeSchedule.sol";

/**
 * @title FixedFeeSchedule
 * @author World Contributors
 * @notice Flat per-verification pricing for a {WorldIDFeeEscrow} channel.
 * @dev Immutable and non-upgradeable: a channel pins its schedule address at open, so the terms
 *      must not be mutable after the RP signs them.
 */
contract FixedFeeSchedule is IFeeSchedule {
    /// @notice Fee charged per verification.
    uint256 public immutable pricePerVerification;

    constructor(uint256 pricePerVerification_) {
        pricePerVerification = pricePerVerification_;
    }

    /// @inheritdoc IFeeSchedule
    function cumulativeFee(uint256 count) external view returns (uint256) {
        return count * pricePerVerification;
    }
}
