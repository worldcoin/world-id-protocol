// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {RationalDecayFeeSchedule} from "../../src/core/RationalDecayFeeSchedule.sol";

contract RationalDecayFeeScheduleTest is Test {
    uint256 internal constant PRICE = 1e18;
    uint256 internal constant THRESHOLD = 4;

    RationalDecayFeeSchedule internal schedule;

    function setUp() public {
        schedule = new RationalDecayFeeSchedule(PRICE, THRESHOLD);
    }

    ////////////////////////////////////////////////////////////
    //                      CONSTRUCTOR                       //
    ////////////////////////////////////////////////////////////

    function test_constructorRejectsZeroPrice() public {
        vm.expectRevert(RationalDecayFeeSchedule.ZeroPrice.selector);
        new RationalDecayFeeSchedule(0, 1);
    }

    function test_constructorRejectsZeroThreshold() public {
        vm.expectRevert(RationalDecayFeeSchedule.ZeroThreshold.selector);
        new RationalDecayFeeSchedule(1, 0);
    }

    function test_parameters() public view {
        assertEq(schedule.pricePerVerification(), PRICE);
        assertEq(schedule.threshold(), THRESHOLD);
        assertEq(schedule.maxFee(), 8e18);
    }

    ////////////////////////////////////////////////////////////
    //                      EXACT VALUES                      //
    ////////////////////////////////////////////////////////////

    function test_linearRegionIsExact() public view {
        assertEq(schedule.cumulativeFee(0), 0);
        assertEq(schedule.cumulativeFee(1), 1e18);
        assertEq(schedule.cumulativeFee(2), 2e18);
        assertEq(schedule.cumulativeFee(3), 3e18);
        assertEq(schedule.cumulativeFee(4), 4e18);
    }

    function test_tailValues() public view {
        // 4e18 + 1e18 * 4 * 1 / 5
        assertEq(schedule.cumulativeFee(5), 4.8e18);
        // 4e18 + 1e18 * 4 * 4 / 8
        assertEq(schedule.cumulativeFee(8), 6e18);
        // 4e18 + 1e18 * 4 * 26 / 30
        assertEq(schedule.cumulativeFee(30), 7466666666666666666);
    }

    function test_continuousAtThreshold() public view {
        uint256 marginal = schedule.cumulativeFee(5) - schedule.cumulativeFee(4);
        assertEq(marginal, 0.8e18);
        assertGt(marginal, 0);
        assertLe(marginal, PRICE);
    }

    function test_approachesButNeverReachesMaxFee() public view {
        uint256 cap = schedule.maxFee();

        uint256 atMillion = schedule.cumulativeFee(1e6);
        assertEq(atMillion, 7999984000000000000);
        assertLt(atMillion, cap);
        assertGe(atMillion, cap - PRICE);

        uint256 atU64Max = schedule.cumulativeFee(type(uint64).max);
        assertEq(atU64Max, 7999999999999999999);
        assertLt(atU64Max, cap);
    }

    ////////////////////////////////////////////////////////////
    //                       PROPERTIES                       //
    ////////////////////////////////////////////////////////////

    function testFuzz_monotonic(uint128 n) public view {
        uint256 count = n;
        assertGe(schedule.cumulativeFee(count + 1), schedule.cumulativeFee(count));
    }

    function testFuzz_neverExceedsMax(uint256 n) public view {
        n = bound(n, 0, type(uint96).max);
        assertLt(schedule.cumulativeFee(n), schedule.maxFee());
    }

    /**
     * @dev The real-valued marginal `p*T^2 / (n*(n+1))` is strictly decreasing, but flooring the
     *      cumulative total lets one marginal exceed the previous by at most 1 wei. See
     *      {test_marginalCanRiseByOneWei} for a concrete case, which is why this is not a strict `<=`.
     */
    function testFuzz_marginalNonIncreasingAfterThreshold(uint64 n) public view {
        uint256 count = bound(uint256(n), THRESHOLD + 1, type(uint64).max - 1);
        uint256 next = schedule.cumulativeFee(count + 1) - schedule.cumulativeFee(count);
        uint256 previous = schedule.cumulativeFee(count) - schedule.cumulativeFee(count - 1);
        assertLe(next, previous + 1);
    }

    /// @dev Regression for the flooring artefact that makes a strict non-increasing marginal false.
    function test_marginalCanRiseByOneWei() public view {
        uint256 n = 5333333333333333333;
        uint256 next = schedule.cumulativeFee(n + 1) - schedule.cumulativeFee(n);
        uint256 previous = schedule.cumulativeFee(n) - schedule.cumulativeFee(n - 1);
        assertEq(previous, 0);
        assertEq(next, 1);
    }

    function testFuzz_parametersNeverOverflowInSupportedDomain(uint256 p, uint256 t, uint256 n) public {
        p = bound(p, 1, 1e24);
        t = bound(t, 1, 1e9);
        n = bound(n, 0, type(uint96).max);

        // p * t * (n - t) <= 1e24 * 1e9 * 2^96 ~= 8e61, well inside the uint256 ceiling of ~1.16e77.
        RationalDecayFeeSchedule s = new RationalDecayFeeSchedule(p, t);
        uint256 fee = s.cumulativeFee(n);
        assertLe(fee, s.maxFee());
    }
}
