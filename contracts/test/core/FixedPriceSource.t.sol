// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {FixedPriceSource} from "../../src/core/FixedPriceSource.sol";

contract FixedPriceSourceTest is Test {
    FixedPriceSource source;
    address owner = makeAddr("owner");

    function setUp() public {
        vm.warp(1_790_000_000);
        source = new FixedPriceSource(owner);
    }

    function test_Decimals() public view {
        assertEq(source.decimals(), 18);
    }

    function test_LatestRoundData_RevertsUntilSet() public {
        vm.expectRevert(FixedPriceSource.PriceNotSet.selector);
        source.latestRoundData();
    }

    function test_SetPrice_EmitsOldAndNewRate() public {
        vm.expectEmit(address(source));
        emit FixedPriceSource.PriceUpdated(0, 2e18);
        vm.prank(owner);
        source.setPrice(2e18);

        vm.expectEmit(address(source));
        emit FixedPriceSource.PriceUpdated(2e18, 3e18);
        vm.prank(owner);
        source.setPrice(3e18);

        (, int256 answer,,,) = source.latestRoundData();
        assertEq(answer, 3e18);
    }

    /// @dev The rate is reported as observed now at every read, however long ago it was set.
    function testFuzz_LatestRoundData_NeverStale(uint32 elapsed) public {
        vm.prank(owner);
        source.setPrice(2e18);

        uint256 readAt = vm.getBlockTimestamp() + elapsed;
        vm.warp(readAt);
        (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound) =
            source.latestRoundData();
        assertEq(roundId, 1);
        assertEq(answer, 2e18);
        assertEq(startedAt, readAt);
        assertEq(updatedAt, readAt);
        assertEq(answeredInRound, 1);
    }

    function test_SetPrice_RejectsInvalidPrice() public {
        vm.startPrank(owner);
        vm.expectRevert(FixedPriceSource.InvalidPrice.selector);
        source.setPrice(0);
        vm.expectRevert(FixedPriceSource.InvalidPrice.selector);
        source.setPrice(uint256(type(int256).max) + 1);
        source.setPrice(uint256(type(int256).max));
        vm.stopPrank();
    }

    function testFuzz_SetPrice_OnlyOwner(address caller) public {
        vm.assume(caller != owner);
        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, caller));
        source.setPrice(2e18);
    }

    function test_Ownership_TwoStep() public {
        address newOwner = makeAddr("newOwner");
        vm.prank(owner);
        source.transferOwnership(newOwner);
        assertEq(source.owner(), owner);

        vm.prank(newOwner);
        source.acceptOwnership();
        assertEq(source.owner(), newOwner);

        vm.prank(newOwner);
        source.setPrice(2e18);
    }
}
