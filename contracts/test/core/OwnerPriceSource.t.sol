// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {OwnerPriceSource} from "../../src/core/OwnerPriceSource.sol";

contract OwnerPriceSourceTest is Test {
    OwnerPriceSource source;
    address owner = makeAddr("owner");

    function setUp() public {
        vm.warp(1_790_000_000);
        source = new OwnerPriceSource(owner);
    }

    function test_Decimals() public view {
        assertEq(source.decimals(), 18);
    }

    function test_LatestRoundData_RevertsUntilSet() public {
        vm.expectRevert(OwnerPriceSource.PriceNotSet.selector);
        source.latestRoundData();
    }

    function test_SetPrice_RecordsRateAndTime() public {
        uint256 setAt = vm.getBlockTimestamp();
        vm.expectEmit(address(source));
        emit OwnerPriceSource.PriceUpdated(1, 2e18, setAt);
        vm.prank(owner);
        source.setPrice(2e18);

        (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound) =
            source.latestRoundData();
        assertEq(roundId, 1);
        assertEq(answer, 2e18);
        assertEq(startedAt, setAt);
        assertEq(updatedAt, setAt);
        assertEq(answeredInRound, 1);

        vm.warp(setAt + 1 hours);
        (,,, updatedAt,) = source.latestRoundData();
        assertEq(updatedAt, setAt);

        vm.prank(owner);
        source.setPrice(3e18);
        (roundId, answer,, updatedAt,) = source.latestRoundData();
        assertEq(roundId, 2);
        assertEq(answer, 3e18);
        assertEq(updatedAt, setAt + 1 hours);
    }

    function test_SetPrice_RejectsInvalidPrice() public {
        vm.startPrank(owner);
        vm.expectRevert(OwnerPriceSource.InvalidPrice.selector);
        source.setPrice(0);
        vm.expectRevert(OwnerPriceSource.InvalidPrice.selector);
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
