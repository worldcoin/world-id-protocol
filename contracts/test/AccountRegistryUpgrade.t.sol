// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {AccountRegistry} from "../src/AccountRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title AccountRegistryV2Mock
 * @notice Mock V2 implementation for testing upgrades
 */
contract AccountRegistryV2Mock is AccountRegistry {
    // Add a new state variable to test storage layout preservation
    uint256 public newFeature;

    function version() public pure returns (string memory) {
        return "V2";
    }

    function setNewFeature(uint256 _value) public {
        newFeature = _value;
    }
}

contract AccountRegistryUpgradeTest is Test {
    AccountRegistry public accountRegistry;
    ERC1967Proxy public proxy;
    address public owner;
    address public nonOwner;

    function setUp() public {
        owner = address(this);
        nonOwner = address(0xBEEF);

        // Deploy implementation V1
        AccountRegistry implementationV1 = new AccountRegistry();

        // Deploy proxy with initialization
        bytes memory initData = abi.encodeWithSelector(AccountRegistry.initialize.selector, 30);
        proxy = new ERC1967Proxy(address(implementationV1), initData);

        accountRegistry = AccountRegistry(address(proxy));
    }

    function test_UpgradeSuccess() public {
        // Create an account in V1
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = address(0x123);
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        uint256 commitment = 0x1234567890;

        accountRegistry.createAccount(address(0xABCD), authenticatorAddresses, authenticatorPubkeys, commitment);

        // Verify state before upgrade
        assertEq(accountRegistry.nextAccountIndex(), 2);
        uint256 rootBefore = accountRegistry.currentRoot();

        // Deploy V2 implementation
        AccountRegistryV2Mock implementationV2 = new AccountRegistryV2Mock();

        // Upgrade to V2 (as owner)
        AccountRegistry(address(proxy)).upgradeToAndCall(address(implementationV2), "");

        // Wrap proxy with V2 interface
        AccountRegistryV2Mock accountRegistryV2 = AccountRegistryV2Mock(address(proxy));

        // Verify storage was preserved
        assertEq(accountRegistryV2.nextAccountIndex(), 2);
        assertEq(accountRegistryV2.currentRoot(), rootBefore);

        // Verify new functionality works
        assertEq(accountRegistryV2.version(), "V2");
        accountRegistryV2.setNewFeature(42);
        assertEq(accountRegistryV2.newFeature(), 42);

        // Verify old functionality still works
        address[] memory newAuthAddresses = new address[](1);
        newAuthAddresses[0] = address(0x456);
        uint256[] memory newAuthPubkeys = new uint256[](1);
        newAuthPubkeys[0] = 0;
        accountRegistryV2.createAccount(address(0xDEF), newAuthAddresses, newAuthPubkeys, 0x9876543210);
        assertEq(accountRegistryV2.nextAccountIndex(), 3);
    }

    function test_UpgradeFailsForNonOwner() public {
        // Deploy V2 implementation
        AccountRegistryV2Mock implementationV2 = new AccountRegistryV2Mock();

        // Try to upgrade as non-owner (should fail)
        vm.prank(nonOwner);
        vm.expectRevert();
        AccountRegistry(address(proxy)).upgradeToAndCall(address(implementationV2), "");
    }

    function test_OwnershipTransfer() public {
        address newOwner = address(0xABCDEF);

        // Transfer ownership (2-step process)
        accountRegistry.transferOwnership(newOwner);

        // Verify pending owner is set
        assertEq(accountRegistry.pendingOwner(), newOwner);

        // Accept ownership as new owner
        vm.prank(newOwner);
        accountRegistry.acceptOwnership();

        // Verify ownership transferred
        assertEq(accountRegistry.owner(), newOwner);

        // Deploy V2 implementation
        AccountRegistryV2Mock implementationV2 = new AccountRegistryV2Mock();

        // Old owner can no longer upgrade
        vm.expectRevert();
        AccountRegistry(address(proxy)).upgradeToAndCall(address(implementationV2), "");

        // New owner can upgrade
        vm.prank(newOwner);
        AccountRegistry(address(proxy)).upgradeToAndCall(address(implementationV2), "");

        // Verify upgrade succeeded
        AccountRegistryV2Mock accountRegistryV2 = AccountRegistryV2Mock(address(proxy));
        assertEq(accountRegistryV2.version(), "V2");
    }

    function test_CannotInitializeTwice() public {
        // Try to initialize again (should fail)
        vm.expectRevert();
        accountRegistry.initialize(30);
    }

    function test_ImplementationCannotBeInitialized() public {
        // Deploy a fresh implementation
        AccountRegistry implementation = new AccountRegistry();

        // Try to initialize the implementation directly (should fail)
        vm.expectRevert();
        implementation.initialize(30);
    }
}
