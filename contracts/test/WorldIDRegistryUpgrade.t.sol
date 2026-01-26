// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {WorldIDRegistry} from "../src/WorldIDRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";

/**
 * @title WorldIDRegistryV2Mock
 * @notice Mock V2 implementation for testing upgrades
 */
contract WorldIDRegistryV2Mock is WorldIDRegistry {
    // Add a new state variable to test storage layout preservation
    uint256 public newFeature;

    function version() public pure returns (string memory) {
        return "V2";
    }

    function setNewFeature(uint256 _value) public {
        newFeature = _value;
    }
}

contract WorldIDRegistryUpgradeTest is Test {
    WorldIDRegistry public worldIDRegistry;
    ERC1967Proxy public proxy;
    address public owner;
    address public nonOwner;

    function setUp() public {
        owner = address(this);
        nonOwner = address(0xBEEF);

        // Deploy implementation V1
        WorldIDRegistry implementationV1 = new WorldIDRegistry();

        // Deploy proxy with initialization (no fees)
        ERC20Mock feeToken = new ERC20Mock();
        bytes memory initData =
            abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30, address(0xAAA), feeToken, 0);
        proxy = new ERC1967Proxy(address(implementationV1), initData);

        worldIDRegistry = WorldIDRegistry(address(proxy));
    }

    function test_UpgradeSuccess() public {
        // Create an account in V1
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = address(0x123);
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        uint256 commitment = 0x1234567890;

        worldIDRegistry.createAccount(address(0xABCD), authenticatorAddresses, authenticatorPubkeys, commitment);

        // Verify state before upgrade
        assertEq(worldIDRegistry.getNextLeafIndex(), 2);
        uint256 rootBefore = worldIDRegistry.currentRoot();

        // Deploy V2 implementation
        WorldIDRegistryV2Mock implementationV2 = new WorldIDRegistryV2Mock();

        // Upgrade to V2 (as owner)
        WorldIDRegistry(address(proxy)).upgradeToAndCall(address(implementationV2), "");

        // Wrap proxy with V2 interface
        WorldIDRegistryV2Mock worldIDRegistryV2 = WorldIDRegistryV2Mock(address(proxy));

        // Verify storage was preserved
        assertEq(worldIDRegistryV2.getNextLeafIndex(), 2);
        assertEq(worldIDRegistryV2.currentRoot(), rootBefore);

        // Verify new functionality works
        assertEq(worldIDRegistryV2.version(), "V2");
        worldIDRegistryV2.setNewFeature(42);
        assertEq(worldIDRegistryV2.newFeature(), 42);

        // Verify old functionality still works
        address[] memory newAuthAddresses = new address[](1);
        newAuthAddresses[0] = address(0x456);
        uint256[] memory newAuthPubkeys = new uint256[](1);
        newAuthPubkeys[0] = 0;
        worldIDRegistryV2.createAccount(address(0xDEF), newAuthAddresses, newAuthPubkeys, 0x9876543210);
        assertEq(worldIDRegistryV2.getNextLeafIndex(), 3);
    }

    function test_UpgradeFailsForNonOwner() public {
        // Deploy V2 implementation
        WorldIDRegistryV2Mock implementationV2 = new WorldIDRegistryV2Mock();

        // Try to upgrade as non-owner (should fail)
        vm.prank(nonOwner);
        vm.expectRevert();
        WorldIDRegistry(address(proxy)).upgradeToAndCall(address(implementationV2), "");
    }

    function test_OwnershipTransfer() public {
        address newOwner = address(0xABCDEF);

        // Transfer ownership (2-step process)
        worldIDRegistry.transferOwnership(newOwner);

        // Verify pending owner is set
        assertEq(worldIDRegistry.pendingOwner(), newOwner);

        // Accept ownership as new owner
        vm.prank(newOwner);
        worldIDRegistry.acceptOwnership();

        // Verify ownership transferred
        assertEq(worldIDRegistry.owner(), newOwner);

        // Deploy V2 implementation
        WorldIDRegistryV2Mock implementationV2 = new WorldIDRegistryV2Mock();

        // Old owner can no longer upgrade
        vm.expectRevert();
        WorldIDRegistry(address(proxy)).upgradeToAndCall(address(implementationV2), "");

        // New owner can upgrade
        vm.prank(newOwner);
        WorldIDRegistry(address(proxy)).upgradeToAndCall(address(implementationV2), "");

        // Verify upgrade succeeded
        WorldIDRegistryV2Mock worldIDRegistryV2 = WorldIDRegistryV2Mock(address(proxy));
        assertEq(worldIDRegistryV2.version(), "V2");
    }

    function test_CannotInitializeTwice() public {
        // Try to initialize again (should fail)
        vm.expectRevert();
        worldIDRegistry.initialize(30, address(0), address(0), 0);
    }

    function test_ImplementationCannotBeInitialized() public {
        // Deploy a fresh implementation
        WorldIDRegistry implementation = new WorldIDRegistry();

        // Try to initialize the implementation directly (should fail)
        vm.expectRevert();
        implementation.initialize(30, address(0), address(0), 0);
    }
}
