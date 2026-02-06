// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {WorldIDVerifier} from "../src/WorldIDVerifier.sol";
import {IWorldIDVerifier} from "../src/interfaces/IWorldIDVerifier.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title VerifierV2Mock
 * @notice Mock V2 implementation for testing upgrades
 */
contract VerifierV2Mock is WorldIDVerifier {
    // Add a new state variable to test storage layout preservation
    uint256 public newFeature;

    function version() public pure returns (string memory) {
        return "V2";
    }

    function setNewFeature(uint256 _value) public {
        newFeature = _value;
    }
}

contract WorldIDRegistryMock {
    uint256 private treeDepth = 30;

    function getTreeDepth() external view returns (uint256) {
        return treeDepth;
    }
}

contract VerifierUpgradeTest is Test {
    WorldIDVerifier public verifier;
    ERC1967Proxy public proxy;
    address public owner;
    address public nonOwner;
    address public credentialIssuerRegistry;
    address public worldIDRegistry;
    address public oprfKeyRegistry;
    address public groth16Verifier;
    uint64 public minExpirationThreshold;

    function setUp() public {
        owner = address(this);
        nonOwner = address(0xBEEF);
        credentialIssuerRegistry = address(0x1111);
        worldIDRegistry = address(new WorldIDRegistryMock());
        oprfKeyRegistry = address(0x3333);
        groth16Verifier = address(0x4444);
        minExpirationThreshold = 5 hours;

        // Deploy implementation V1
        WorldIDVerifier implementationV1 = new WorldIDVerifier();

        // Deploy proxy with initialization
        bytes memory initData = abi.encodeWithSelector(
            WorldIDVerifier.initialize.selector,
            credentialIssuerRegistry,
            worldIDRegistry,
            oprfKeyRegistry,
            groth16Verifier,
            minExpirationThreshold
        );
        proxy = new ERC1967Proxy(address(implementationV1), initData);

        verifier = WorldIDVerifier(address(proxy));
    }

    function test_UpgradeSuccess() public {
        // Set OPRF key registry in V1
        verifier.updateOprfKeyRegistry(oprfKeyRegistry);

        // Verify state before upgrade
        assertEq(verifier.getCredentialSchemaIssuerRegistry(), credentialIssuerRegistry);
        assertEq(verifier.getWorldIDRegistry(), worldIDRegistry);
        assertEq(verifier.getOprfKeyRegistry(), oprfKeyRegistry);

        // Deploy V2 implementation
        VerifierV2Mock implementationV2 = new VerifierV2Mock();

        // Upgrade to V2 (as owner)
        WorldIDVerifier(address(proxy)).upgradeToAndCall(address(implementationV2), "");

        // Wrap proxy with V2 interface
        VerifierV2Mock verifierV2 = VerifierV2Mock(address(proxy));

        // Verify storage was preserved
        assertEq(verifierV2.getCredentialSchemaIssuerRegistry(), credentialIssuerRegistry);
        assertEq(verifierV2.getWorldIDRegistry(), worldIDRegistry);
        assertEq(verifierV2.getOprfKeyRegistry(), oprfKeyRegistry);

        // Verify new functionality works
        assertEq(verifierV2.version(), "V2");
        verifierV2.setNewFeature(42);
        assertEq(verifierV2.newFeature(), 42);

        // Verify old functionality still works
        address newOprfKeyRegistry = address(0x4444);
        verifierV2.updateOprfKeyRegistry(newOprfKeyRegistry);
        assertEq(verifierV2.getOprfKeyRegistry(), newOprfKeyRegistry);
    }

    function test_UpgradeFailsForNonOwner() public {
        // Deploy V2 implementation
        VerifierV2Mock implementationV2 = new VerifierV2Mock();

        // Try to upgrade as non-owner (should fail)
        vm.prank(nonOwner);
        vm.expectRevert();
        WorldIDVerifier(address(proxy)).upgradeToAndCall(address(implementationV2), "");
    }

    function test_OwnershipTransfer() public {
        address newOwner = address(0xABCDEF);

        // Transfer ownership (2-step process)
        verifier.transferOwnership(newOwner);

        // Verify pending owner is set
        assertEq(verifier.pendingOwner(), newOwner);

        // Accept ownership as new owner
        vm.prank(newOwner);
        verifier.acceptOwnership();

        // Verify ownership transferred
        assertEq(verifier.owner(), newOwner);

        // Deploy V2 implementation
        VerifierV2Mock implementationV2 = new VerifierV2Mock();

        // Old owner can no longer upgrade
        vm.expectRevert();
        WorldIDVerifier(address(proxy)).upgradeToAndCall(address(implementationV2), "");

        // New owner can upgrade
        vm.prank(newOwner);
        WorldIDVerifier(address(proxy)).upgradeToAndCall(address(implementationV2), "");

        // Verify upgrade succeeded
        VerifierV2Mock verifierV2 = VerifierV2Mock(address(proxy));
        assertEq(verifierV2.version(), "V2");
    }

    function test_CannotInitializeTwice() public {
        // Try to initialize again (should fail)
        vm.expectRevert();
        verifier.initialize(
            credentialIssuerRegistry, worldIDRegistry, oprfKeyRegistry, groth16Verifier, minExpirationThreshold
        );
    }

    function test_ImplementationCannotBeInitialized() public {
        // Deploy a fresh implementation
        WorldIDVerifier implementation = new WorldIDVerifier();

        // Try to initialize the implementation directly (should fail)
        vm.expectRevert();
        implementation.initialize(
            credentialIssuerRegistry, worldIDRegistry, oprfKeyRegistry, groth16Verifier, minExpirationThreshold
        );
    }

    function test_UpdateCredentialSchemaIssuerRegistry() public {
        address newRegistry = address(0x5555);

        vm.expectEmit(true, true, true, true);
        emit IWorldIDVerifier.CredentialSchemaIssuerRegistryUpdated(credentialIssuerRegistry, newRegistry);

        verifier.updateCredentialSchemaIssuerRegistry(newRegistry);
        assertEq(verifier.getCredentialSchemaIssuerRegistry(), newRegistry);
    }

    function test_UpdateWorldIDRegistry() public {
        address newRegistry = address(new WorldIDRegistryMock());

        vm.expectEmit(true, true, true, true);
        emit IWorldIDVerifier.WorldIDRegistryUpdated(worldIDRegistry, newRegistry);

        verifier.updateWorldIDRegistry(newRegistry);
        assertEq(verifier.getWorldIDRegistry(), newRegistry);
    }

    function test_UpdateOprfKeyRegistry() public {
        address newOprfKeyRegistry = address(0x7777);

        vm.expectEmit(true, true, true, true);
        emit IWorldIDVerifier.OprfKeyRegistryUpdated(oprfKeyRegistry, newOprfKeyRegistry);

        verifier.updateOprfKeyRegistry(newOprfKeyRegistry);
        assertEq(verifier.getOprfKeyRegistry(), newOprfKeyRegistry);
    }

    function test_OnlyOwnerCanUpdate() public {
        address newRegistry = address(0x8888);

        vm.startPrank(nonOwner);

        vm.expectRevert();
        verifier.updateCredentialSchemaIssuerRegistry(newRegistry);

        vm.expectRevert();
        verifier.updateWorldIDRegistry(newRegistry);

        vm.expectRevert();
        verifier.updateOprfKeyRegistry(newRegistry);

        vm.stopPrank();
    }
}
