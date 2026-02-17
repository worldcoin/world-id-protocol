// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {CredentialSchemaIssuerRegistry} from "../../src/core/CredentialSchemaIssuerRegistry.sol";
import {ICredentialSchemaIssuerRegistry} from "../../src/core/interfaces/ICredentialSchemaIssuerRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";

contract MockOprfKeyRegistry {
    function initKeyGen(uint160 oprfKeyId) external {}
}

/**
 * @title CredentialSchemaIssuerRegistryV2Mock
 * @notice Mock V2 implementation for testing upgrades
 */
contract CredentialSchemaIssuerRegistryV2Mock is CredentialSchemaIssuerRegistry {
    // Add a new state variable to test storage layout preservation
    uint256 public newFeature;

    function version() public pure returns (string memory) {
        return "V2";
    }

    function setNewFeature(uint256 _value) public {
        newFeature = _value;
    }
}

contract CredentialSchemaIssuerRegistryUpgradeTest is Test {
    CredentialSchemaIssuerRegistry public registry;
    ERC1967Proxy public proxy;
    address public owner;
    address public nonOwner;
    ERC20Mock public feeToken;
    address public feeRecipient;

    function setUp() public {
        owner = address(this);
        nonOwner = address(0xBEEF);
        feeRecipient = address(0x9999);

        // Deploy mock ERC20 token
        feeToken = new ERC20Mock();

        // Deploy implementation V1
        CredentialSchemaIssuerRegistry implementationV1 = new CredentialSchemaIssuerRegistry();

        // Deploy mock OPRF key registry
        address oprfKeyRegistry = address(new MockOprfKeyRegistry());

        // Deploy proxy with initialization
        bytes memory initData = abi.encodeWithSelector(
            CredentialSchemaIssuerRegistry.initialize.selector, feeRecipient, address(feeToken), 0, oprfKeyRegistry
        );
        proxy = new ERC1967Proxy(address(implementationV1), initData);

        registry = CredentialSchemaIssuerRegistry(address(proxy));
    }

    function test_UpgradeSuccess() public {
        // Register an issuer schema in V1
        uint64 issuerSchemaId = 1;
        ICredentialSchemaIssuerRegistry.Pubkey memory pubkey = ICredentialSchemaIssuerRegistry.Pubkey(1, 2);
        address signer = address(0x123);

        registry.register(issuerSchemaId, pubkey, signer);

        // Verify state before upgrade
        assertEq(registry.getSignerForIssuerSchemaId(issuerSchemaId), signer);
        ICredentialSchemaIssuerRegistry.Pubkey memory storedPubkey = registry.issuerSchemaIdToPubkey(issuerSchemaId);
        assertEq(storedPubkey.x, 1);
        assertEq(storedPubkey.y, 2);

        // Deploy V2 implementation
        CredentialSchemaIssuerRegistryV2Mock implementationV2 = new CredentialSchemaIssuerRegistryV2Mock();

        // Upgrade to V2 (as owner)
        CredentialSchemaIssuerRegistry(address(proxy)).upgradeToAndCall(address(implementationV2), "");

        // Wrap proxy with V2 interface
        CredentialSchemaIssuerRegistryV2Mock registryV2 = CredentialSchemaIssuerRegistryV2Mock(address(proxy));

        // Verify storage was preserved
        assertEq(registryV2.getSignerForIssuerSchemaId(issuerSchemaId), signer);
        ICredentialSchemaIssuerRegistry.Pubkey memory storedPubkeyV2 = registryV2.issuerSchemaIdToPubkey(issuerSchemaId);
        assertEq(storedPubkeyV2.x, 1);
        assertEq(storedPubkeyV2.y, 2);

        // Verify new functionality works
        assertEq(registryV2.version(), "V2");
        registryV2.setNewFeature(42);
        assertEq(registryV2.newFeature(), 42);

        // Verify old functionality still works
        uint64 newIssuerSchemaId = 2;
        ICredentialSchemaIssuerRegistry.Pubkey memory newPubkey = ICredentialSchemaIssuerRegistry.Pubkey(3, 4);
        address newSigner = address(0x456);
        registryV2.register(newIssuerSchemaId, newPubkey, newSigner);
        assertEq(registryV2.getSignerForIssuerSchemaId(newIssuerSchemaId), newSigner);
    }

    function test_UpgradeFailsForNonOwner() public {
        // Deploy V2 implementation
        CredentialSchemaIssuerRegistryV2Mock implementationV2 = new CredentialSchemaIssuerRegistryV2Mock();

        // Try to upgrade as non-owner (should fail)
        vm.prank(nonOwner);
        vm.expectRevert();
        CredentialSchemaIssuerRegistry(address(proxy)).upgradeToAndCall(address(implementationV2), "");
    }

    function test_OwnershipTransfer() public {
        address newOwner = address(0xABCDEF);

        // Transfer ownership (2-step process)
        registry.transferOwnership(newOwner);

        // Verify pending owner is set
        assertEq(registry.pendingOwner(), newOwner);

        // Accept ownership as new owner
        vm.prank(newOwner);
        registry.acceptOwnership();

        // Verify ownership transferred
        assertEq(registry.owner(), newOwner);

        // Deploy V2 implementation
        CredentialSchemaIssuerRegistryV2Mock implementationV2 = new CredentialSchemaIssuerRegistryV2Mock();

        // Old owner can no longer upgrade
        vm.expectRevert();
        CredentialSchemaIssuerRegistry(address(proxy)).upgradeToAndCall(address(implementationV2), "");

        // New owner can upgrade
        vm.prank(newOwner);
        CredentialSchemaIssuerRegistry(address(proxy)).upgradeToAndCall(address(implementationV2), "");

        // Verify upgrade succeeded
        CredentialSchemaIssuerRegistryV2Mock registryV2 = CredentialSchemaIssuerRegistryV2Mock(address(proxy));
        assertEq(registryV2.version(), "V2");
    }

    function test_CannotInitializeTwice() public {
        // Try to initialize again (should fail)
        address oprfKeyRegistry = address(new MockOprfKeyRegistry());
        vm.expectRevert();
        registry.initialize(feeRecipient, address(feeToken), 0, oprfKeyRegistry);
    }

    function test_ImplementationCannotBeInitialized() public {
        // Deploy a fresh implementation
        CredentialSchemaIssuerRegistry implementation = new CredentialSchemaIssuerRegistry();

        // Try to initialize the implementation directly (should fail)
        address oprfKeyRegistry = address(new MockOprfKeyRegistry());
        vm.expectRevert();
        implementation.initialize(feeRecipient, address(feeToken), 0, oprfKeyRegistry);
    }

    function test_OwnerCannotRegisterWithoutUpgrade() public {
        // Owner should not have any special privileges for register function
        // register() is open to everyone, no owner restriction
        uint64 issuerSchemaId = 1;
        ICredentialSchemaIssuerRegistry.Pubkey memory pubkey = ICredentialSchemaIssuerRegistry.Pubkey(1, 2);
        address signer = address(0x123);

        // This should succeed (register is public)
        registry.register(issuerSchemaId, pubkey, signer);
        assertEq(registry.getSignerForIssuerSchemaId(issuerSchemaId), signer);
    }
}
