// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {RpRegistry} from "../../src/core/RpRegistry.sol";
import {RpRegistryV2} from "../../src/core/RpRegistryV2.sol";
import {IRpRegistry} from "../../src/core/interfaces/IRpRegistry.sol";
import {IRpRegistryV2} from "../../src/core/interfaces/IRpRegistryV2.sol";

contract OprfKeyRegistryV2Mock {
    error AlreadySubmitted();

    mapping(uint160 => bool) public registeredKeys;

    function initKeyGen(uint160 oprfKeyId) external {
        if (registeredKeys[oprfKeyId]) revert AlreadySubmitted();
        registeredKeys[oprfKeyId] = true;
    }
}

contract RpRegistryV2Test is Test {
    uint64 private constant LEGACY_RP_ID = 42;

    RpRegistryV2 private registry;
    ERC20Mock private feeToken;
    OprfKeyRegistryV2Mock private oprfKeyRegistry;

    address private registrar;
    address private secondRegistrar;
    address private attacker;
    address private manager;
    address private signer;

    function setUp() public {
        registrar = makeAddr("registrar");
        secondRegistrar = makeAddr("secondRegistrar");
        attacker = makeAddr("attacker");
        manager = makeAddr("manager");
        signer = makeAddr("signer");

        feeToken = new ERC20Mock();
        oprfKeyRegistry = new OprfKeyRegistryV2Mock();

        RpRegistry implementationV1 = new RpRegistry();
        bytes memory initData = abi.encodeWithSelector(
            RpRegistry.initialize.selector, address(0), address(feeToken), 0, address(oprfKeyRegistry)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementationV1), initData);
        RpRegistry registryV1 = RpRegistry(address(proxy));

        // Preserve a V1 registration across the upgrade.
        vm.prank(attacker);
        registryV1.register(LEGACY_RP_ID, manager, signer, "legacy.example.org");

        RpRegistryV2 implementationV2 = new RpRegistryV2();
        registryV1.upgradeToAndCall(address(implementationV2), abi.encodeCall(RpRegistryV2.initializeV2, (registrar)));
        registry = RpRegistryV2(address(proxy));
    }

    function testUpgradePreservesExistingRegistration() public view {
        IRpRegistry.RelyingParty memory rp = registry.getRpUnchecked(LEGACY_RP_ID);

        assertTrue(rp.initialized);
        assertTrue(rp.active);
        assertEq(rp.manager, manager);
        assertEq(rp.signer, signer);
        assertEq(rp.unverifiedWellKnownDomain, "legacy.example.org");
        assertTrue(registry.isRegistrar(registrar));
    }

    function testUnauthorizedAccountCannotRegister() public {
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IRpRegistryV2.UnauthorizedRegistrar.selector, attacker));
        registry.register(1, manager, signer, "example.org");
    }

    function testAuthorizedRegistrarCanRegister() public {
        vm.prank(registrar);
        registry.register(1, manager, signer, "example.org");

        IRpRegistry.RelyingParty memory rp = registry.getRpUnchecked(1);
        assertEq(rp.manager, manager);
        assertEq(rp.signer, signer);
    }

    function testUnauthorizedAccountCannotRegisterMany() public {
        uint64[] memory rpIds = new uint64[](1);
        rpIds[0] = 1;
        address[] memory managers = new address[](1);
        managers[0] = manager;
        address[] memory signers = new address[](1);
        signers[0] = signer;
        string[] memory domains = new string[](1);
        domains[0] = "example.org";

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IRpRegistryV2.UnauthorizedRegistrar.selector, attacker));
        registry.registerMany(rpIds, managers, signers, domains);
    }

    function testOwnerCanAuthorizeAndRevokeRegistrar() public {
        vm.expectEmit(true, false, false, true);
        emit IRpRegistryV2.RegistrarAuthorizationUpdated(secondRegistrar, true);
        registry.setRegistrar(secondRegistrar, true);
        assertTrue(registry.isRegistrar(secondRegistrar));

        registry.setRegistrar(secondRegistrar, false);
        assertFalse(registry.isRegistrar(secondRegistrar));

        vm.prank(secondRegistrar);
        vm.expectRevert(abi.encodeWithSelector(IRpRegistryV2.UnauthorizedRegistrar.selector, secondRegistrar));
        registry.register(1, manager, signer, "example.org");
    }

    function testNonOwnerCannotAuthorizeRegistrar() public {
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, attacker));
        registry.setRegistrar(secondRegistrar, true);
    }

    function testCannotAuthorizeZeroAddressRegistrar() public {
        vm.expectRevert(IRpRegistryV2.RegistrarCannotBeZeroAddress.selector);
        registry.setRegistrar(address(0), true);
    }

    function testOwnerCanRecoverRp() public {
        address recoveredManager = makeAddr("recoveredManager");
        address recoveredSigner = makeAddr("recoveredSigner");

        vm.expectEmit(true, true, false, true);
        emit IRpRegistryV2.RpRecovered(LEGACY_RP_ID, manager, recoveredManager, recoveredSigner);
        registry.recoverRp(LEGACY_RP_ID, recoveredManager, recoveredSigner, "recovered.example.org");

        IRpRegistry.RelyingParty memory rp = registry.getRpUnchecked(LEGACY_RP_ID);
        assertTrue(rp.active);
        assertEq(rp.manager, recoveredManager);
        assertEq(rp.signer, recoveredSigner);
        assertEq(rp.unverifiedWellKnownDomain, "recovered.example.org");
        assertEq(registry.nonceOf(LEGACY_RP_ID), 1);
    }

    function testNonOwnerCannotRecoverRp() public {
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, attacker));
        registry.recoverRp(LEGACY_RP_ID, attacker, attacker, "attacker.example.org");
    }

    function testCannotRecoverMissingRp() public {
        vm.expectRevert(IRpRegistry.RpIdDoesNotExist.selector);
        registry.recoverRp(999, manager, signer, "example.org");
    }

    function testCannotRecoverWithZeroAddressManager() public {
        vm.expectRevert(IRpRegistry.ManagerCannotBeZeroAddress.selector);
        registry.recoverRp(LEGACY_RP_ID, address(0), signer, "example.org");
    }

    function testCannotRecoverWithZeroAddressSigner() public {
        vm.expectRevert(IRpRegistry.SignerCannotBeZeroAddress.selector);
        registry.recoverRp(LEGACY_RP_ID, manager, address(0), "example.org");
    }
}
