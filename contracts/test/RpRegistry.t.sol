// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {RpRegistry} from "../src/RpRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract RpRegistryTest is Test {
    RpRegistry private registry;
    address private owner;
    address private manager1;
    address private signer1;
    address private manager2;
    address private signer2;

    function setUp() public {
        owner = address(this);
        manager1 = vm.addr(0x1111);
        signer1 = vm.addr(0x2222);
        manager2 = vm.addr(0x3333);
        signer2 = vm.addr(0x4444);

        // Deploy implementation
        RpRegistry implementation = new RpRegistry();

        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(RpRegistry.initialize.selector);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);

        registry = RpRegistry(address(proxy));
    }

    function testInitialized() public view {
        // Should not revert when calling a function that requires initialization
        registry.domainSeparatorV4();
    }

    function testRegister() public {
        uint64 rpId = 12345;
        string memory wellKnownDomain = "example.world.org";

        vm.expectEmit(true, true, false, true);
        emit RpRegistry.RpRegistered(rpId, 0, manager1, wellKnownDomain);

        registry.register(rpId, manager1, signer1, wellKnownDomain);
    }

    function testRegisterMultipleRps() public {
        uint64 rpId1 = 1;
        uint64 rpId2 = 2;
        string memory domain1 = "app1.world.org";
        string memory domain2 = "app2.world.org";

        registry.register(rpId1, manager1, signer1, domain1);
        registry.register(rpId2, manager2, signer2, domain2);
    }

    function testCannotRegisterDuplicateRpId() public {
        uint64 rpId = 12345;
        string memory wellKnownDomain = "example.world.org";

        registry.register(rpId, manager1, signer1, wellKnownDomain);

        vm.expectRevert(abi.encodeWithSelector(RpRegistry.RpIdAlreadyInUse.selector, rpId));
        registry.register(rpId, manager2, signer2, wellKnownDomain);
    }

    function testCannotRegisterWithZeroAddressManager() public {
        uint64 rpId = 12345;
        string memory wellKnownDomain = "example.world.org";

        vm.expectRevert(abi.encodeWithSelector(RpRegistry.ManagerCannotBeZeroAddress.selector));
        registry.register(rpId, address(0), signer1, wellKnownDomain);
    }

    function testCannotRegisterWithZeroAddressSigner() public {
        uint64 rpId = 12345;
        string memory wellKnownDomain = "example.world.org";

        vm.expectRevert(abi.encodeWithSelector(RpRegistry.SignerCannotBeZeroAddress.selector));
        registry.register(rpId, manager1, address(0), wellKnownDomain);
    }

    function testCannotRegisterManyWithMismatchedArrayLengths() public {
        uint64[] memory rpIds = new uint64[](2);
        rpIds[0] = 1;
        rpIds[1] = 2;

        address[] memory managers = new address[](2);
        managers[0] = manager1;
        managers[1] = manager2;

        address[] memory signers = new address[](2);
        signers[0] = signer1;
        signers[1] = signer2;

        string[] memory domains = new string[](1); // Wrong length
        domains[0] = "app1.world.org";

        vm.expectRevert(abi.encodeWithSelector(RpRegistry.MismatchingArrayLengths.selector));
        registry.registerMany(rpIds, managers, signers, domains);
    }

    function testCannotRegisterManyWithMismatchedManagersLength() public {
        uint64[] memory rpIds = new uint64[](2);
        rpIds[0] = 1;
        rpIds[1] = 2;

        address[] memory managers = new address[](1); // Wrong length
        managers[0] = manager1;

        address[] memory signers = new address[](2);
        signers[0] = signer1;
        signers[1] = signer2;

        string[] memory domains = new string[](2);
        domains[0] = "app1.world.org";
        domains[1] = "app2.world.org";

        vm.expectRevert(abi.encodeWithSelector(RpRegistry.MismatchingArrayLengths.selector));
        registry.registerMany(rpIds, managers, signers, domains);
    }

    function testCannotRegisterManyWithMismatchedSignersLength() public {
        uint64[] memory rpIds = new uint64[](2);
        rpIds[0] = 1;
        rpIds[1] = 2;

        address[] memory managers = new address[](2);
        managers[0] = manager1;
        managers[1] = manager2;

        address[] memory signers = new address[](1); // Wrong length
        signers[0] = signer1;

        string[] memory domains = new string[](2);
        domains[0] = "app1.world.org";
        domains[1] = "app2.world.org";

        vm.expectRevert(abi.encodeWithSelector(RpRegistry.MismatchingArrayLengths.selector));
        registry.registerMany(rpIds, managers, signers, domains);
    }

    function testRegisterManyValidatesEachRegistration() public {
        uint64[] memory rpIds = new uint64[](2);
        rpIds[0] = 1;
        rpIds[1] = 1; // Duplicate rpId

        address[] memory managers = new address[](2);
        managers[0] = manager1;
        managers[1] = manager2;

        address[] memory signers = new address[](2);
        signers[0] = signer1;
        signers[1] = signer2;

        string[] memory domains = new string[](2);
        domains[0] = "app1.world.org";
        domains[1] = "app2.world.org";

        vm.expectRevert(abi.encodeWithSelector(RpRegistry.RpIdAlreadyInUse.selector, 1));
        registry.registerMany(rpIds, managers, signers, domains);
    }

    function testRegisterManyValidatesManagerNotZero() public {
        uint64[] memory rpIds = new uint64[](2);
        rpIds[0] = 1;
        rpIds[1] = 2;

        address[] memory managers = new address[](2);
        managers[0] = manager1;
        managers[1] = address(0); // Invalid manager

        address[] memory signers = new address[](2);
        signers[0] = signer1;
        signers[1] = signer2;

        string[] memory domains = new string[](2);
        domains[0] = "app1.world.org";
        domains[1] = "app2.world.org";

        vm.expectRevert(abi.encodeWithSelector(RpRegistry.ManagerCannotBeZeroAddress.selector));
        registry.registerMany(rpIds, managers, signers, domains);
    }

    function testRegisterManyValidatesSignerNotZero() public {
        uint64[] memory rpIds = new uint64[](2);
        rpIds[0] = 1;
        rpIds[1] = 2;

        address[] memory managers = new address[](2);
        managers[0] = manager1;
        managers[1] = manager2;

        address[] memory signers = new address[](2);
        signers[0] = signer1;
        signers[1] = address(0); // Invalid signer

        string[] memory domains = new string[](2);
        domains[0] = "app1.world.org";
        domains[1] = "app2.world.org";

        vm.expectRevert(abi.encodeWithSelector(RpRegistry.SignerCannotBeZeroAddress.selector));
        registry.registerMany(rpIds, managers, signers, domains);
    }

    function testOnlyOwnerCanRegister() public {
        uint64 rpId = 12345;
        string memory wellKnownDomain = "example.world.org";

        vm.prank(manager1);
        vm.expectRevert();
        registry.register(rpId, manager1, signer1, wellKnownDomain);
    }

    function testOnlyOwnerCanRegisterMany() public {
        uint64[] memory rpIds = new uint64[](1);
        rpIds[0] = 1;

        address[] memory managers = new address[](1);
        managers[0] = manager1;

        address[] memory signers = new address[](1);
        signers[0] = signer1;

        string[] memory domains = new string[](1);
        domains[0] = "app1.world.org";

        vm.prank(manager1);
        vm.expectRevert();
        registry.registerMany(rpIds, managers, signers, domains);
    }
}
