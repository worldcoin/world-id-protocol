// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {RpRegistry} from "../src/RpRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MockERC1271Wallet} from "./Mock1271Wallet.t.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";

contract OprfKeyRegistryMock {
    function initKeyGen(uint160 oprfKeyId) external {}
}

contract RpRegistryTest is Test {
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    RpRegistry private registry;
    ERC20Mock private feeToken;
    OprfKeyRegistryMock private oprfKeyRegistry;
    address private owner;
    address private feeRecipient;
    address private manager1;
    uint256 private manager1Pk;
    address private signer1;
    address private manager2;
    uint256 private manager2Pk;
    address private signer2;

    function setUp() public {
        owner = address(this);
        feeRecipient = vm.addr(0x9999);
        manager1Pk = 0x1111;
        manager1 = vm.addr(manager1Pk);
        signer1 = vm.addr(0x2222);
        manager2Pk = 0x3333;
        manager2 = vm.addr(manager2Pk);
        signer2 = vm.addr(0x4444);

        // Deploy mock ERC20 token
        feeToken = new ERC20Mock();

        // Deploy OprfKeyRegistry
        oprfKeyRegistry = new OprfKeyRegistryMock();

        // Deploy implementation
        RpRegistry implementation = new RpRegistry();

        // Deploy proxy with fee recipient, fee token, and zero fee
        bytes memory initData =
            abi.encodeWithSelector(RpRegistry.initialize.selector, feeRecipient, address(feeToken), 0, oprfKeyRegistry);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);

        registry = RpRegistry(address(proxy));
    }

    function testInitialized() public view {
        // Should not revert when calling a function that requires initialization
        registry.domainSeparatorV4();
    }

    function testRegister() public {
        uint64 rpId = 12345;
        uint160 oprfKeyId = uint160(rpId);
        string memory wellKnownDomain = "example.world.org";

        vm.expectEmit(true, true, false, true);
        emit RpRegistry.RpRegistered(rpId, oprfKeyId, manager1, wellKnownDomain);

        registry.register(rpId, manager1, signer1, wellKnownDomain);
    }

    function testRegisterMultipleRps() public {
        uint64 rpId1 = 1;
        uint64 rpId2 = 2;
        string memory domain1 = "app1.world.org";
        string memory domain2 = "app2.world.org";

        vm.prank(manager1); // anyone can call it

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

    function testRegisterMany() public {
        uint64[] memory rpIds = new uint64[](3);
        rpIds[0] = 1;
        rpIds[1] = 2;
        rpIds[2] = 3;

        address[] memory managers = new address[](3);
        managers[0] = manager1;
        managers[1] = manager2;
        managers[2] = vm.addr(0x5555);

        address[] memory signers = new address[](3);
        signers[0] = signer1;
        signers[1] = signer2;
        signers[2] = vm.addr(0x6666);

        string[] memory domains = new string[](3);
        domains[0] = "app1.world.org";
        domains[1] = "app2.world.org";
        domains[2] = "app3.world.org";

        vm.prank(manager1); // anyone can call it

        registry.registerMany(rpIds, managers, signers, domains);
    }

    function testRegisterManyWithEmptyArrays() public {
        uint64[] memory rpIds = new uint64[](0);
        address[] memory managers = new address[](0);
        address[] memory signers = new address[](0);
        string[] memory domains = new string[](0);

        // Should succeed with empty arrays
        registry.registerMany(rpIds, managers, signers, domains);
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

    // Helper functions for updateRp tests
    function _domainSeparator() internal view returns (bytes32) {
        bytes32 nameHash = keccak256(bytes(registry.EIP712_NAME()));
        bytes32 versionHash = keccak256(bytes(registry.EIP712_VERSION()));
        return keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, nameHash, versionHash, block.chainid, address(registry)));
    }

    function _signUpdateRp(
        uint256 pk,
        uint64 rpId,
        uint160 oprfKeyId,
        address manager,
        address signer,
        bool toggleActive,
        string memory unverifiedWellKnownDomain,
        uint256 nonce
    ) internal view returns (bytes memory) {
        // NOTE: The contract encodes the string directly, not its hash
        // This is technically not compliant with EIP-712 spec for dynamic types
        bytes32 structHash = keccak256(
            abi.encode(
                registry.UPDATE_RP_TYPEHASH(),
                rpId,
                oprfKeyId,
                manager,
                signer,
                toggleActive,
                keccak256(bytes(unverifiedWellKnownDomain)),
                nonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    // UpdateRp Tests

    function testUpdateRpSuccess() public {
        uint64 rpId = 1;
        uint160 oprfKeyId = uint160(rpId);
        string memory initialDomain = "app1.world.org";

        // Register an RP
        registry.register(rpId, manager1, signer1, initialDomain);

        // Update all fields
        uint160 newOprfKeyId = 2;
        address newManager = vm.addr(0x5555);
        address newSigner = vm.addr(0x6666);
        string memory newDomain = "app1-updated.world.org";

        bytes memory sig = _signUpdateRp(manager1Pk, rpId, newOprfKeyId, newManager, newSigner, false, newDomain, 0);

        vm.expectEmit(true, true, false, true);
        emit RpRegistry.RpUpdated(rpId, newOprfKeyId, true, newManager, newSigner, newDomain);
        registry.updateRp(rpId, newOprfKeyId, newManager, newSigner, false, newDomain, 0, sig);

        // Verify updates
        RpRegistry.RelyingParty memory rp = registry.getRp(rpId);
        assertEq(rp.oprfKeyId, newOprfKeyId);
        assertEq(rp.manager, newManager);
        assertEq(rp.signer, newSigner);
        assertEq(rp.unverifiedWellKnownDomain, newDomain);
        assertTrue(rp.active);
        assertEq(registry.nonceOf(rpId), 1);
    }

    function testUpdateRpPartialUpdate() public {
        uint64 rpId = 1;
        uint160 oprfKeyId = uint160(rpId);
        string memory initialDomain = "app1.world.org";

        // Register an RP
        registry.register(rpId, manager1, signer1, initialDomain);

        // Update only signer (manager = 0, domain = NO_UPDATE)
        address newSigner = vm.addr(0x6666);
        string memory noUpdate = registry.NO_UPDATE();

        bytes memory sig = _signUpdateRp(manager1Pk, rpId, 0, address(0), newSigner, false, noUpdate, 0);

        registry.updateRp(rpId, 0, address(0), newSigner, false, noUpdate, 0, sig);

        // Verify only signer changed
        RpRegistry.RelyingParty memory rp = registry.getRp(rpId);
        assertEq(rp.oprfKeyId, oprfKeyId); // Unchanged
        assertEq(rp.manager, manager1); // Unchanged
        assertEq(rp.signer, newSigner); // Changed
        assertEq(rp.unverifiedWellKnownDomain, initialDomain); // Unchanged
        assertTrue(rp.active);
    }

    function testUpdateRpToggleActive() public {
        uint64 rpId = 1;
        string memory initialDomain = "app1.world.org";

        // Register an RP (starts active)
        registry.register(rpId, manager1, signer1, initialDomain);
        assertTrue(registry.getRp(rpId).active);

        string memory noUpdate = registry.NO_UPDATE();

        // Toggle to inactive
        bytes memory sig = _signUpdateRp(manager1Pk, rpId, 0, address(0), address(0), true, noUpdate, 0);
        registry.updateRp(rpId, 0, address(0), address(0), true, noUpdate, 0, sig);

        RpRegistry.RelyingParty memory rp = registry.getRpUnchecked(rpId);
        assertFalse(rp.active);

        // Toggle back to active
        sig = _signUpdateRp(manager1Pk, rpId, 0, address(0), address(0), true, noUpdate, 1);
        registry.updateRp(rpId, 0, address(0), address(0), true, noUpdate, 1, sig);

        rp = registry.getRp(rpId);
        assertTrue(rp.active);
    }

    function testUpdateRpWithNoUpdate() public {
        uint64 rpId = 1;
        string memory initialDomain = "app1.world.org";

        // Register an RP
        registry.register(rpId, manager1, signer1, initialDomain);

        string memory noUpdate = registry.NO_UPDATE();

        // Update with NO_UPDATE sentinel value for domain
        bytes memory sig = _signUpdateRp(manager1Pk, rpId, 0, address(0), address(0), false, noUpdate, 0);
        registry.updateRp(rpId, 0, address(0), address(0), false, noUpdate, 0, sig);

        // Verify domain unchanged
        RpRegistry.RelyingParty memory rp = registry.getRp(rpId);
        assertEq(rp.unverifiedWellKnownDomain, initialDomain);
    }

    function testUpdateRpWithEIP1271Signature() public {
        // Create a mock ERC-1271 wallet controlled by a signer
        uint256 walletOwnerPk = 0x7777;
        address walletOwner = vm.addr(walletOwnerPk);
        MockERC1271Wallet wallet = new MockERC1271Wallet(walletOwner);

        uint64 rpId = 1;
        string memory initialDomain = "app1.world.org";

        // Register an RP with wallet as manager
        registry.register(rpId, address(wallet), signer1, initialDomain);

        string memory noUpdate = registry.NO_UPDATE();

        // Update using EIP-1271 signature
        address newSigner = vm.addr(0x8888);
        bytes memory sig = _signUpdateRp(walletOwnerPk, rpId, 0, address(0), newSigner, false, noUpdate, 0);

        registry.updateRp(rpId, 0, address(0), newSigner, false, noUpdate, 0, sig);

        // Verify update
        RpRegistry.RelyingParty memory rp = registry.getRp(rpId);
        assertEq(rp.signer, newSigner);
        assertEq(rp.manager, address(wallet));
    }

    function testUpdateRpInvalidSignature() public {
        uint64 rpId = 1;
        string memory initialDomain = "app1.world.org";

        // Register an RP
        registry.register(rpId, manager1, signer1, initialDomain);

        string memory noUpdate = registry.NO_UPDATE();

        // Try to update with wrong private key
        uint256 wrongPk = 0x9999;
        bytes memory badSig = _signUpdateRp(wrongPk, rpId, 0, address(0), signer2, false, noUpdate, 0);

        vm.expectRevert(abi.encodeWithSelector(RpRegistry.InvalidSignature.selector));
        registry.updateRp(rpId, 0, address(0), signer2, false, noUpdate, 0, badSig);
    }

    function testUpdateRpInvalidEIP1271Signature() public {
        // Create a mock ERC-1271 wallet
        uint256 walletOwnerPk = 0x7777;
        address walletOwner = vm.addr(walletOwnerPk);
        MockERC1271Wallet wallet = new MockERC1271Wallet(walletOwner);

        uint64 rpId = 1;
        string memory initialDomain = "app1.world.org";

        // Register an RP with wallet as manager
        registry.register(rpId, address(wallet), signer1, initialDomain);

        string memory noUpdate = registry.NO_UPDATE();

        // Try to update with wrong private key for EIP-1271
        uint256 wrongPk = 0x9999;
        bytes memory badSig = _signUpdateRp(wrongPk, rpId, 0, address(0), signer2, false, noUpdate, 0);

        vm.expectRevert(abi.encodeWithSelector(RpRegistry.InvalidSignature.selector));
        registry.updateRp(rpId, 0, address(0), signer2, false, noUpdate, 0, badSig);
    }

    function testUpdateRpNonceMismatch() public {
        uint64 rpId = 1;
        string memory initialDomain = "app1.world.org";

        // Register an RP
        registry.register(rpId, manager1, signer1, initialDomain);

        assertEq(registry.nonceOf(rpId), 0);

        string memory noUpdate = registry.NO_UPDATE();

        // Try to update with wrong nonce
        bytes memory sig = _signUpdateRp(manager1Pk, rpId, 0, address(0), signer2, false, noUpdate, 5);

        vm.expectRevert(abi.encodeWithSelector(RpRegistry.InvalidNonce.selector));
        registry.updateRp(rpId, 0, address(0), signer2, false, noUpdate, 5, sig);
    }

    function testUpdateRpNonExistentRp() public {
        uint64 nonExistentRpId = 999;
        string memory noUpdate = registry.NO_UPDATE();

        bytes memory sig = _signUpdateRp(manager1Pk, nonExistentRpId, 0, address(0), signer2, false, noUpdate, 0);

        vm.expectRevert(abi.encodeWithSelector(RpRegistry.RpIdDoesNotExist.selector));
        registry.updateRp(nonExistentRpId, 0, address(0), signer2, false, noUpdate, 0, sig);
    }

    function testUpdateRpNonceIncrementsOnEachUpdate() public {
        uint64 rpId = 1;
        string memory initialDomain = "app1.world.org";

        // Register an RP
        registry.register(rpId, manager1, signer1, initialDomain);

        assertEq(registry.nonceOf(rpId), 0);

        string memory noUpdate = registry.NO_UPDATE();

        // First update (also tests that domain can be set to empty string)
        bytes memory sig1 = _signUpdateRp(manager1Pk, rpId, 0, address(0), signer2, false, "", 0);
        registry.updateRp(rpId, 0, address(0), signer2, false, "", 0, sig1);
        assertEq(registry.nonceOf(rpId), 1);
        assertEq(registry.getRp(rpId).unverifiedWellKnownDomain, "");

        // Second update
        bytes memory sig2 = _signUpdateRp(manager1Pk, rpId, 0, address(0), signer1, false, noUpdate, 1);
        registry.updateRp(rpId, 0, address(0), signer1, false, noUpdate, 1, sig2);
        assertEq(registry.nonceOf(rpId), 2);

        // Third update
        bytes memory sig3 = _signUpdateRp(manager1Pk, rpId, 0, address(0), signer2, false, noUpdate, 2);
        registry.updateRp(rpId, 0, address(0), signer2, false, noUpdate, 2, sig3);
        assertEq(registry.nonceOf(rpId), 3);
    }

    function testUpdateRpCannotReplayOldSignature() public {
        uint64 rpId = 1;
        string memory initialDomain = "app1.world.org";

        // Register an RP
        registry.register(rpId, manager1, signer1, initialDomain);

        string memory noUpdate = registry.NO_UPDATE();

        // First update
        bytes memory sig1 = _signUpdateRp(manager1Pk, rpId, 0, address(0), signer2, false, noUpdate, 0);
        registry.updateRp(rpId, 0, address(0), signer2, false, noUpdate, 0, sig1);

        // Try to replay the same signature
        vm.expectRevert(abi.encodeWithSelector(RpRegistry.InvalidNonce.selector));
        registry.updateRp(rpId, 0, address(0), signer2, false, noUpdate, 0, sig1);
    }

    function testUpdateRpManagerTransfer() public {
        uint64 rpId = 1;
        string memory initialDomain = "app1.world.org";

        // Register an RP
        registry.register(rpId, manager1, signer1, initialDomain);

        string memory noUpdate = registry.NO_UPDATE();

        // Transfer manager from manager1 to manager2
        bytes memory sig = _signUpdateRp(manager1Pk, rpId, 0, manager2, address(0), false, noUpdate, 0);
        registry.updateRp(rpId, 0, manager2, address(0), false, noUpdate, 0, sig);

        RpRegistry.RelyingParty memory rp = registry.getRp(rpId);
        assertEq(rp.manager, manager2);

        // Now only manager2 can sign updates
        bytes memory sig2 = _signUpdateRp(manager2Pk, rpId, 0, address(0), signer2, false, noUpdate, 1);
        registry.updateRp(rpId, 0, address(0), signer2, false, noUpdate, 1, sig2);

        rp = registry.getRp(rpId);
        assertEq(rp.signer, signer2);

        // Old manager tries to sign an update
        bytes memory badSig = _signUpdateRp(manager1Pk, rpId, 0, address(0), signer2, false, noUpdate, 2);

        vm.expectRevert(abi.encodeWithSelector(RpRegistry.InvalidSignature.selector));
        registry.updateRp(rpId, 0, address(0), signer2, false, noUpdate, 2, badSig);
    }

    function testUpdateRpOprfKeyId() public {
        uint64 rpId = 1;
        uint160 oprfKeyId = uint160(rpId);
        string memory initialDomain = "app1.world.org";

        // Register an RP
        registry.register(rpId, manager1, signer1, initialDomain);

        string memory noUpdate = registry.NO_UPDATE();

        // Update only oprfKeyId
        uint160 newOprfKeyId = 42;

        bytes memory sig = _signUpdateRp(manager1Pk, rpId, newOprfKeyId, address(0), address(0), false, noUpdate, 0);
        registry.updateRp(rpId, newOprfKeyId, address(0), address(0), false, noUpdate, 0, sig);

        // Verify only oprfKeyId changed
        RpRegistry.RelyingParty memory rp = registry.getRp(rpId);
        assertEq(rp.oprfKeyId, newOprfKeyId); // Changed
        assertEq(rp.manager, manager1); // Unchanged
        assertEq(rp.signer, signer1); // Unchanged
        assertEq(rp.unverifiedWellKnownDomain, initialDomain); // Unchanged
        assertTrue(rp.active);
    }

    // Fee Management Tests

    function testSetFeeRecipient() public {
        address newRecipient = vm.addr(0xAAAA);

        vm.expectEmit(true, true, false, true);
        emit RpRegistry.FeeRecipientUpdated(feeRecipient, newRecipient);

        registry.setFeeRecipient(newRecipient);

        assertEq(registry.getFeeRecipient(), newRecipient);
    }

    function testCannotSetFeeRecipientToZeroAddress() public {
        vm.expectRevert(abi.encodeWithSelector(RpRegistry.ZeroAddress.selector));
        registry.setFeeRecipient(address(0));
    }

    function testOnlyOwnerCanSetFeeRecipient() public {
        address newRecipient = vm.addr(0xAAAA);

        vm.prank(manager1);
        vm.expectRevert();
        registry.setFeeRecipient(newRecipient);
        assertEq(registry.getFeeRecipient(), feeRecipient);
    }

    function testSetRegistrationFee() public {
        uint256 newFee = 0.01 ether;

        vm.expectEmit(false, false, false, true);
        emit RpRegistry.RegistrationFeeUpdated(0, newFee);

        registry.setRegistrationFee(newFee);

        assertEq(registry.getRegistrationFee(), newFee);
    }

    function testOnlyOwnerCanSetRegistrationFee() public {
        uint256 newFee = 1 ether;

        vm.prank(manager1);
        vm.expectRevert();
        registry.setRegistrationFee(newFee);
    }

    function testSetFeeToken() public {
        ERC20Mock newToken = new ERC20Mock();

        vm.expectEmit(true, true, false, true);
        emit RpRegistry.FeeTokenUpdated(address(feeToken), address(newToken));

        registry.setFeeToken(address(newToken));

        assertEq(registry.getFeeToken(), address(newToken));
    }

    function testCannotSetFeeTokenToZeroAddress() public {
        vm.expectRevert(abi.encodeWithSelector(RpRegistry.ZeroAddress.selector));
        registry.setFeeToken(address(0));
    }

    function testOnlyOwnerCanSetFeeToken() public {
        ERC20Mock newToken = new ERC20Mock();

        vm.prank(manager1);
        vm.expectRevert();
        registry.setFeeToken(address(newToken));

        assertEq(registry.getFeeToken(), address(feeToken));
    }

    function testRegisterWithFee() public {
        uint256 fee = 100e18;
        registry.setRegistrationFee(fee);

        uint64 rpId = 1;
        string memory domain = "example.world.org";

        // Mint tokens to manager1 and approve registry
        feeToken.mint(manager1, fee);
        vm.prank(manager1);
        feeToken.approve(address(registry), fee);

        uint256 recipientBalanceBefore = feeToken.balanceOf(feeRecipient);

        vm.prank(manager1);
        registry.register(rpId, manager1, signer1, domain);

        assertEq(feeToken.balanceOf(feeRecipient), recipientBalanceBefore + fee);
        assertEq(feeToken.balanceOf(manager1), 0);
    }

    function testRegisterWithExcessFee() public {
        uint256 fee = 100e18;
        registry.setRegistrationFee(fee);

        uint64 rpId = 1;
        string memory domain = "example.world.org";

        // Mint more tokens than required and approve registry
        feeToken.mint(manager1, fee * 2);
        vm.prank(manager1);
        feeToken.approve(address(registry), fee * 2);

        uint256 recipientBalanceBefore = feeToken.balanceOf(feeRecipient);

        vm.prank(manager1);
        registry.register(rpId, manager1, signer1, domain);

        // Only the fee amount should be transferred
        assertEq(feeToken.balanceOf(feeRecipient), recipientBalanceBefore + fee);
        assertEq(feeToken.balanceOf(manager1), fee);
    }

    function testCannotRegisterWithInsufficientFee() public {
        uint256 fee = 100e18;
        registry.setRegistrationFee(fee);

        uint64 rpId = 1;
        string memory domain = "example.world.org";

        // Mint insufficient tokens
        feeToken.mint(manager1, fee - 1);
        vm.prank(manager1);
        feeToken.approve(address(registry), fee - 1);

        vm.expectRevert(abi.encodeWithSelector(RpRegistry.InsufficientFunds.selector));
        vm.prank(manager1);
        registry.register(rpId, manager1, signer1, domain);
    }

    function testRegisterManyWithFee() public {
        uint256 fee = 100e18;
        registry.setRegistrationFee(fee);

        uint64[] memory rpIds = new uint64[](3);
        rpIds[0] = 1;
        rpIds[1] = 2;
        rpIds[2] = 3;

        address[] memory managers = new address[](3);
        managers[0] = manager1;
        managers[1] = manager2;
        managers[2] = vm.addr(0x5555);

        address[] memory signers = new address[](3);
        signers[0] = signer1;
        signers[1] = signer2;
        signers[2] = vm.addr(0x6666);

        string[] memory domains = new string[](3);
        domains[0] = "app1.world.org";
        domains[1] = "app2.world.org";
        domains[2] = "app3.world.org";

        // Mint tokens and approve
        feeToken.mint(manager1, fee * 3);
        vm.prank(manager1);
        feeToken.approve(address(registry), fee * 3);

        uint256 recipientBalanceBefore = feeToken.balanceOf(feeRecipient);

        vm.prank(manager1);
        registry.registerMany(rpIds, managers, signers, domains);

        assertEq(feeToken.balanceOf(feeRecipient), recipientBalanceBefore + fee * 3);
        assertEq(feeToken.balanceOf(manager1), 0);
    }

    function testCannotRegisterManyWithInsufficientFee() public {
        uint256 fee = 100e18;
        registry.setRegistrationFee(fee);

        uint64[] memory rpIds = new uint64[](3);
        rpIds[0] = 1;
        rpIds[1] = 2;
        rpIds[2] = 3;

        address[] memory managers = new address[](3);
        managers[0] = manager1;
        managers[1] = manager2;
        managers[2] = vm.addr(0x5555);

        address[] memory signers = new address[](3);
        signers[0] = signer1;
        signers[1] = signer2;
        signers[2] = vm.addr(0x6666);

        string[] memory domains = new string[](3);
        domains[0] = "app1.world.org";
        domains[1] = "app2.world.org";
        domains[2] = "app3.world.org";

        // Mint insufficient tokens (3 * fee - 1)
        feeToken.mint(manager1, fee * 3 - 1);
        vm.prank(manager1);
        feeToken.approve(address(registry), fee * 3 - 1);

        vm.expectRevert(abi.encodeWithSelector(RpRegistry.InsufficientFunds.selector));
        vm.prank(manager1);
        registry.registerMany(rpIds, managers, signers, domains);
    }
}
