// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {WorldIDRegistry} from "../../src/core/WorldIDRegistry.sol";
import {WorldIDRegistryV2} from "../../src/core/WorldIDRegistryV2Unreleased.sol";
import {IWorldIDRegistry} from "../../src/core/interfaces/IWorldIDRegistry.sol";
import {IWorldIDRegistryV2} from "../../src/core/interfaces/IWorldIDRegistryV2.sol";
import {PackedAccountData} from "../../src/core/libraries/PackedAccountData.sol";
import {WorldIDBase} from "../../src/core/abstract/WorldIDBase.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";

contract WorldIDRegistryV2WIP104Test is Test {
    WorldIDRegistryV2 public registry;

    uint256 constant AUTH1_PRIVATE_KEY = 0x01;
    uint256 constant AUTH2_PRIVATE_KEY = 0x02;
    uint256 constant AUTH3_PRIVATE_KEY = 0x03;
    uint256 constant OFFCHAIN_SIGNER_COMMITMENT = 0x1234567890;

    address public auth1;
    address public auth2;
    address public auth3;
    address public recoveryAddress;

    function setUp() public {
        auth1 = vm.addr(AUTH1_PRIVATE_KEY);
        auth2 = vm.addr(AUTH2_PRIVATE_KEY);
        auth3 = vm.addr(AUTH3_PRIVATE_KEY);
        recoveryAddress = address(0xEC4);

        WorldIDRegistry implementationV1 = new WorldIDRegistry();
        ERC20Mock feeToken = new ERC20Mock();
        bytes memory initData =
            abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30, address(this), feeToken, 0);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementationV1), initData);

        WorldIDRegistryV2 implementationV2 = new WorldIDRegistryV2();
        WorldIDRegistry(address(proxy)).upgradeToAndCall(address(implementationV2), "");

        registry = WorldIDRegistryV2(address(proxy));
    }

    ////////////////////////////////////////////////////////////
    //                        Helpers                         //
    ////////////////////////////////////////////////////////////

    function _eip712Sign(bytes32 typeHash, bytes memory data, uint256 privateKey) private view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encodePacked(typeHash, data));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", registry.domainSeparatorV4(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _createAccount(address authenticator) private returns (uint64 leafIndex) {
        leafIndex = uint64(registry.getNextLeafIndex());
        address[] memory addrs = new address[](1);
        addrs[0] = authenticator;
        uint256[] memory pubkeys = new uint256[](1);
        pubkeys[0] = 0;
        registry.createAccount(recoveryAddress, addrs, pubkeys, OFFCHAIN_SIGNER_COMMITMENT);
    }

    function _insertAuthenticator(
        uint64 leafIndex,
        address newAuthenticator,
        uint32 pubkeyId,
        uint256 signerKey,
        uint256 oldCommitment
    ) private returns (uint256 newCommitment) {
        newCommitment = oldCommitment + 1;
        uint256 nonce = registry.getSignatureNonce(leafIndex);

        bytes memory signature = _eip712Sign(
            registry.INSERT_AUTHENTICATOR_TYPEHASH(),
            abi.encode(leafIndex, newAuthenticator, uint256(pubkeyId), newCommitment, newCommitment, nonce),
            signerKey
        );

        registry.insertAuthenticator(
            leafIndex, newAuthenticator, pubkeyId, newCommitment, oldCommitment, newCommitment, signature, nonce
        );
    }

    function _removeAuthenticator(
        uint64 leafIndex,
        address authenticator,
        uint32 pubkeyId,
        uint256 signerKey,
        uint256 oldCommitment
    ) private returns (uint256 newCommitment) {
        newCommitment = oldCommitment + 1;
        uint256 nonce = registry.getSignatureNonce(leafIndex);

        bytes memory signature = _eip712Sign(
            registry.REMOVE_AUTHENTICATOR_TYPEHASH(),
            abi.encode(leafIndex, authenticator, uint256(pubkeyId), oldCommitment, newCommitment, nonce),
            signerKey
        );

        registry.removeAuthenticator(
            leafIndex, authenticator, pubkeyId, oldCommitment, oldCommitment, newCommitment, signature, nonce
        );
    }

    ////////////////////////////////////////////////////////////
    //                    Account Creation                    //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Creating an account with non-admin authenticators is not allowed per WIP-104.
     */
    function test_CreateAccount_RevertsWithZeroAddress() public {
        address[] memory addrs = new address[](1);
        addrs[0] = address(0);
        uint256[] memory pubkeys = new uint256[](1);
        pubkeys[0] = 0;

        vm.expectRevert(abi.encodeWithSelector(WorldIDBase.ZeroAddress.selector));
        registry.createAccount(recoveryAddress, addrs, pubkeys, OFFCHAIN_SIGNER_COMMITMENT);
    }

    ////////////////////////////////////////////////////////////
    //                Insert Authenticator                    //
    ////////////////////////////////////////////////////////////

    function test_InsertProvingAuthenticator() public {
        uint64 leafIndex = _createAccount(auth1);
        uint256 commitment = OFFCHAIN_SIGNER_COMMITMENT;

        commitment = _insertAuthenticator(leafIndex, address(0), 1, AUTH1_PRIVATE_KEY, commitment);

        // Proving authenticator has no on-chain mapping
        assertEq(registry.getPackedAccountData(address(0)), 0);
        // Admin authenticator still exists
        assertEq(PackedAccountData.leafIndex(registry.getPackedAccountData(auth1)), leafIndex);
    }

    function test_InsertAdminAuthenticator() public {
        uint64 leafIndex = _createAccount(auth1);
        uint256 commitment = OFFCHAIN_SIGNER_COMMITMENT;

        commitment = _insertAuthenticator(leafIndex, auth2, 1, AUTH1_PRIVATE_KEY, commitment);

        assertEq(PackedAccountData.leafIndex(registry.getPackedAccountData(auth2)), leafIndex);
        assertEq(PackedAccountData.pubkeyId(registry.getPackedAccountData(auth2)), 1);
    }

    function test_InsertProvingAuthenticator_SkipsAddressValidation() public {
        // Insert two proving authenticators with address(0) — should not conflict
        uint64 leafIndex = _createAccount(auth1);
        uint256 commitment = OFFCHAIN_SIGNER_COMMITMENT;

        commitment = _insertAuthenticator(leafIndex, address(0), 1, AUTH1_PRIVATE_KEY, commitment);
        commitment = _insertAuthenticator(leafIndex, address(0), 2, AUTH1_PRIVATE_KEY, commitment);
    }

    ////////////////////////////////////////////////////////////
    //                Remove Authenticator                    //
    ////////////////////////////////////////////////////////////

    function test_RemoveProvingAuthenticator() public {
        uint64 leafIndex = _createAccount(auth1);
        uint256 commitment = OFFCHAIN_SIGNER_COMMITMENT;

        commitment = _insertAuthenticator(leafIndex, address(0), 1, AUTH1_PRIVATE_KEY, commitment);
        commitment = _removeAuthenticator(leafIndex, address(0), 1, AUTH1_PRIVATE_KEY, commitment);

        // Re-inserting at the same pubkeyId succeeds, proving the bitmap was cleared
        commitment = _insertAuthenticator(leafIndex, address(0), 1, AUTH1_PRIVATE_KEY, commitment);
    }

    function test_RemoveAdminAuthenticator() public {
        uint64 leafIndex = _createAccount(auth1);
        uint256 commitment = OFFCHAIN_SIGNER_COMMITMENT;

        // Insert a second admin so we can remove the first
        commitment = _insertAuthenticator(leafIndex, auth2, 1, AUTH1_PRIVATE_KEY, commitment);
        commitment = _removeAuthenticator(leafIndex, auth1, 0, AUTH2_PRIVATE_KEY, commitment);

        assertEq(registry.getPackedAccountData(auth1), 0);
    }

    function test_RemoveProvingAuthenticator_RevertsWithNonZeroAddress() public {
        uint64 leafIndex = _createAccount(auth1);
        uint256 commitment = OFFCHAIN_SIGNER_COMMITMENT;

        commitment = _insertAuthenticator(leafIndex, address(0), 1, AUTH1_PRIVATE_KEY, commitment);

        uint256 nonce = registry.getSignatureNonce(leafIndex);
        uint256 newCommitment = commitment + 1;

        // Sign with non-zero address for a proving authenticator
        bytes memory signature = _eip712Sign(
            registry.REMOVE_AUTHENTICATOR_TYPEHASH(),
            abi.encode(leafIndex, auth2, uint256(1), commitment, newCommitment, nonce),
            AUTH1_PRIVATE_KEY
        );

        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistryV2.AuthenticatorClassMismatch.selector, uint32(1), true));
        registry.removeAuthenticator(leafIndex, auth2, 1, commitment, commitment, newCommitment, signature, nonce);
    }

    function test_RemoveAdminAuthenticator_RevertsWithZeroAddress() public {
        uint64 leafIndex = _createAccount(auth1);
        uint256 commitment = OFFCHAIN_SIGNER_COMMITMENT;

        commitment = _insertAuthenticator(leafIndex, auth2, 1, AUTH1_PRIVATE_KEY, commitment);

        uint256 nonce = registry.getSignatureNonce(leafIndex);
        uint256 newCommitment = commitment + 1;

        bytes memory signature = _eip712Sign(
            registry.REMOVE_AUTHENTICATOR_TYPEHASH(),
            abi.encode(leafIndex, address(0), uint256(1), commitment, newCommitment, nonce),
            AUTH1_PRIVATE_KEY
        );

        vm.expectRevert(
            abi.encodeWithSelector(IWorldIDRegistryV2.AuthenticatorClassMismatch.selector, uint32(1), false)
        );
        registry.removeAuthenticator(leafIndex, address(0), 1, commitment, commitment, newCommitment, signature, nonce);
    }

    function test_RemoveLastAdmin_RevertsWhenOnlyProvingRemains() public {
        uint64 leafIndex = _createAccount(auth1);
        uint256 commitment = OFFCHAIN_SIGNER_COMMITMENT;

        // Insert a proving authenticator
        commitment = _insertAuthenticator(leafIndex, address(0), 1, AUTH1_PRIVATE_KEY, commitment);

        // Try to remove the only admin authenticator
        uint256 nonce = registry.getSignatureNonce(leafIndex);
        uint256 newCommitment = commitment + 1;

        bytes memory signature = _eip712Sign(
            registry.REMOVE_AUTHENTICATOR_TYPEHASH(),
            abi.encode(leafIndex, auth1, uint256(0), commitment, newCommitment, nonce),
            AUTH1_PRIVATE_KEY
        );

        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistryV2.UnmanageableNotAllowed.selector));
        registry.removeAuthenticator(leafIndex, auth1, 0, commitment, commitment, newCommitment, signature, nonce);
    }

    function test_RemoveLastAdmin_SucceedsWhenNoProvingRemains() public {
        // This is essentially removing the World ID as it won't be usable anymore
        uint64 leafIndex = _createAccount(auth1);
        uint256 commitment = OFFCHAIN_SIGNER_COMMITMENT;

        // Insert second admin, then remove first — leaves only one admin, no proving
        commitment = _insertAuthenticator(leafIndex, auth2, 1, AUTH1_PRIVATE_KEY, commitment);
        commitment = _removeAuthenticator(leafIndex, auth1, 0, AUTH2_PRIVATE_KEY, commitment);

        assertEq(registry.getPackedAccountData(auth1), 0);
    }

    ////////////////////////////////////////////////////////////
    //                Update Authenticator                    //
    ////////////////////////////////////////////////////////////

    function test_UpdateAuthenticator_RevertsMethodUnsupported() public {
        uint64 leafIndex = _createAccount(auth1);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistryV2.MethodUnsupported.selector));
        registry.updateAuthenticator(
            leafIndex, auth1, auth2, 0, 0, OFFCHAIN_SIGNER_COMMITMENT, OFFCHAIN_SIGNER_COMMITMENT + 1, bytes(""), 0
        );
    }

    ////////////////////////////////////////////////////////////
    //                  Max Authenticators                    //
    ////////////////////////////////////////////////////////////

    function test_SetMaxAuthenticators_RevertsAbove48() public {
        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.OwnerMaxAuthenticatorsOutOfBounds.selector));
        registry.setMaxAuthenticators(49);
    }

    function test_SetMaxAuthenticators_SucceedsAt48() public {
        registry.setMaxAuthenticators(48);
        assertEq(registry.getMaxAuthenticators(), 48);
    }
}
