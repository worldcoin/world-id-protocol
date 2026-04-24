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

/// @dev Shared scaffolding for tests that exercise the upgraded V2 proxy:
///     deploys V1 behind an ERC1967 proxy, upgrades to V2, and exposes an EIP-712 signing helper.
abstract contract WorldIDRegistryV2TestBase is Test {
    WorldIDRegistryV2 public registry;

    uint256 internal constant OFFCHAIN_SIGNER_COMMITMENT = 0x1234567890;

    function setUp() public virtual {
        WorldIDRegistry implementationV1 = new WorldIDRegistry();
        ERC20Mock feeToken = new ERC20Mock();
        bytes memory initData =
            abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30, address(this), feeToken, 0);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementationV1), initData);

        WorldIDRegistryV2 implementationV2 = new WorldIDRegistryV2();
        WorldIDRegistry(address(proxy)).upgradeToAndCall(address(implementationV2), "");

        registry = WorldIDRegistryV2(address(proxy));
    }

    function _eip712Sign(bytes32 typeHash, bytes memory data, uint256 privateKey) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encodePacked(typeHash, data));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", registry.domainSeparatorV4(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _createAccount(address authenticator, address recoveryAgent) internal returns (uint64 leafIndex) {
        leafIndex = registry.getNextLeafIndex();
        address[] memory addrs = new address[](1);
        addrs[0] = authenticator;
        uint256[] memory pubkeys = new uint256[](1);
        pubkeys[0] = 0;
        registry.createAccount(recoveryAgent, addrs, pubkeys, OFFCHAIN_SIGNER_COMMITMENT);
    }
}

contract WorldIDRegistryV2WIP104Test is WorldIDRegistryV2TestBase {
    uint256 constant AUTH1_PRIVATE_KEY = 0x01;
    uint256 constant AUTH2_PRIVATE_KEY = 0x02;
    uint256 constant AUTH3_PRIVATE_KEY = 0x03;

    address public auth1;
    address public auth2;
    address public auth3;
    address public recoveryAddress;

    function setUp() public override {
        super.setUp();
        auth1 = vm.addr(AUTH1_PRIVATE_KEY);
        auth2 = vm.addr(AUTH2_PRIVATE_KEY);
        auth3 = vm.addr(AUTH3_PRIVATE_KEY);
        recoveryAddress = address(0xEC4);
    }

    ////////////////////////////////////////////////////////////
    //                        Helpers                         //
    ////////////////////////////////////////////////////////////

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
        uint64 leafIndex = _createAccount(auth1, recoveryAddress);
        uint256 commitment = OFFCHAIN_SIGNER_COMMITMENT;

        commitment = _insertAuthenticator(leafIndex, address(0), 1, AUTH1_PRIVATE_KEY, commitment);

        // Proving authenticator has no on-chain mapping
        assertEq(registry.getPackedAccountData(address(0)), 0);
        // Admin authenticator still exists
        assertEq(PackedAccountData.leafIndex(registry.getPackedAccountData(auth1)), leafIndex);
    }

    function test_InsertAdminAuthenticator() public {
        uint64 leafIndex = _createAccount(auth1, recoveryAddress);
        uint256 commitment = OFFCHAIN_SIGNER_COMMITMENT;

        commitment = _insertAuthenticator(leafIndex, auth2, 1, AUTH1_PRIVATE_KEY, commitment);

        assertEq(PackedAccountData.leafIndex(registry.getPackedAccountData(auth2)), leafIndex);
        assertEq(PackedAccountData.pubkeyId(registry.getPackedAccountData(auth2)), 1);
    }

    function test_InsertProvingAuthenticator_SkipsAddressValidation() public {
        // Insert two proving authenticators with address(0) — should not conflict
        uint64 leafIndex = _createAccount(auth1, recoveryAddress);
        uint256 commitment = OFFCHAIN_SIGNER_COMMITMENT;

        commitment = _insertAuthenticator(leafIndex, address(0), 1, AUTH1_PRIVATE_KEY, commitment);
        commitment = _insertAuthenticator(leafIndex, address(0), 2, AUTH1_PRIVATE_KEY, commitment);
    }

    ////////////////////////////////////////////////////////////
    //                Remove Authenticator                    //
    ////////////////////////////////////////////////////////////

    function test_RemoveProvingAuthenticator() public {
        uint64 leafIndex = _createAccount(auth1, recoveryAddress);
        uint256 commitment = OFFCHAIN_SIGNER_COMMITMENT;

        commitment = _insertAuthenticator(leafIndex, address(0), 1, AUTH1_PRIVATE_KEY, commitment);
        commitment = _removeAuthenticator(leafIndex, address(0), 1, AUTH1_PRIVATE_KEY, commitment);

        // Re-inserting at the same pubkeyId succeeds, proving the bitmap was cleared
        commitment = _insertAuthenticator(leafIndex, address(0), 1, AUTH1_PRIVATE_KEY, commitment);
    }

    function test_RemoveAdminAuthenticator() public {
        uint64 leafIndex = _createAccount(auth1, recoveryAddress);
        uint256 commitment = OFFCHAIN_SIGNER_COMMITMENT;

        // Insert a second admin so we can remove the first
        commitment = _insertAuthenticator(leafIndex, auth2, 1, AUTH1_PRIVATE_KEY, commitment);
        commitment = _removeAuthenticator(leafIndex, auth1, 0, AUTH2_PRIVATE_KEY, commitment);

        assertEq(registry.getPackedAccountData(auth1), 0);
    }

    function test_RemoveProvingAuthenticator_RevertsWithNonZeroAddress() public {
        uint64 leafIndex = _createAccount(auth1, recoveryAddress);
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
        uint64 leafIndex = _createAccount(auth1, recoveryAddress);
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
        uint64 leafIndex = _createAccount(auth1, recoveryAddress);
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
        uint64 leafIndex = _createAccount(auth1, recoveryAddress);
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
        uint64 leafIndex = _createAccount(auth1, recoveryAddress);

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

/// @title WIP-102 tests for WorldIDRegistryV2
/// @notice Exercises `updateRecoveryAgent`, `revertRecoveryAgentUpdate`, the new `recoverAccount`
///     signer-selection semantics, and the deprecation of the three V1 recovery-agent-update methods.
contract WorldIDRegistryV2WIP102Test is WorldIDRegistryV2TestBase {
    uint256 constant AUTH1_PRIVATE_KEY = 0xA1;
    uint256 constant RECOVERY_OLD_PRIVATE_KEY = 0xEC01;
    uint256 constant RECOVERY_NEW_PRIVATE_KEY = 0xEC02;
    uint256 constant RECOVERY_ATTACKER_PRIVATE_KEY = 0xBAD1;

    address auth1;
    address recoveryOld;
    address recoveryNew;
    address recoveryAttacker;

    function setUp() public override {
        super.setUp();
        auth1 = vm.addr(AUTH1_PRIVATE_KEY);
        recoveryOld = vm.addr(RECOVERY_OLD_PRIVATE_KEY);
        recoveryNew = vm.addr(RECOVERY_NEW_PRIVATE_KEY);
        recoveryAttacker = vm.addr(RECOVERY_ATTACKER_PRIVATE_KEY);
    }

    ////////////////////////////////////////////////////////////
    //                        Helpers                         //
    ////////////////////////////////////////////////////////////

    function _updateRecoveryAgentSig(uint64 leafIndex, address newAgent, uint256 nonce, uint256 privateKey)
        private
        view
        returns (bytes memory)
    {
        return
            _eip712Sign(registry.UPDATE_RECOVERY_AGENT_TYPEHASH(), abi.encode(leafIndex, newAgent, nonce), privateKey);
    }

    function _revertRecoveryAgentUpdateSig(uint64 leafIndex, uint256 nonce, uint256 privateKey)
        private
        view
        returns (bytes memory)
    {
        return _eip712Sign(registry.REVERT_RECOVERY_AGENT_UPDATE_TYPEHASH(), abi.encode(leafIndex, nonce), privateKey);
    }

    function _recoverAccountSig(
        uint64 leafIndex,
        address newAuth,
        uint256 newCommitment,
        uint256 nonce,
        uint256 privateKey
    ) private view returns (bytes memory) {
        return _eip712Sign(
            registry.RECOVER_ACCOUNT_TYPEHASH(),
            abi.encode(leafIndex, newAuth, newCommitment, newCommitment, nonce),
            privateKey
        );
    }

    ////////////////////////////////////////////////////////////
    //                  updateRecoveryAgent                   //
    ////////////////////////////////////////////////////////////

    function test_UpdateRecoveryAgent_Success() public {
        uint64 leafIndex = _createAccount(auth1, recoveryOld);
        uint256 cooldown = registry.getRecoveryAgentUpdateCooldown();
        uint256 expectedInvalidAfter = block.timestamp + cooldown;

        bytes memory sig = _updateRecoveryAgentSig(leafIndex, recoveryNew, 0, AUTH1_PRIVATE_KEY);

        vm.expectEmit(true, true, true, true);
        emit IWorldIDRegistryV2.RecoveryAgentUpdated(leafIndex, recoveryOld, recoveryNew, expectedInvalidAfter);
        registry.updateRecoveryAgent(leafIndex, recoveryNew, sig, 0);

        // Effective Recovery Agent remains the previous one during the revert window.
        assertEq(registry.getRecoveryAgent(leafIndex), recoveryOld);

        // Previous Recovery Agent captured in the revert window.
        (address prev, uint256 invalidAfter) = registry.getPreviousRecoveryAgentUpdate(leafIndex);
        assertEq(prev, recoveryOld);
        assertEq(invalidAfter, expectedInvalidAfter);

        // Nonce was incremented.
        assertEq(registry.getSignatureNonce(leafIndex), 1);

        // After the window elapses, the newly-set agent becomes the effective Recovery Agent.
        skip(cooldown + 1);
        assertEq(registry.getRecoveryAgent(leafIndex), recoveryNew);
    }

    function test_UpdateRecoveryAgent_RevertsWhenActiveUpdate() public {
        uint64 leafIndex = _createAccount(auth1, recoveryOld);
        uint256 cooldown = registry.getRecoveryAgentUpdateCooldown();

        bytes memory sig1 = _updateRecoveryAgentSig(leafIndex, recoveryNew, 0, AUTH1_PRIVATE_KEY);
        registry.updateRecoveryAgent(leafIndex, recoveryNew, sig1, 0);

        // Still within the window → a second updateRecoveryAgent must revert.
        address third = vm.addr(0xEC03);
        bytes memory sig2 = _updateRecoveryAgentSig(leafIndex, third, 1, AUTH1_PRIVATE_KEY);
        uint256 expectedInvalidAfter = block.timestamp + cooldown;
        vm.expectRevert(
            abi.encodeWithSelector(
                IWorldIDRegistryV2.RecoveryAgentUpdateStillActive.selector, leafIndex, expectedInvalidAfter
            )
        );
        registry.updateRecoveryAgent(leafIndex, third, sig2, 1);
    }

    function test_UpdateRecoveryAgent_SucceedsAfterWindowElapses() public {
        uint64 leafIndex = _createAccount(auth1, recoveryOld);
        uint256 cooldown = registry.getRecoveryAgentUpdateCooldown();

        bytes memory sig1 = _updateRecoveryAgentSig(leafIndex, recoveryNew, 0, AUTH1_PRIVATE_KEY);
        registry.updateRecoveryAgent(leafIndex, recoveryNew, sig1, 0);

        // Window elapses → new agent becomes the sole valid Recovery Agent and a second update is allowed.
        skip(cooldown + 1);

        address third = vm.addr(0xEC03);
        bytes memory sig2 = _updateRecoveryAgentSig(leafIndex, third, 1, AUTH1_PRIVATE_KEY);
        uint256 expectedInvalidAfter = block.timestamp + cooldown;

        vm.expectEmit(true, true, true, true);
        emit IWorldIDRegistryV2.RecoveryAgentUpdated(leafIndex, recoveryNew, third, expectedInvalidAfter);
        registry.updateRecoveryAgent(leafIndex, third, sig2, 1);

        // A new revert window is open, so the effective agent is once again the previous one.
        assertEq(registry.getRecoveryAgent(leafIndex), recoveryNew);
        (address prev, uint256 invalidAfter) = registry.getPreviousRecoveryAgentUpdate(leafIndex);
        assertEq(prev, recoveryNew);
        assertEq(invalidAfter, expectedInvalidAfter);
    }

    function test_UpdateRecoveryAgent_InvalidSignature() public {
        uint64 leafIndex = _createAccount(auth1, recoveryOld);

        // Signed with a key whose recovered address has no packed account data.
        uint256 strangerKey = 0xDEADBEEF;
        bytes memory sig = _updateRecoveryAgentSig(leafIndex, recoveryNew, 0, strangerKey);

        address stranger = vm.addr(strangerKey);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.AuthenticatorDoesNotExist.selector, stranger));
        registry.updateRecoveryAgent(leafIndex, recoveryNew, sig, 0);
    }

    function test_UpdateRecoveryAgent_InvalidNonce() public {
        uint64 leafIndex = _createAccount(auth1, recoveryOld);

        uint256 wrongNonce = 5;
        bytes memory sig = _updateRecoveryAgentSig(leafIndex, recoveryNew, wrongNonce, AUTH1_PRIVATE_KEY);
        vm.expectRevert(
            abi.encodeWithSelector(IWorldIDRegistry.MismatchedSignatureNonce.selector, leafIndex, 0, wrongNonce)
        );
        registry.updateRecoveryAgent(leafIndex, recoveryNew, sig, wrongNonce);
    }

    function test_UpdateRecoveryAgent_AccountDoesNotExist() public {
        uint64 leafIndex = 42; // never created
        bytes memory sig = _updateRecoveryAgentSig(leafIndex, recoveryNew, 0, AUTH1_PRIVATE_KEY);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.AccountDoesNotExist.selector, leafIndex));
        registry.updateRecoveryAgent(leafIndex, recoveryNew, sig, 0);
    }

    ////////////////////////////////////////////////////////////
    //               revertRecoveryAgentUpdate                //
    ////////////////////////////////////////////////////////////

    function test_RevertRecoveryAgentUpdate_Success() public {
        uint64 leafIndex = _createAccount(auth1, recoveryOld);
        bytes memory updateSig = _updateRecoveryAgentSig(leafIndex, recoveryNew, 0, AUTH1_PRIVATE_KEY);
        registry.updateRecoveryAgent(leafIndex, recoveryNew, updateSig, 0);

        bytes memory revertSig = _revertRecoveryAgentUpdateSig(leafIndex, 1, AUTH1_PRIVATE_KEY);

        vm.expectEmit(true, true, true, true);
        emit IWorldIDRegistryV2.RecoveryAgentUpdateReverted(leafIndex, recoveryOld, recoveryNew);
        registry.revertRecoveryAgentUpdate(leafIndex, revertSig, 1);

        assertEq(registry.getRecoveryAgent(leafIndex), recoveryOld);
        (address prev, uint256 invalidAfter) = registry.getPreviousRecoveryAgentUpdate(leafIndex);
        assertEq(prev, address(0));
        assertEq(invalidAfter, 0);
        assertEq(registry.getSignatureNonce(leafIndex), 2);
    }

    function test_RevertRecoveryAgentUpdate_RevertsWhenNoActiveUpdate() public {
        uint64 leafIndex = _createAccount(auth1, recoveryOld);
        bytes memory sig = _revertRecoveryAgentUpdateSig(leafIndex, 0, AUTH1_PRIVATE_KEY);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistryV2.NoActiveRecoveryAgentUpdate.selector, leafIndex));
        registry.revertRecoveryAgentUpdate(leafIndex, sig, 0);
    }

    function test_RevertRecoveryAgentUpdate_RevertsAfterWindowExpired() public {
        uint64 leafIndex = _createAccount(auth1, recoveryOld);
        uint256 cooldown = registry.getRecoveryAgentUpdateCooldown();

        bytes memory updateSig = _updateRecoveryAgentSig(leafIndex, recoveryNew, 0, AUTH1_PRIVATE_KEY);
        registry.updateRecoveryAgent(leafIndex, recoveryNew, updateSig, 0);
        (, uint256 invalidAfter) = registry.getPreviousRecoveryAgentUpdate(leafIndex);

        skip(cooldown + 1);

        bytes memory revertSig = _revertRecoveryAgentUpdateSig(leafIndex, 1, AUTH1_PRIVATE_KEY);
        vm.expectRevert(
            abi.encodeWithSelector(
                IWorldIDRegistryV2.RecoveryAgentUpdateWindowExpired.selector, leafIndex, invalidAfter
            )
        );
        registry.revertRecoveryAgentUpdate(leafIndex, revertSig, 1);
    }

    function test_RevertRecoveryAgentUpdate_InvalidSignature() public {
        uint64 leafIndex = _createAccount(auth1, recoveryOld);
        bytes memory updateSig = _updateRecoveryAgentSig(leafIndex, recoveryNew, 0, AUTH1_PRIVATE_KEY);
        registry.updateRecoveryAgent(leafIndex, recoveryNew, updateSig, 0);

        uint256 strangerKey = 0xCAFE;
        address stranger = vm.addr(strangerKey);
        bytes memory badRevertSig = _revertRecoveryAgentUpdateSig(leafIndex, 1, strangerKey);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.AuthenticatorDoesNotExist.selector, stranger));
        registry.revertRecoveryAgentUpdate(leafIndex, badRevertSig, 1);
    }

    function test_RevertRecoveryAgentUpdate_InvalidNonce() public {
        uint64 leafIndex = _createAccount(auth1, recoveryOld);
        bytes memory updateSig = _updateRecoveryAgentSig(leafIndex, recoveryNew, 0, AUTH1_PRIVATE_KEY);
        registry.updateRecoveryAgent(leafIndex, recoveryNew, updateSig, 0);

        uint256 wrongNonce = 99;
        bytes memory revertSig = _revertRecoveryAgentUpdateSig(leafIndex, wrongNonce, AUTH1_PRIVATE_KEY);
        vm.expectRevert(
            abi.encodeWithSelector(IWorldIDRegistry.MismatchedSignatureNonce.selector, leafIndex, 1, wrongNonce)
        );
        registry.revertRecoveryAgentUpdate(leafIndex, revertSig, wrongNonce);
    }

    ////////////////////////////////////////////////////////////
    //           recoverAccount with revert window            //
    ////////////////////////////////////////////////////////////

    function test_RecoverAccount_DuringWindow_UsesPreviousAgent() public {
        uint64 leafIndex = _createAccount(auth1, recoveryOld);

        // Kick off an update → revert window is open.
        bytes memory updateSig = _updateRecoveryAgentSig(leafIndex, recoveryNew, 0, AUTH1_PRIVATE_KEY);
        registry.updateRecoveryAgent(leafIndex, recoveryNew, updateSig, 0);

        // Recovery signed by the PREVIOUS agent must succeed inside the window.
        address newAuth = address(0xBEE1);
        uint256 nonce = 1;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;
        bytes memory recoverySig =
            _recoverAccountSig(leafIndex, newAuth, newCommitment, nonce, RECOVERY_OLD_PRIVATE_KEY);
        registry.recoverAccount(
            leafIndex, newAuth, newCommitment, OFFCHAIN_SIGNER_COMMITMENT, newCommitment, recoverySig, nonce
        );

        // Prev-update mapping cleared.
        (address prev, uint256 invalidAfter) = registry.getPreviousRecoveryAgentUpdate(leafIndex);
        assertEq(prev, address(0));
        assertEq(invalidAfter, 0);

        // New authenticator installed with bumped recovery counter.
        assertEq(PackedAccountData.leafIndex(registry.getPackedAccountData(newAuth)), leafIndex);
        assertEq(PackedAccountData.recoveryCounter(registry.getPackedAccountData(newAuth)), 1);
    }

    function test_RecoverAccount_DuringWindow_NewAgentSignatureFails() public {
        uint64 leafIndex = _createAccount(auth1, recoveryOld);
        bytes memory updateSig = _updateRecoveryAgentSig(leafIndex, recoveryNew, 0, AUTH1_PRIVATE_KEY);
        registry.updateRecoveryAgent(leafIndex, recoveryNew, updateSig, 0);

        address newAuth = address(0xBEE1);
        uint256 nonce = 1;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;
        bytes memory recoverySig =
            _recoverAccountSig(leafIndex, newAuth, newCommitment, nonce, RECOVERY_NEW_PRIVATE_KEY);

        vm.expectRevert(IWorldIDRegistry.InvalidSignature.selector);
        registry.recoverAccount(
            leafIndex, newAuth, newCommitment, OFFCHAIN_SIGNER_COMMITMENT, newCommitment, recoverySig, nonce
        );
    }

    function test_RecoverAccount_AfterWindow_UsesNewAgent() public {
        uint64 leafIndex = _createAccount(auth1, recoveryOld);
        uint256 cooldown = registry.getRecoveryAgentUpdateCooldown();

        bytes memory updateSig = _updateRecoveryAgentSig(leafIndex, recoveryNew, 0, AUTH1_PRIVATE_KEY);
        registry.updateRecoveryAgent(leafIndex, recoveryNew, updateSig, 0);

        skip(cooldown + 1);

        address newAuth = address(0xBEE1);
        uint256 nonce = 1;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;
        bytes memory recoverySig =
            _recoverAccountSig(leafIndex, newAuth, newCommitment, nonce, RECOVERY_NEW_PRIVATE_KEY);

        registry.recoverAccount(
            leafIndex, newAuth, newCommitment, OFFCHAIN_SIGNER_COMMITMENT, newCommitment, recoverySig, nonce
        );

        assertEq(PackedAccountData.leafIndex(registry.getPackedAccountData(newAuth)), leafIndex);
    }

    function test_RecoverAccount_AfterWindow_PrevAgentFails() public {
        uint64 leafIndex = _createAccount(auth1, recoveryOld);
        uint256 cooldown = registry.getRecoveryAgentUpdateCooldown();

        bytes memory updateSig = _updateRecoveryAgentSig(leafIndex, recoveryNew, 0, AUTH1_PRIVATE_KEY);
        registry.updateRecoveryAgent(leafIndex, recoveryNew, updateSig, 0);
        skip(cooldown + 1);

        address newAuth = address(0xBEE1);
        uint256 nonce = 1;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;
        bytes memory recoverySig =
            _recoverAccountSig(leafIndex, newAuth, newCommitment, nonce, RECOVERY_OLD_PRIVATE_KEY);

        vm.expectRevert(IWorldIDRegistry.InvalidSignature.selector);
        registry.recoverAccount(
            leafIndex, newAuth, newCommitment, OFFCHAIN_SIGNER_COMMITMENT, newCommitment, recoverySig, nonce
        );
    }

    function test_RecoverAccount_NoPendingUpdate_UsesCurrentAgent() public {
        uint64 leafIndex = _createAccount(auth1, recoveryOld);

        address newAuth = address(0xBEE1);
        uint256 nonce = 0;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;
        bytes memory recoverySig =
            _recoverAccountSig(leafIndex, newAuth, newCommitment, nonce, RECOVERY_OLD_PRIVATE_KEY);

        registry.recoverAccount(
            leafIndex, newAuth, newCommitment, OFFCHAIN_SIGNER_COMMITMENT, newCommitment, recoverySig, nonce
        );

        assertEq(PackedAccountData.leafIndex(registry.getPackedAccountData(newAuth)), leafIndex);
        assertEq(registry.getRecoveryCounter(leafIndex), 1);
    }

    ////////////////////////////////////////////////////////////
    //                   Attack mitigation                    //
    ////////////////////////////////////////////////////////////

    function test_AttackMitigation_MaliciousUpdateClearedByRecovery() public {
        // Compromised authenticator `auth1` initiates a Recovery Agent swap to `recoveryAttacker`.
        uint64 leafIndex = _createAccount(auth1, recoveryOld);
        bytes memory attackerSig = _updateRecoveryAgentSig(leafIndex, recoveryAttacker, 0, AUTH1_PRIVATE_KEY);
        registry.updateRecoveryAgent(leafIndex, recoveryAttacker, attackerSig, 0);

        // On-chain agent is now the attacker, but the revert window keeps the legitimate agent as the
        // only valid recovery signer. True owner recovers the account via the previous (legitimate) agent.
        address newAuth = address(0xBEE1);
        uint256 nonce = 1;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;
        bytes memory recoverySig =
            _recoverAccountSig(leafIndex, newAuth, newCommitment, nonce, RECOVERY_OLD_PRIVATE_KEY);

        registry.recoverAccount(
            leafIndex, newAuth, newCommitment, OFFCHAIN_SIGNER_COMMITMENT, newCommitment, recoverySig, nonce
        );

        // Attacker's mapping entry is cleared. Note the on-chain recovery agent is still `recoveryAttacker`
        // at this point — the user must issue a fresh `updateRecoveryAgent` to restore their own agent.
        // The critical property is that the attacker's update is no longer "protected" by a revert window.
        (address prev, uint256 invalidAfter) = registry.getPreviousRecoveryAgentUpdate(leafIndex);
        assertEq(prev, address(0));
        assertEq(invalidAfter, 0);
    }

    ////////////////////////////////////////////////////////////
    //                 Deprecated V1 methods                  //
    ////////////////////////////////////////////////////////////

    function test_InitiateRecoveryAgentUpdate_RevertsMethodUnsupported() public {
        uint64 leafIndex = _createAccount(auth1, recoveryOld);
        vm.expectRevert(IWorldIDRegistryV2.MethodUnsupported.selector);
        registry.initiateRecoveryAgentUpdate(leafIndex, recoveryNew, bytes(""), 0);
    }

    function test_CancelRecoveryAgentUpdate_RevertsMethodUnsupported() public {
        uint64 leafIndex = _createAccount(auth1, recoveryOld);
        vm.expectRevert(IWorldIDRegistryV2.MethodUnsupported.selector);
        registry.cancelRecoveryAgentUpdate(leafIndex, bytes(""), 0);
    }

    function test_ExecuteRecoveryAgentUpdate_RevertsMethodUnsupported() public {
        uint64 leafIndex = _createAccount(auth1, recoveryOld);
        vm.expectRevert(IWorldIDRegistryV2.MethodUnsupported.selector);
        registry.executeRecoveryAgentUpdate(leafIndex);
    }

    function test_GetPendingRecoveryAgentUpdate_RevertsMethodUnsupported() public {
        uint64 leafIndex = _createAccount(auth1, recoveryOld);
        vm.expectRevert(IWorldIDRegistryV2.MethodUnsupported.selector);
        registry.getPendingRecoveryAgentUpdate(leafIndex);
    }
}

/// @title Cross-version sanity: a V1 pending update is orphaned (but harmless) after upgrade to V2.
contract WorldIDRegistryV2WIP102OrphanTest is Test {
    uint256 constant WIP102_ORPHAN_AUTH1_PRIVATE_KEY = 0xA1;
    uint256 constant WIP102_ORPHAN_OFFCHAIN_SIGNER_COMMITMENT = 0x1234567890;

    function test_V1PendingUpdateOrphanedAfterUpgrade() public {
        address auth1 = vm.addr(WIP102_ORPHAN_AUTH1_PRIVATE_KEY);
        address recoveryOld = address(0xEC01);
        address recoveryLegacyPending = address(0xEC0F);
        address recoveryPostUpgrade = address(0xEC02);

        // Deploy V1 and create a pending update under the V1 three-tx flow.
        WorldIDRegistry implementationV1 = new WorldIDRegistry();
        ERC20Mock feeToken = new ERC20Mock();
        bytes memory initData =
            abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30, address(this), feeToken, 0);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementationV1), initData);
        WorldIDRegistry v1 = WorldIDRegistry(address(proxy));

        address[] memory addrs = new address[](1);
        addrs[0] = auth1;
        uint256[] memory pubkeys = new uint256[](1);
        pubkeys[0] = 0;
        v1.createAccount(recoveryOld, addrs, pubkeys, WIP102_ORPHAN_OFFCHAIN_SIGNER_COMMITMENT);
        uint64 leafIndex = 1;

        bytes memory v1InitiateSig = _eip712SignV1(
            v1,
            v1.INITIATE_RECOVERY_AGENT_UPDATE_TYPEHASH(),
            abi.encode(leafIndex, recoveryLegacyPending, uint256(0)),
            WIP102_ORPHAN_AUTH1_PRIVATE_KEY
        );
        v1.initiateRecoveryAgentUpdate(leafIndex, recoveryLegacyPending, v1InitiateSig, 0);

        (address legacyPending, uint256 legacyExecuteAfter) = v1.getPendingRecoveryAgentUpdate(leafIndex);
        assertEq(legacyPending, recoveryLegacyPending);
        assertTrue(legacyExecuteAfter > 0);

        // Upgrade to V2.
        WorldIDRegistryV2 implementationV2 = new WorldIDRegistryV2();
        v1.upgradeToAndCall(address(implementationV2), "");
        WorldIDRegistryV2 v2 = WorldIDRegistryV2(address(proxy));

        // V1 pending-update view is loudly deprecated — consumers must migrate to
        // `getPreviousRecoveryAgentUpdate`. The underlying V1 storage slot is not cleared.
        vm.expectRevert(IWorldIDRegistryV2.MethodUnsupported.selector);
        v2.getPendingRecoveryAgentUpdate(leafIndex);

        // The new V2 flow works on the same leaf without tripping over the orphaned slot.
        // Nonce is now 1 (V1 initiate incremented it).
        bytes memory v2UpdateSig = _eip712SignV1(
            WorldIDRegistry(address(v2)),
            v2.UPDATE_RECOVERY_AGENT_TYPEHASH(),
            abi.encode(leafIndex, recoveryPostUpgrade, uint256(1)),
            WIP102_ORPHAN_AUTH1_PRIVATE_KEY
        );
        v2.updateRecoveryAgent(leafIndex, recoveryPostUpgrade, v2UpdateSig, 1);

        // Effective agent during the fresh revert window is still the original recoveryOld.
        assertEq(v2.getRecoveryAgent(leafIndex), recoveryOld);
        (address prev,) = v2.getPreviousRecoveryAgentUpdate(leafIndex);
        assertEq(prev, recoveryOld);
    }

    function _eip712SignV1(WorldIDRegistry reg, bytes32 typeHash, bytes memory data, uint256 privateKey)
        private
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(abi.encodePacked(typeHash, data));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", reg.domainSeparatorV4(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
