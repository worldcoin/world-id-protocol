// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {WorldIDRegistry} from "../../src/core/WorldIDRegistry.sol";
import {WorldIDRegistryV2} from "../../src/core/WorldIDRegistryV2Unreleased.sol";
import {IWorldIDRegistry} from "../../src/core/interfaces/IWorldIDRegistry.sol";
import {IWorldIDRegistryV2} from "../../src/core/interfaces/IWorldIDRegistryV2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";

/// @title Cross-version tests for V1 pending Recovery Agent updates migrating to V2 semantics.
contract WorldIDRegistryV2MigrationTest is Test {
    uint256 constant WIP102_MIGRATION_AUTH1_PRIVATE_KEY = 0xA1;
    uint256 constant WIP102_MIGRATION_RECOVERY_OLD_PRIVATE_KEY = 0xEC01;
    uint256 constant WIP102_MIGRATION_OFFCHAIN_SIGNER_COMMITMENT = 0x1234567890;

    /// @dev V1 pending updates are invisible after upgrade, and a fresh V2 update clears the legacy pending slot.
    function test_V1PendingUpdateInvisibleAfterUpgrade() public {
        address auth1 = vm.addr(WIP102_MIGRATION_AUTH1_PRIVATE_KEY);
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
        v1.createAccount(recoveryOld, addrs, pubkeys, WIP102_MIGRATION_OFFCHAIN_SIGNER_COMMITMENT);
        uint64 leafIndex = 1;

        bytes memory v1InitiateSig = _eip712SignV1(
            v1,
            v1.INITIATE_RECOVERY_AGENT_UPDATE_TYPEHASH(),
            abi.encode(leafIndex, recoveryLegacyPending, uint256(0)),
            WIP102_MIGRATION_AUTH1_PRIVATE_KEY
        );
        v1.initiateRecoveryAgentUpdate(leafIndex, recoveryLegacyPending, v1InitiateSig, 0);

        (address legacyPending, uint256 legacyExecuteAfter) = v1.getPendingRecoveryAgentUpdate(leafIndex);
        assertEq(legacyPending, recoveryLegacyPending);
        assertTrue(legacyExecuteAfter > 0);

        // Upgrade to V2.
        WorldIDRegistryV2 implementationV2 = new WorldIDRegistryV2();
        v1.upgradeToAndCall(address(implementationV2), "");
        WorldIDRegistryV2 v2 = WorldIDRegistryV2(address(proxy));

        // The V2 getter only reports active V2 update state. Legacy V1 state remains
        // migratable, but is not exposed as if it already had V2 semantics.
        (address pendingBeforeMigration, uint256 validAfterBeforeMigration) =
            v2.getPendingRecoveryAgentUpdate(leafIndex);
        assertEq(pendingBeforeMigration, address(0));
        assertEq(validAfterBeforeMigration, 0);

        // The new V2 flow works on the same leaf without tripping over the legacy slot.
        // Nonce is now 1 (V1 initiate incremented it).
        bytes memory v2UpdateSig = _eip712SignV1(
            WorldIDRegistry(address(v2)),
            // WIP-102: `updateRecoveryAgent` verifies against V1's INITIATE typehash.
            v2.INITIATE_RECOVERY_AGENT_UPDATE_TYPEHASH(),
            abi.encode(leafIndex, recoveryPostUpgrade, uint256(1)),
            WIP102_MIGRATION_AUTH1_PRIVATE_KEY
        );
        v2.updateRecoveryAgent(leafIndex, recoveryPostUpgrade, v2UpdateSig, 1);

        // Effective agent during the fresh revert window is still the original recoveryOld.
        assertEq(v2.getRecoveryAgent(leafIndex), recoveryOld);
        (address prev,) = v2.getPreviousRecoveryAgentUpdate(leafIndex);
        assertEq(prev, recoveryOld);

        // A fresh V2 update supersedes and clears the legacy pending state.
        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.NoPendingRecoveryAgentUpdate.selector, leafIndex));
        v2.migrateLegacyRecoveryAgentUpdate(leafIndex);
    }

    /// @dev Migrating before `executeAfter` preserves that timestamp as V2's revert-window deadline.
    function test_MigrateLegacyRecoveryAgentUpdate_PreservesExecuteAfter() public {
        address recoveryOld = vm.addr(WIP102_MIGRATION_RECOVERY_OLD_PRIVATE_KEY);
        address recoveryLegacyPending = address(0xEC0F);

        (WorldIDRegistry v1, uint64 leafIndex, uint256 legacyExecuteAfter) =
            _deployV1WithPendingUpdate(recoveryOld, recoveryLegacyPending);
        WorldIDRegistryV2 v2 = _upgradeToV2(v1);

        vm.expectEmit(true, true, true, true);
        emit IWorldIDRegistryV2.RecoveryAgentUpdated(leafIndex, recoveryOld, recoveryLegacyPending, legacyExecuteAfter);
        v2.migrateLegacyRecoveryAgentUpdate(leafIndex);

        assertEq(v2.getRecoveryAgent(leafIndex), recoveryOld);
        (address prev, uint256 invalidAfter) = v2.getPreviousRecoveryAgentUpdate(leafIndex);
        assertEq(prev, recoveryOld);
        assertEq(invalidAfter, legacyExecuteAfter);

        (address pendingAgent, uint256 validAfter) = v2.getPendingRecoveryAgentUpdate(leafIndex);
        assertEq(pendingAgent, recoveryLegacyPending);
        assertEq(validAfter, legacyExecuteAfter);

        vm.warp(legacyExecuteAfter + 1);
        assertEq(v2.getRecoveryAgent(leafIndex), recoveryLegacyPending);
    }

    /// @dev Migrating after `executeAfter` immediately makes the legacy pending agent effective.
    function test_MigrateLegacyRecoveryAgentUpdate_ExecutesIfExecuteAfterElapsed() public {
        address recoveryOld = vm.addr(WIP102_MIGRATION_RECOVERY_OLD_PRIVATE_KEY);
        address recoveryLegacyPending = address(0xEC0F);

        (WorldIDRegistry v1, uint64 leafIndex, uint256 legacyExecuteAfter) =
            _deployV1WithPendingUpdate(recoveryOld, recoveryLegacyPending);
        skip(v1.getRecoveryAgentUpdateCooldown() + 1);
        assertGt(block.timestamp, legacyExecuteAfter);

        WorldIDRegistryV2 v2 = _upgradeToV2(v1);
        // Once `executeAfter` has elapsed there is no revert window, so the emitted
        // `invalidAfter` must be `0` (matching `getPreviousRecoveryAgentUpdate`), not a
        // stale past-timestamp.
        vm.expectEmit(true, true, true, true);
        emit IWorldIDRegistryV2.RecoveryAgentUpdated(leafIndex, recoveryOld, recoveryLegacyPending, 0);
        v2.migrateLegacyRecoveryAgentUpdate(leafIndex);

        assertEq(v2.getRecoveryAgent(leafIndex), recoveryLegacyPending);
        (address prev, uint256 invalidAfter) = v2.getPreviousRecoveryAgentUpdate(leafIndex);
        assertEq(prev, address(0));
        assertEq(invalidAfter, 0);
    }

    /// @dev `getPendingRecoveryAgentUpdate` only reports legacy updates after migration into V2 state.
    function test_GetPendingRecoveryAgentUpdate_OnlyReportsMigratedV2State() public {
        address recoveryOld = vm.addr(WIP102_MIGRATION_RECOVERY_OLD_PRIVATE_KEY);
        address recoveryLegacyPending = address(0xEC0F);

        (WorldIDRegistry v1, uint64 leafIndex, uint256 legacyExecuteAfter) =
            _deployV1WithPendingUpdate(recoveryOld, recoveryLegacyPending);
        WorldIDRegistryV2 v2 = _upgradeToV2(v1);

        (address pendingAgent, uint256 validAfter) = v2.getPendingRecoveryAgentUpdate(leafIndex);
        assertEq(pendingAgent, address(0));
        assertEq(validAfter, 0);

        // After migration the V1 entry is cleared and the V2 active-update state takes over.
        v2.migrateLegacyRecoveryAgentUpdate(leafIndex);
        (pendingAgent, validAfter) = v2.getPendingRecoveryAgentUpdate(leafIndex);
        // During the (preserved) revert window, V2 active-update state is reported.
        assertEq(pendingAgent, recoveryLegacyPending);
        assertEq(validAfter, legacyExecuteAfter);

        // Past the revert window, both views return (0, 0).
        vm.warp(legacyExecuteAfter + 1);
        (pendingAgent, validAfter) = v2.getPendingRecoveryAgentUpdate(leafIndex);
        assertEq(pendingAgent, address(0));
        assertEq(validAfter, 0);
    }

    /// @dev Recovering in V2 clears any legacy V1 pending update so it cannot be migrated later.
    function test_RecoverAccount_ClearsLegacyPendingUpdate() public {
        address recoveryOld = vm.addr(WIP102_MIGRATION_RECOVERY_OLD_PRIVATE_KEY);
        address recoveryLegacyPending = address(0xEC0F);

        (WorldIDRegistry v1, uint64 leafIndex,) = _deployV1WithPendingUpdate(recoveryOld, recoveryLegacyPending);
        WorldIDRegistryV2 v2 = _upgradeToV2(v1);

        address newAuth = address(0xBEE1);
        uint256 newCommitment = WIP102_MIGRATION_OFFCHAIN_SIGNER_COMMITMENT + 1;
        bytes memory recoverySig = _eip712SignV1(
            WorldIDRegistry(address(v2)),
            v2.RECOVER_ACCOUNT_TYPEHASH(),
            abi.encode(leafIndex, newAuth, newCommitment, newCommitment, uint256(1)),
            WIP102_MIGRATION_RECOVERY_OLD_PRIVATE_KEY
        );
        v2.recoverAccount(
            leafIndex,
            newAuth,
            newCommitment,
            WIP102_MIGRATION_OFFCHAIN_SIGNER_COMMITMENT,
            newCommitment,
            recoverySig,
            1
        );

        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.NoPendingRecoveryAgentUpdate.selector, leafIndex));
        v2.migrateLegacyRecoveryAgentUpdate(leafIndex);
    }

    function _deployV1WithPendingUpdate(address recoveryOld, address recoveryLegacyPending)
        private
        returns (WorldIDRegistry v1, uint64 leafIndex, uint256 legacyExecuteAfter)
    {
        address auth1 = vm.addr(WIP102_MIGRATION_AUTH1_PRIVATE_KEY);
        WorldIDRegistry implementationV1 = new WorldIDRegistry();
        ERC20Mock feeToken = new ERC20Mock();
        bytes memory initData =
            abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30, address(this), feeToken, 0);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementationV1), initData);
        v1 = WorldIDRegistry(address(proxy));

        address[] memory addrs = new address[](1);
        addrs[0] = auth1;
        uint256[] memory pubkeys = new uint256[](1);
        pubkeys[0] = 0;
        v1.createAccount(recoveryOld, addrs, pubkeys, WIP102_MIGRATION_OFFCHAIN_SIGNER_COMMITMENT);
        leafIndex = 1;

        bytes memory v1InitiateSig = _eip712SignV1(
            v1,
            v1.INITIATE_RECOVERY_AGENT_UPDATE_TYPEHASH(),
            abi.encode(leafIndex, recoveryLegacyPending, uint256(0)),
            WIP102_MIGRATION_AUTH1_PRIVATE_KEY
        );
        v1.initiateRecoveryAgentUpdate(leafIndex, recoveryLegacyPending, v1InitiateSig, 0);

        (address legacyPending, uint256 executeAfter) = v1.getPendingRecoveryAgentUpdate(leafIndex);
        assertEq(legacyPending, recoveryLegacyPending);
        assertTrue(executeAfter > 0);
        legacyExecuteAfter = executeAfter;
    }

    function _upgradeToV2(WorldIDRegistry v1) private returns (WorldIDRegistryV2 v2) {
        WorldIDRegistryV2 implementationV2 = new WorldIDRegistryV2();
        v1.upgradeToAndCall(address(implementationV2), "");
        v2 = WorldIDRegistryV2(address(v1));
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
