// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {WorldIDRegistry} from "../../src/core/WorldIDRegistry.sol";
import {WorldIDRegistryV2} from "../../src/core/WorldIDRegistryV2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";

/**
 * @title WorldIDRegistryV2RaceConditionTest
 * @notice Demonstrates that V1 has a root validity race condition and V2 fixes it.
 * @dev The race condition arises when a root outlives its creation-time TTL while still being the
 *      latest root (valid due to the `root == _latestRoot` fast-path). The moment a new root is
 *      recorded, V1 immediately invalidates the old root because its creation-time TTL is already
 *      exhausted. V2 fixes this by recording when a root was *replaced* and measuring TTL from that
 *      point instead, guaranteeing a full validity window after each root transition.
 */
contract WorldIDRegistryV2RaceConditionTest is Test {
    ERC1967Proxy public proxy;

    uint256 constant ROOT_VALIDITY_WINDOW = 3600;

    function setUp() public {
        // Deploy V1 implementation behind a proxy
        WorldIDRegistry implementationV1 = new WorldIDRegistry();
        ERC20Mock feeToken = new ERC20Mock();
        bytes memory initData =
            abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30, address(0xAAA), feeToken, 0);
        proxy = new ERC1967Proxy(address(implementationV1), initData);
    }

    /// @dev Helper: creates an account so the Merkle root changes.
    function _createAccount(address authenticator, uint256 commitment) internal {
        address[] memory auths = new address[](1);
        auths[0] = authenticator;
        uint256[] memory pubkeys = new uint256[](1);
        pubkeys[0] = 0;
        WorldIDRegistry(address(proxy)).createAccount(address(0xABCD), auths, pubkeys, commitment);
    }

    /**
     * @notice V1: a root that outlived its creation-time TTL is immediately invalid the moment
     *         a new root is recorded, leaving zero grace period for proof verification.
     */
    function test_V1_RootInvalidImmediatelyOnceReplacedAfterTTL() public {
        WorldIDRegistry registry = WorldIDRegistry(address(proxy));

        _createAccount(address(0x111), 0xAAAA);
        uint256 rootA = registry.currentRoot();

        // Move forward in time so rootA outlives its TTL
        vm.warp(ROOT_VALIDITY_WINDOW + 2);
        assertTrue(registry.isValidRoot(rootA), "rootA is still valid: it is the latest root");

        // Record a new root - rootA is now historical
        _createAccount(address(0x222), 0xBBBB);

        // rootA's creation-time TTL is already past, so it expires the instant it is replaced
        assertFalse(registry.isValidRoot(rootA), "V1: rootA invalid immediately after replacement");
    }

    /**
     * @notice V2 fix: recording a new root stamps the old root with its replacement timestamp,
     *         giving it a full validity window from that moment.
     */
    function test_V2_RootRemainsValidAfterReplacementWhenTTLExpired() public {
        // Upgrade proxy to V2 before any accounts are created
        WorldIDRegistryV2 implementationV2 = new WorldIDRegistryV2();
        WorldIDRegistry(address(proxy)).upgradeToAndCall(address(implementationV2), "");
        WorldIDRegistryV2 registry = WorldIDRegistryV2(address(proxy));

        _createAccount(address(0x111), 0xAAAA);
        uint256 rootA = registry.currentRoot();

        // Move forward in time so rootA outlives the TTL (as it would do in V1)
        vm.warp(ROOT_VALIDITY_WINDOW + 2);
        assertTrue(registry.isValidRoot(rootA), "rootA is still valid: it is the latest root");

        // Record a new root — V2's _recordCurrentRoot sets _rootToValidityTimestamp[rootA] = 3602
        _createAccount(address(0x222), 0xBBBB);
        assertTrue(rootA != registry.currentRoot(), "a new root should have been recorded");

        // V2 FIX: rootA's replacement-time TTL starts at T=3602, expires at T=7202
        assertTrue(registry.isValidRoot(rootA), "V2 FIX: rootA valid, full TTL window starts at replacement");

        // Verify rootA eventually expires: warp past T = 3602 + 3600 + 1 = 7203
        vm.warp(ROOT_VALIDITY_WINDOW + 2 + ROOT_VALIDITY_WINDOW + 1);
        assertFalse(registry.isValidRoot(rootA), "rootA expires after full window from replacement time");
    }
}

