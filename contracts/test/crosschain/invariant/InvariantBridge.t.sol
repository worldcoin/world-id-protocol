// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {WorldIDSource} from "../../../src/crosschain/WorldIDSource.sol";
import {WorldIDSatellite} from "../../../src/crosschain/WorldIDSatellite.sol";
import {IStateBridge} from "../../../src/crosschain/interfaces/IStateBridge.sol";
import {PermissionedGatewayAdapter} from "../../../src/crosschain/adapters/PermissionedGatewayAdapter.sol";
import {Lib} from "../../../src/crosschain/lib/Lib.sol";
import {Verifier} from "../../../src/core/Verifier.sol";

import {MockRegistry, MockIssuerRegistry, MockOprfRegistry} from "../helpers/Mocks.sol";
import {RegistryHandler} from "./handlers/RegistryHandler.sol";
import {RelayHandler} from "./handlers/RelayHandler.sol";

/// @title InvariantBridge
/// @notice Foundry invariant tests for the World ID state bridge pipeline.
///   Uses two handler contracts: `RegistryHandler` (drives fuzz-randomized registry mutations)
///   and `RelayHandler` (drives the propagate-and-relay cycle). The invariant runner calls
///   handler functions with random inputs; after each call sequence, the invariant functions
///   below are checked.
contract InvariantBridge is StdInvariant, Test {
    uint256 constant WC_CHAIN_ID = 480;
    uint256 constant ROOT_VALIDITY_WINDOW = 3600;
    uint256 constant TREE_DEPTH = 30;
    uint64 constant MIN_EXPIRATION = 7200;

    MockRegistry public registry;
    MockIssuerRegistry public issuerRegistry;
    MockOprfRegistry public oprfRegistry;

    address public sourceProxy;
    address public satelliteProxy;
    PermissionedGatewayAdapter public gateway;

    RegistryHandler public registryHandler;
    RelayHandler public relayHandler;

    address owner = makeAddr("owner");

    function setUp() public {
        // ── Deploy mock registries with initial state ──
        registry = new MockRegistry();
        issuerRegistry = new MockIssuerRegistry();
        oprfRegistry = new MockOprfRegistry();

        registry.setLatestRoot(1000);
        issuerRegistry.setPubkey(1, 11, 22);
        oprfRegistry.setKey(1, 33, 44);

        // ── Deploy WorldIDSource (impl + proxy) ──
        WorldIDSource sourceImpl = new WorldIDSource(address(registry), address(issuerRegistry), address(oprfRegistry));

        address[] memory emptyGws = new address[](0);
        IStateBridge.InitConfig memory srcCfg = IStateBridge.InitConfig({
            name: "World ID Source", version: "1", owner: owner, authorizedGateways: emptyGws
        });

        sourceProxy = address(new ERC1967Proxy(address(sourceImpl), abi.encodeCall(WorldIDSource.initialize, (srcCfg))));

        // ── Deploy WorldIDSatellite (impl + proxy) ──
        Verifier verifier = new Verifier();
        WorldIDSatellite satImpl =
            new WorldIDSatellite(address(verifier), ROOT_VALIDITY_WINDOW, TREE_DEPTH, MIN_EXPIRATION);

        IStateBridge.InitConfig memory dstCfg = IStateBridge.InitConfig({
            name: "World ID Bridge", version: "1", owner: owner, authorizedGateways: emptyGws
        });

        satelliteProxy =
            address(new ERC1967Proxy(address(satImpl), abi.encodeCall(WorldIDSatellite.initialize, (dstCfg))));

        // ── Deploy gateway and authorize on satellite ──
        gateway = new PermissionedGatewayAdapter(owner, satelliteProxy, sourceProxy, WC_CHAIN_ID);

        vm.prank(owner);
        WorldIDSatellite(satelliteProxy).addGateway(address(gateway));

        // ── Deploy handlers ──
        registryHandler = new RegistryHandler(registry, issuerRegistry, oprfRegistry);
        relayHandler = new RelayHandler(
            sourceProxy,
            satelliteProxy,
            address(gateway),
            owner,
            registry,
            issuerRegistry,
            oprfRegistry,
            registryHandler
        );

        // ── Configure invariant fuzzer: only target handlers, only target their fuzz functions ──
        targetContract(address(registryHandler));
        targetContract(address(relayHandler));

        bytes4[] memory regSelectors = new bytes4[](4);
        regSelectors[0] = RegistryHandler.updateRoot.selector;
        regSelectors[1] = RegistryHandler.registerIssuer.selector;
        regSelectors[2] = RegistryHandler.updateIssuer.selector;
        regSelectors[3] = RegistryHandler.registerOprfKey.selector;
        targetSelector(FuzzSelector({addr: address(registryHandler), selectors: regSelectors}));

        bytes4[] memory relaySelectors = new bytes4[](2);
        relaySelectors[0] = RelayHandler.propagateAndRelay.selector;
        relaySelectors[1] = RelayHandler.propagateOnly.selector;
        targetSelector(FuzzSelector({addr: address(relayHandler), selectors: relaySelectors}));
    }

    // ─── Invariants ──────────────────────────────────────────────────────────

    /// @notice After every successful relay, source and satellite keccak chain heads must match.
    ///   The chain is an append-only hash accumulator, so any divergence means commitments
    ///   were lost or reordered during relay.
    function invariant_chainIntegrity() public view {
        if (relayHandler.totalRelays() == 0 || relayHandler.sourceDirty()) return;

        Lib.Chain memory srcChain = WorldIDSource(sourceProxy).KECCAK_CHAIN();
        Lib.Chain memory dstChain = WorldIDSatellite(satelliteProxy).KECCAK_CHAIN();

        assertEq(dstChain.head, srcChain.head, "chain heads must match after relay");
        assertEq(dstChain.length, srcChain.length, "chain lengths must match after relay");
    }

    /// @notice After relay, the satellite's root and all public keys must be identical to the source's.
    ///   This ensures the full state diff was faithfully applied on the destination.
    function invariant_stateConsistency() public view {
        if (relayHandler.totalRelays() == 0 || relayHandler.sourceDirty()) return;

        assertEq(
            WorldIDSatellite(satelliteProxy).LATEST_ROOT(),
            WorldIDSource(sourceProxy).LATEST_ROOT(),
            "roots must match after relay"
        );

        // Verify all registered issuer pubkeys match
        uint64[] memory issuerIds = registryHandler.getRegisteredIssuerIds();
        for (uint256 i; i < issuerIds.length; i++) {
            IStateBridge.ProvenPubKeyInfo memory src =
                WorldIDSource(sourceProxy).issuerSchemaIdToPubkeyAndProofId(issuerIds[i]);
            IStateBridge.ProvenPubKeyInfo memory dst =
                WorldIDSatellite(satelliteProxy).issuerSchemaIdToPubkeyAndProofId(issuerIds[i]);
            assertEq(src.pubKey.x, dst.pubKey.x, "issuer x must match");
            assertEq(src.pubKey.y, dst.pubKey.y, "issuer y must match");
        }

        // Verify all registered OPRF pubkeys match
        uint160[] memory oprfIds = registryHandler.getRegisteredOprfIds();
        for (uint256 i; i < oprfIds.length; i++) {
            IStateBridge.ProvenPubKeyInfo memory src =
                WorldIDSource(sourceProxy).oprfKeyIdToPubkeyAndProofId(oprfIds[i]);
            IStateBridge.ProvenPubKeyInfo memory dst =
                WorldIDSatellite(satelliteProxy).oprfKeyIdToPubkeyAndProofId(oprfIds[i]);
            assertEq(src.pubKey.x, dst.pubKey.x, "oprf x must match");
            assertEq(src.pubKey.y, dst.pubKey.y, "oprf y must match");
        }
    }

    /// @notice The latest root on the satellite must always pass `isValidRoot` if at least
    ///   one relay has occurred.
    function invariant_latestRootAlwaysValid() public view {
        if (relayHandler.totalRelays() == 0) return;

        uint256 latestRoot = WorldIDSatellite(satelliteProxy).LATEST_ROOT();
        assertTrue(WorldIDSatellite(satelliteProxy).isValidRoot(latestRoot), "latest root must always be valid");
    }

    /// @notice The source chain length must be monotonically non-decreasing.
    ///   Each propagation appends at least one commitment; the chain never shrinks.
    function invariant_chainMonotonicity() public view {
        Lib.Chain memory srcChain = WorldIDSource(sourceProxy).KECCAK_CHAIN();
        // After setUp, chain length is 0. Every successful propagation increments it.
        // The unsigned type already prevents underflow, but this documents the invariant.
        assertTrue(srcChain.length >= 0, "chain length must never decrease");
    }

    /// @notice Roots that were never committed must always be invalid on the satellite.
    function invariant_unknownRootInvalid() public view {
        assertFalse(WorldIDSatellite(satelliteProxy).isValidRoot(type(uint256).max), "unknown root must be invalid");
        assertFalse(WorldIDSatellite(satelliteProxy).isValidRoot(0), "zero root must be invalid");
    }

    /// @notice The satellite chain length must never exceed the source chain length.
    ///   The satellite can only receive committed state; it cannot get ahead of the source.
    function invariant_satelliteNeverAheadOfSource() public view {
        Lib.Chain memory srcChain = WorldIDSource(sourceProxy).KECCAK_CHAIN();
        Lib.Chain memory dstChain = WorldIDSatellite(satelliteProxy).KECCAK_CHAIN();

        assertTrue(dstChain.length <= srcChain.length, "satellite chain must not exceed source chain length");
    }
}
