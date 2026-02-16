// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {InteroperableAddress} from "openzeppelin-contracts/contracts/utils/draft-InteroperableAddress.sol";

import {PermissionedGatewayAdapter} from "@core/adapters/PermissionedGatewayAdapter.sol";
import {WorldIDSource} from "@core/Source.sol";
import {WorldIDSatellite} from "@core/Satellite.sol";
import {IStateBridge} from "@core/types/IStateBridge.sol";
import {Lib} from "@lib-core/Lib.sol";
import {Verifier} from "@world-id/Verifier.sol";

import {MockRegistry, MockIssuerRegistry, MockOprfRegistry} from "./helpers/Mocks.sol";

/// @title E2ETest
/// @notice End-to-end tests for the full state bridge pipeline:
///   registry mutation → WorldIDSource.propagateState → gateway relay → WorldIDSatellite state update.
contract E2ETest is Test {
    using InteroperableAddress for bytes;

    bytes4 constant UPDATE_ROOT_SELECTOR = bytes4(keccak256("updateRoot(uint256,uint256,bytes32)"));
    bytes4 constant SET_ISSUER_PUBKEY_SELECTOR = bytes4(keccak256("setIssuerPubkey(uint64,uint256,uint256,bytes32)"));
    bytes4 constant SET_OPRF_KEY_SELECTOR = bytes4(keccak256("setOprfKey(uint160,uint256,uint256,bytes32)"));

    uint256 constant WC_CHAIN_ID = 480;
    uint256 constant ROOT_VALIDITY_WINDOW = 3600;
    uint256 constant TREE_DEPTH = 30;
    uint64 constant MIN_EXPIRATION = 7200;

    address owner = makeAddr("owner");

    MockRegistry registry;
    MockIssuerRegistry issuerRegistry;
    MockOprfRegistry oprfRegistry;

    address sourceProxy;
    address satelliteProxy;

    PermissionedGatewayAdapter gateway;

    function setUp() public {
        // Deploy mock registries with initial state
        registry = new MockRegistry();
        issuerRegistry = new MockIssuerRegistry();
        oprfRegistry = new MockOprfRegistry();

        registry.setLatestRoot(1000);
        issuerRegistry.setPubkey(1, 11, 22);
        oprfRegistry.setKey(1, 33, 44);

        // Deploy WorldIDSource (impl + proxy)
        WorldIDSource sourceImpl = new WorldIDSource(address(registry), address(issuerRegistry), address(oprfRegistry));

        address[] memory emptyGws = new address[](0);
        IStateBridge.InitConfig memory srcCfg = IStateBridge.InitConfig({
            name: "World ID Source", version: "1", owner: owner, authorizedGateways: emptyGws
        });

        sourceProxy = address(new ERC1967Proxy(address(sourceImpl), abi.encodeCall(WorldIDSource.initialize, (srcCfg))));

        // Deploy WorldIDSatellite (impl + proxy)
        Verifier verifier = new Verifier();
        WorldIDSatellite satImpl =
            new WorldIDSatellite(address(verifier), ROOT_VALIDITY_WINDOW, TREE_DEPTH, MIN_EXPIRATION);

        IStateBridge.InitConfig memory dstCfg = IStateBridge.InitConfig({
            name: "World ID Bridge", version: "1", owner: owner, authorizedGateways: emptyGws
        });

        satelliteProxy =
            address(new ERC1967Proxy(address(satImpl), abi.encodeCall(WorldIDSatellite.initialize, (dstCfg))));

        // Deploy PermissionedGatewayAdapter and authorize it on satellite
        gateway = new PermissionedGatewayAdapter(owner, satelliteProxy, sourceProxy, WC_CHAIN_ID);

        vm.prank(owner);
        WorldIDSatellite(satelliteProxy).addGateway(address(gateway));
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    /// @dev Propagates state on source, returning the new chain head.
    function _propagate(uint64[] memory issuerIds, uint160[] memory oprfIds) internal returns (bytes32) {
        WorldIDSource(sourceProxy).propagateState(issuerIds, oprfIds);
        return WorldIDSource(sourceProxy).KECCAK_CHAIN().head;
    }

    /// @dev Builds commitment payload matching propagateState output for the given keys.
    function _buildPayload(uint64[] memory issuerIds, uint160[] memory oprfIds) internal view returns (bytes memory) {
        bytes32 blockHash = blockhash(block.number - 1);
        bytes32 proofId = bytes32(block.number);

        // Count how many actual changes there are
        uint256 count = 0;

        // Check root
        uint256 root = registry.latestRoot();
        if (root != WorldIDSource(sourceProxy).LATEST_ROOT()) count++;

        // Check issuers
        for (uint256 i; i < issuerIds.length; i++) {
            IStateBridge.ProvenPubKeyInfo memory stored =
                WorldIDSource(sourceProxy).issuerSchemaIdToPubkeyAndProofId(issuerIds[i]);
            MockIssuerRegistry.Pubkey memory key = issuerRegistry.issuerSchemaIdToPubkey(issuerIds[i]);
            if (key.x != stored.pubKey.x || key.y != stored.pubKey.y) count++;
        }

        // Check OPRFs
        for (uint256 i; i < oprfIds.length; i++) {
            IStateBridge.ProvenPubKeyInfo memory stored =
                WorldIDSource(sourceProxy).oprfKeyIdToPubkeyAndProofId(oprfIds[i]);
            MockOprfRegistry.RegisteredOprfPublicKey memory key = oprfRegistry.getOprfPublicKeyAndEpoch(oprfIds[i]);
            if (key.key.x != stored.pubKey.x || key.key.y != stored.pubKey.y) count++;
        }

        Lib.Commitment[] memory commits = new Lib.Commitment[](count);
        uint256 idx = 0;

        // Root
        if (root != WorldIDSource(sourceProxy).LATEST_ROOT()) {
            commits[idx++] = Lib.Commitment({
                blockHash: blockHash, data: abi.encodeWithSelector(UPDATE_ROOT_SELECTOR, root, block.timestamp, proofId)
            });
        }

        // Issuers
        for (uint256 i; i < issuerIds.length; i++) {
            IStateBridge.ProvenPubKeyInfo memory stored =
                WorldIDSource(sourceProxy).issuerSchemaIdToPubkeyAndProofId(issuerIds[i]);
            MockIssuerRegistry.Pubkey memory key = issuerRegistry.issuerSchemaIdToPubkey(issuerIds[i]);
            if (key.x != stored.pubKey.x || key.y != stored.pubKey.y) {
                commits[idx++] = Lib.Commitment({
                    blockHash: blockHash,
                    data: abi.encodeWithSelector(SET_ISSUER_PUBKEY_SELECTOR, issuerIds[i], key.x, key.y, proofId)
                });
            }
        }

        // OPRFs
        for (uint256 i; i < oprfIds.length; i++) {
            IStateBridge.ProvenPubKeyInfo memory stored =
                WorldIDSource(sourceProxy).oprfKeyIdToPubkeyAndProofId(oprfIds[i]);
            MockOprfRegistry.RegisteredOprfPublicKey memory key = oprfRegistry.getOprfPublicKeyAndEpoch(oprfIds[i]);
            if (key.key.x != stored.pubKey.x || key.key.y != stored.pubKey.y) {
                commits[idx++] = Lib.Commitment({
                    blockHash: blockHash,
                    data: abi.encodeWithSelector(SET_OPRF_KEY_SELECTOR, oprfIds[i], key.key.x, key.key.y, proofId)
                });
            }
        }

        return abi.encode(commits);
    }

    /// @dev Relays a chain head + commit payload through the permissioned gateway.
    function _relay(bytes32 chainHead, bytes memory commitPayload) internal {
        bytes4 attrSelector = bytes4(keccak256("chainHead(bytes32)"));
        bytes[] memory attributes = new bytes[](1);
        attributes[0] = abi.encodePacked(attrSelector, abi.encode(chainHead));

        bytes memory recipient = InteroperableAddress.formatEvmV1(block.chainid, satelliteProxy);

        vm.prank(owner);
        gateway.sendMessage(recipient, commitPayload, attributes);
    }

    /// @dev Full propagate-and-relay cycle: propagate on source, build payload, relay to satellite.
    function _propagateAndRelay(uint64[] memory issuerIds, uint160[] memory oprfIds) internal returns (bytes32) {
        bytes memory payload = _buildPayload(issuerIds, oprfIds);
        bytes32 head = _propagate(issuerIds, oprfIds);
        _relay(head, payload);
        return head;
    }

    /// @dev Create single-element arrays for common test case.
    function _singleIds() internal pure returns (uint64[] memory issuerIds, uint160[] memory oprfIds) {
        issuerIds = new uint64[](1);
        issuerIds[0] = 1;
        oprfIds = new uint160[](1);
        oprfIds[0] = 1;
    }

    // ─── Tests ───────────────────────────────────────────────────────────────

    /// @notice Full pipeline: seed → propagate → relay → verify root+keys.
    ///   Then update registries, second round, verify state advanced.
    ///   Then warp past ROOT_VALIDITY_WINDOW, verify old root expired but new root valid.
    function test_e2e_fullPipeline() public {
        (uint64[] memory issuerIds, uint160[] memory oprfIds) = _singleIds();

        // ── Round 1: initial propagation ──
        bytes32 head1 = _propagateAndRelay(issuerIds, oprfIds);

        // Verify satellite state
        assertEq(WorldIDSatellite(satelliteProxy).LATEST_ROOT(), 1000);
        assertTrue(WorldIDSatellite(satelliteProxy).isValidRoot(1000));
        assertEq(WorldIDSatellite(satelliteProxy).KECCAK_CHAIN().head, head1);
        assertEq(WorldIDSatellite(satelliteProxy).KECCAK_CHAIN().length, 3); // root + issuer + oprf

        // Verify keys bridged
        IStateBridge.ProvenPubKeyInfo memory issuerInfo =
            WorldIDSatellite(satelliteProxy).issuerSchemaIdToPubkeyAndProofId(1);
        assertEq(issuerInfo.pubKey.x, 11);
        assertEq(issuerInfo.pubKey.y, 22);

        IStateBridge.ProvenPubKeyInfo memory oprfInfo = WorldIDSatellite(satelliteProxy).oprfKeyIdToPubkeyAndProofId(1);
        assertEq(oprfInfo.pubKey.x, 33);
        assertEq(oprfInfo.pubKey.y, 44);

        // ── Round 2: update registries, propagate again ──
        registry.setLatestRoot(2000);
        issuerRegistry.setPubkey(1, 55, 66);
        vm.roll(block.number + 1);

        bytes32 head2 = _propagateAndRelay(issuerIds, oprfIds);
        assertTrue(head2 != head1, "chain head should advance");

        assertEq(WorldIDSatellite(satelliteProxy).LATEST_ROOT(), 2000);
        assertTrue(WorldIDSatellite(satelliteProxy).isValidRoot(2000));
        assertTrue(WorldIDSatellite(satelliteProxy).isValidRoot(1000), "old root still valid within window");

        IStateBridge.ProvenPubKeyInfo memory updatedIssuer =
            WorldIDSatellite(satelliteProxy).issuerSchemaIdToPubkeyAndProofId(1);
        assertEq(updatedIssuer.pubKey.x, 55);
        assertEq(updatedIssuer.pubKey.y, 66);

        // ── Time warp: old root expires ──
        vm.warp(block.timestamp + ROOT_VALIDITY_WINDOW + 1);
        assertFalse(WorldIDSatellite(satelliteProxy).isValidRoot(1000), "old root should have expired");
        assertTrue(WorldIDSatellite(satelliteProxy).isValidRoot(2000), "latest root always valid");
    }

    /// @notice After propagation, calling propagateState again with no changes reverts NothingChanged().
    function test_e2e_nothingChanged_reverts() public {
        (uint64[] memory issuerIds, uint160[] memory oprfIds) = _singleIds();

        _propagateAndRelay(issuerIds, oprfIds);

        // Source state now matches registries — propagating again should revert
        vm.expectRevert(abi.encodeWithSignature("NothingChanged()"));
        WorldIDSource(sourceProxy).propagateState(issuerIds, oprfIds);
    }

    /// @notice Propagate multiple issuer keys + OPRF keys in a single batch.
    function test_e2e_multipleKeys() public {
        // Seed 3 issuer keys + 2 OPRF keys
        issuerRegistry.setPubkey(2, 100, 200);
        issuerRegistry.setPubkey(3, 300, 400);
        oprfRegistry.setKey(2, 500, 600);

        uint64[] memory issuerIds = new uint64[](3);
        issuerIds[0] = 1;
        issuerIds[1] = 2;
        issuerIds[2] = 3;

        uint160[] memory oprfIds = new uint160[](2);
        oprfIds[0] = 1;
        oprfIds[1] = 2;

        bytes32 head = _propagateAndRelay(issuerIds, oprfIds);
        assertTrue(head != bytes32(0));

        // 1 root + 3 issuers + 2 OPRFs = 6 commitments
        assertEq(WorldIDSatellite(satelliteProxy).KECCAK_CHAIN().length, 6);
        assertEq(WorldIDSatellite(satelliteProxy).LATEST_ROOT(), 1000);

        // Verify all keys arrived
        IStateBridge.ProvenPubKeyInfo memory i1 = WorldIDSatellite(satelliteProxy).issuerSchemaIdToPubkeyAndProofId(1);
        assertEq(i1.pubKey.x, 11);

        IStateBridge.ProvenPubKeyInfo memory i2 = WorldIDSatellite(satelliteProxy).issuerSchemaIdToPubkeyAndProofId(2);
        assertEq(i2.pubKey.x, 100);
        assertEq(i2.pubKey.y, 200);

        IStateBridge.ProvenPubKeyInfo memory i3 = WorldIDSatellite(satelliteProxy).issuerSchemaIdToPubkeyAndProofId(3);
        assertEq(i3.pubKey.x, 300);
        assertEq(i3.pubKey.y, 400);

        IStateBridge.ProvenPubKeyInfo memory o1 = WorldIDSatellite(satelliteProxy).oprfKeyIdToPubkeyAndProofId(1);
        assertEq(o1.pubKey.x, 33);
        assertEq(o1.pubKey.y, 44);

        IStateBridge.ProvenPubKeyInfo memory o2 = WorldIDSatellite(satelliteProxy).oprfKeyIdToPubkeyAndProofId(2);
        assertEq(o2.pubKey.x, 500);
        assertEq(o2.pubKey.y, 600);
    }

    /// @notice Before any propagation, isValidRoot returns false for any root.
    function test_e2e_unknownRootInvalid() public view {
        assertFalse(WorldIDSatellite(satelliteProxy).isValidRoot(1000));
        assertFalse(WorldIDSatellite(satelliteProxy).isValidRoot(0));
        assertFalse(WorldIDSatellite(satelliteProxy).isValidRoot(type(uint256).max));
    }

    /// @notice Three rounds of root-only updates. Chain length increments by 1 each time
    ///   and all three roots remain valid within the window.
    function test_e2e_sequentialUpdates_chainExtends() public {
        uint64[] memory noIssuers = new uint64[](0);
        uint160[] memory noOprfs = new uint160[](0);

        // Round 1
        _propagateAndRelay(noIssuers, noOprfs);
        assertEq(WorldIDSatellite(satelliteProxy).KECCAK_CHAIN().length, 1);
        assertEq(WorldIDSatellite(satelliteProxy).LATEST_ROOT(), 1000);

        // Round 2
        registry.setLatestRoot(2000);
        vm.roll(block.number + 1);
        _propagateAndRelay(noIssuers, noOprfs);
        assertEq(WorldIDSatellite(satelliteProxy).KECCAK_CHAIN().length, 2);
        assertEq(WorldIDSatellite(satelliteProxy).LATEST_ROOT(), 2000);

        // Round 3
        registry.setLatestRoot(3000);
        vm.roll(block.number + 1);
        _propagateAndRelay(noIssuers, noOprfs);
        assertEq(WorldIDSatellite(satelliteProxy).KECCAK_CHAIN().length, 3);
        assertEq(WorldIDSatellite(satelliteProxy).LATEST_ROOT(), 3000);

        // All three roots valid within window
        assertTrue(WorldIDSatellite(satelliteProxy).isValidRoot(1000));
        assertTrue(WorldIDSatellite(satelliteProxy).isValidRoot(2000));
        assertTrue(WorldIDSatellite(satelliteProxy).isValidRoot(3000));
    }
}
