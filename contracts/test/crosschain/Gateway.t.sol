// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {InteroperableAddress} from "openzeppelin-contracts/contracts/utils/draft-InteroperableAddress.sol";

import {PermissionedGatewayAdapter} from "../../src/crosschain/adapters/PermissionedGatewayAdapter.sol";
import {WorldIDGateway} from "../../src/crosschain/lib/Gateway.sol";
import {WorldIDSource} from "../../src/crosschain/WorldIDSource.sol";
import {WorldIDSatellite} from "../../src/crosschain/WorldIDSatellite.sol";
import {StateBridge} from "../../src/crosschain/lib/StateBridge.sol";
import {IStateBridge} from "../../src/crosschain/interfaces/IStateBridge.sol";
import {Lib} from "../../src/crosschain/lib/Lib.sol";
import {Verifier} from "../../src/core/Verifier.sol";

import {
    MockRegistry,
    MockIssuerRegistry,
    MockOprfRegistry,
    MockDisputeGame,
    MockDisputeGameFactory,
    TestableEthereumMPTAdapter
} from "./helpers/Mocks.sol";

// ─── Test Contract ───────────────────────────────────────────────────────────

contract GatewayTest is Test {
    using InteroperableAddress for bytes;

    bytes4 constant UPDATE_ROOT_SELECTOR = bytes4(keccak256("updateRoot(uint256,uint256,bytes32)"));
    bytes4 constant SET_ISSUER_PUBKEY_SELECTOR = bytes4(keccak256("setIssuerPubkey(uint64,uint256,uint256,bytes32)"));
    bytes4 constant SET_OPRF_KEY_SELECTOR = bytes4(keccak256("setOprfKey(uint160,uint256,uint256,bytes32)"));

    uint256 constant WC_CHAIN_ID = 480;
    uint256 constant ROOT_VALIDITY_WINDOW = 3600;
    uint256 constant TREE_DEPTH = 30;
    uint64 constant MIN_EXPIRATION = 7200;
    uint64 constant ISSUER_SCHEMA_ID = 123;
    uint160 constant OPRF_KEY_ID = 123;

    address owner = makeAddr("owner");
    address relayer = makeAddr("relayer");

    MockRegistry registry;
    MockIssuerRegistry issuerRegistry;
    MockOprfRegistry oprfRegistry;

    WorldIDSource source;
    address sourceProxy;

    WorldIDSatellite satellite;
    address satelliteProxy;

    Verifier verifier;

    function setUp() public {
        // Deploy mock registries
        registry = new MockRegistry();
        issuerRegistry = new MockIssuerRegistry();
        oprfRegistry = new MockOprfRegistry();

        // Seed registry data
        registry.setLatestRoot(12345);
        issuerRegistry.setPubkey(ISSUER_SCHEMA_ID, 111, 222);
        oprfRegistry.setKey(OPRF_KEY_ID, 333, 444);

        // Deploy WorldIDSource (impl + proxy)
        source = new WorldIDSource(address(registry), address(issuerRegistry), address(oprfRegistry));

        address[] memory emptyGws = new address[](0);
        IStateBridge.InitConfig memory srcCfg = IStateBridge.InitConfig({
            name: "World ID Source", version: "1", owner: owner, authorizedGateways: emptyGws
        });

        sourceProxy = address(new ERC1967Proxy(address(source), abi.encodeCall(WorldIDSource.initialize, (srcCfg))));

        // Deploy WorldIDSatellite (impl + proxy)
        verifier = new Verifier();
        satellite = new WorldIDSatellite(address(verifier), ROOT_VALIDITY_WINDOW, TREE_DEPTH, MIN_EXPIRATION);

        IStateBridge.InitConfig memory dstCfg = IStateBridge.InitConfig({
            name: "World ID Bridge", version: "1", owner: owner, authorizedGateways: emptyGws
        });

        satelliteProxy =
            address(new ERC1967Proxy(address(satellite), abi.encodeCall(WorldIDSatellite.initialize, (dstCfg))));
    }

    // ────────────────────────────────────────────────────────────────────────
    //  Helpers
    // ────────────────────────────────────────────────────────────────────────

    /// @dev Propagates state on source, returning the new chain head.
    function _propagateSource() internal returns (bytes32 chainHead) {
        uint64[] memory issuerIds = new uint64[](1);
        issuerIds[0] = ISSUER_SCHEMA_ID;
        uint160[] memory oprfIds = new uint160[](1);
        oprfIds[0] = OPRF_KEY_ID;

        WorldIDSource(sourceProxy).propagateState(issuerIds, oprfIds);

        Lib.Chain memory chain = WorldIDSource(sourceProxy).KECCAK_CHAIN();
        chainHead = chain.head;
    }

    /// @dev Builds the commitment payload matching what propagateState produces.
    function _buildCommitPayload() internal view returns (bytes memory) {
        bytes32 blockHash = blockhash(block.number - 1);
        bytes32 proofId = bytes32(block.number);

        Lib.Commitment[] memory commits = new Lib.Commitment[](3);

        // root commit
        commits[0] = Lib.Commitment({
            blockHash: blockHash,
            data: abi.encodeWithSelector(UPDATE_ROOT_SELECTOR, registry.latestRoot(), block.timestamp, proofId)
        });

        // issuer pubkey commit
        commits[1] = Lib.Commitment({
            blockHash: blockHash,
            data: abi.encodeWithSelector(
                SET_ISSUER_PUBKEY_SELECTOR, ISSUER_SCHEMA_ID, uint256(111), uint256(222), proofId
            )
        });

        // oprf key commit
        commits[2] = Lib.Commitment({
            blockHash: blockHash,
            data: abi.encodeWithSelector(SET_OPRF_KEY_SELECTOR, OPRF_KEY_ID, uint256(333), uint256(444), proofId)
        });

        return abi.encode(commits);
    }

    /// @dev Builds the ERC-7786 formatted recipient for the satellite bridge.
    function _recipientBytes() internal view returns (bytes memory) {
        return InteroperableAddress.formatEvmV1(block.chainid, satelliteProxy);
    }

    // ────────────────────────────────────────────────────────────────────────
    //  PermissionedGatewayAdapter E2E
    // ────────────────────────────────────────────────────────────────────────

    function test_permissionedGateway_e2e() public {
        // 1. Deploy PermissionedGatewayAdapter
        PermissionedGatewayAdapter gw = new PermissionedGatewayAdapter(owner, satelliteProxy, sourceProxy, WC_CHAIN_ID);

        // 2. Authorize the gateway on the satellite bridge
        vm.prank(owner);
        WorldIDSatellite(satelliteProxy).addGateway(address(gw));

        // 3. Propagate state on the source to get a chain head
        bytes32 chainHead = _propagateSource();
        assertTrue(chainHead != bytes32(0), "chain head should be non-zero after propagation");

        // 4. Build the commit payload (same commitments as source)
        bytes memory commitPayload = _buildCommitPayload();

        // 5. Build the attribute: chainHead(bytes32)
        bytes4 attrSelector = bytes4(keccak256("chainHead(bytes32)"));
        bytes[] memory attributes = new bytes[](1);
        attributes[0] = abi.encodePacked(attrSelector, abi.encode(chainHead));

        // 6. Call sendMessage as owner through the gateway
        vm.prank(owner);
        bytes32 sendId = gw.sendMessage(_recipientBytes(), commitPayload, attributes);
        assertTrue(sendId != bytes32(0), "sendId should be non-zero");

        // 7. Verify state was bridged to WorldIDSatellite
        assertEq(WorldIDSatellite(satelliteProxy).LATEST_ROOT(), registry.latestRoot());

        Lib.Chain memory dstChain = WorldIDSatellite(satelliteProxy).KECCAK_CHAIN();
        assertEq(dstChain.head, chainHead, "destination chain head should match source");
        assertEq(dstChain.length, 3, "should have 3 commitments");

        assertTrue(WorldIDSatellite(satelliteProxy).isValidRoot(registry.latestRoot()), "root should be valid");
    }

    function test_permissionedGateway_revert_nonOwner() public {
        PermissionedGatewayAdapter gw = new PermissionedGatewayAdapter(owner, satelliteProxy, sourceProxy, WC_CHAIN_ID);

        vm.prank(owner);
        WorldIDSatellite(satelliteProxy).addGateway(address(gw));

        bytes32 chainHead = _propagateSource();
        bytes memory commitPayload = _buildCommitPayload();

        bytes4 attrSelector = bytes4(keccak256("chainHead(bytes32)"));
        bytes[] memory attributes = new bytes[](1);
        attributes[0] = abi.encodePacked(attrSelector, abi.encode(chainHead));

        // Non-owner should revert
        vm.prank(relayer);
        vm.expectRevert();
        gw.sendMessage(_recipientBytes(), commitPayload, attributes);
    }

    function test_permissionedGateway_revert_unauthorizedGateway() public {
        PermissionedGatewayAdapter gw = new PermissionedGatewayAdapter(owner, satelliteProxy, sourceProxy, WC_CHAIN_ID);
        // Do NOT add gateway to WorldIDSatellite

        bytes32 chainHead = _propagateSource();
        bytes memory commitPayload = _buildCommitPayload();

        bytes4 attrSelector = bytes4(keccak256("chainHead(bytes32)"));
        bytes[] memory attributes = new bytes[](1);
        attributes[0] = abi.encodePacked(attrSelector, abi.encode(chainHead));

        vm.prank(owner);
        vm.expectRevert();
        gw.sendMessage(_recipientBytes(), commitPayload, attributes);
    }

    function test_permissionedGateway_revert_wrongChainHead() public {
        PermissionedGatewayAdapter gw = new PermissionedGatewayAdapter(owner, satelliteProxy, sourceProxy, WC_CHAIN_ID);

        vm.prank(owner);
        WorldIDSatellite(satelliteProxy).addGateway(address(gw));

        _propagateSource();
        bytes memory commitPayload = _buildCommitPayload();

        // Use a wrong chain head
        bytes4 attrSelector = bytes4(keccak256("chainHead(bytes32)"));
        bytes[] memory attributes = new bytes[](1);
        attributes[0] = abi.encodePacked(attrSelector, abi.encode(bytes32(uint256(0xdead))));

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("InvalidChainHead()"));
        gw.sendMessage(_recipientBytes(), commitPayload, attributes);
    }

    function test_permissionedGateway_revert_emptyPayload() public {
        PermissionedGatewayAdapter gw = new PermissionedGatewayAdapter(owner, satelliteProxy, sourceProxy, WC_CHAIN_ID);

        bytes4 attrSelector = bytes4(keccak256("chainHead(bytes32)"));
        bytes[] memory attributes = new bytes[](1);
        attributes[0] = abi.encodePacked(attrSelector, abi.encode(bytes32(0)));

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("EmptyPayload()"));
        gw.sendMessage(_recipientBytes(), bytes(""), attributes);
    }

    function test_permissionedGateway_revert_wrongRecipient() public {
        PermissionedGatewayAdapter gw = new PermissionedGatewayAdapter(owner, satelliteProxy, sourceProxy, WC_CHAIN_ID);

        _propagateSource();

        bytes4 attrSelector = bytes4(keccak256("chainHead(bytes32)"));
        bytes[] memory attributes = new bytes[](1);
        attributes[0] = abi.encodePacked(attrSelector, abi.encode(bytes32(0)));

        bytes memory commitPayload = _buildCommitPayload();

        // Use a random address as recipient
        bytes memory wrongRecipient = InteroperableAddress.formatEvmV1(block.chainid, address(0xbeef));

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("InvalidRecipient()"));
        gw.sendMessage(wrongRecipient, commitPayload, attributes);
    }

    function test_permissionedGateway_supportsAttribute() public {
        PermissionedGatewayAdapter gw = new PermissionedGatewayAdapter(owner, satelliteProxy, sourceProxy, WC_CHAIN_ID);

        bytes4 chainHeadSel = bytes4(keccak256("chainHead(bytes32)"));
        assertTrue(gw.supportsAttribute(chainHeadSel));
        assertFalse(gw.supportsAttribute(bytes4(0xdeadbeef)));
    }

    // ────────────────────────────────────────────────────────────────────────
    //  EthereumMPTGatewayAdapter E2E (with MPT bypass harness)
    // ────────────────────────────────────────────────────────────────────────

    function test_ethereumMPTGateway_e2e() public {
        MockDisputeGameFactory dgf = new MockDisputeGameFactory();

        // Deploy testable EthereumMPTGatewayAdapter
        TestableEthereumMPTAdapter gw =
            new TestableEthereumMPTAdapter(owner, address(dgf), false, satelliteProxy, sourceProxy, WC_CHAIN_ID);

        // Authorize gateway
        vm.prank(owner);
        WorldIDSatellite(satelliteProxy).addGateway(address(gw));

        // Propagate source state
        bytes32 chainHead = _propagateSource();

        // Set the override to bypass MPT verification
        gw.setOverrideChainHead(chainHead);

        // Build commit payload
        bytes memory commitPayload = _buildCommitPayload();

        // Build L1 gateway attribute (values don't matter since we're using the override)
        bytes4 attrSelector = bytes4(keccak256("l1ProofAttributes(uint32,bytes,bytes32[4],bytes[],bytes[])"));
        bytes[] memory attributes = new bytes[](1);
        {
            uint32 gameType = 0;
            bytes memory extraData = hex"";
            bytes32[4] memory outputRootPreimage;
            bytes[] memory accountProof = new bytes[](0);
            bytes[] memory storageProof = new bytes[](0);
            attributes[0] = abi.encodePacked(
                attrSelector, abi.encode(gameType, extraData, outputRootPreimage, accountProof, storageProof)
            );
        }

        // Send message (anyone can call — it's permissionless via proofs)
        vm.prank(relayer);
        bytes32 sendId = gw.sendMessage(_recipientBytes(), commitPayload, attributes);
        assertTrue(sendId != bytes32(0));

        // Verify state bridged
        assertEq(WorldIDSatellite(satelliteProxy).LATEST_ROOT(), registry.latestRoot());

        Lib.Chain memory dstChain = WorldIDSatellite(satelliteProxy).KECCAK_CHAIN();
        assertEq(dstChain.head, chainHead);
        assertEq(dstChain.length, 3);
    }

    function test_ethereumMPTGateway_revert_unsupportedAttribute() public {
        MockDisputeGameFactory dgf = new MockDisputeGameFactory();
        TestableEthereumMPTAdapter gw =
            new TestableEthereumMPTAdapter(owner, address(dgf), false, satelliteProxy, sourceProxy, WC_CHAIN_ID);

        vm.prank(owner);
        WorldIDSatellite(satelliteProxy).addGateway(address(gw));

        bytes32 chainHead = _propagateSource();
        gw.setOverrideChainHead(chainHead);

        bytes memory commitPayload = _buildCommitPayload();

        // Use wrong attribute selector
        bytes4 wrongSelector = bytes4(keccak256("chainHead(bytes32)"));
        bytes[] memory attributes = new bytes[](1);
        attributes[0] = abi.encodePacked(wrongSelector, abi.encode(bytes32(0)));

        vm.prank(relayer);
        vm.expectRevert();
        gw.sendMessage(_recipientBytes(), commitPayload, attributes);
    }

    function test_ethereumMPTGateway_supportsAttribute() public {
        MockDisputeGameFactory dgf = new MockDisputeGameFactory();
        TestableEthereumMPTAdapter gw =
            new TestableEthereumMPTAdapter(owner, address(dgf), false, satelliteProxy, sourceProxy, WC_CHAIN_ID);

        bytes4 l1Sel = bytes4(keccak256("l1ProofAttributes(uint32,bytes,bytes32[4],bytes[],bytes[])"));
        assertTrue(gw.supportsAttribute(l1Sel));
        assertFalse(gw.supportsAttribute(bytes4(keccak256("chainHead(bytes32)"))));
    }

    // ────────────────────────────────────────────────────────────────────────
    //  Multi-relay: both gateways relay to the same bridge sequentially
    // ────────────────────────────────────────────────────────────────────────

    function test_bothGateways_sequentialRelay() public {
        // Deploy both gateways
        PermissionedGatewayAdapter ownedGw =
            new PermissionedGatewayAdapter(owner, satelliteProxy, sourceProxy, WC_CHAIN_ID);
        MockDisputeGameFactory dgf = new MockDisputeGameFactory();
        TestableEthereumMPTAdapter l1Gw =
            new TestableEthereumMPTAdapter(owner, address(dgf), false, satelliteProxy, sourceProxy, WC_CHAIN_ID);

        // Authorize both
        vm.startPrank(owner);
        WorldIDSatellite(satelliteProxy).addGateway(address(ownedGw));
        WorldIDSatellite(satelliteProxy).addGateway(address(l1Gw));
        vm.stopPrank();

        // ── First relay via PermissionedGatewayAdapter ──
        bytes32 head1 = _propagateSource();
        bytes memory payload1 = _buildCommitPayload();

        bytes4 ownedAttr = bytes4(keccak256("chainHead(bytes32)"));
        bytes[] memory attrs1 = new bytes[](1);
        attrs1[0] = abi.encodePacked(ownedAttr, abi.encode(head1));

        vm.prank(owner);
        ownedGw.sendMessage(_recipientBytes(), payload1, attrs1);

        assertEq(WorldIDSatellite(satelliteProxy).LATEST_ROOT(), registry.latestRoot());
        assertEq(WorldIDSatellite(satelliteProxy).KECCAK_CHAIN().length, 3);

        // ── Update source state ──
        registry.setLatestRoot(99999);
        vm.roll(block.number + 1);

        bytes32 head2 = _propagateSource();
        assertTrue(head2 != head1, "chain head should advance after second propagation");

        // ── Second relay via EthereumMPTGatewayAdapter ──
        l1Gw.setOverrideChainHead(head2);

        // Build new payload for just the root update
        bytes32 blockHash2 = blockhash(block.number - 1);
        bytes32 proofId2 = bytes32(block.number);
        Lib.Commitment[] memory commits2 = new Lib.Commitment[](1);
        commits2[0] = Lib.Commitment({
            blockHash: blockHash2,
            data: abi.encodeWithSelector(UPDATE_ROOT_SELECTOR, uint256(99999), block.timestamp, proofId2)
        });
        bytes memory payload2 = abi.encode(commits2);

        bytes4 l1Attr = bytes4(keccak256("l1ProofAttributes(uint32,bytes,bytes32[4],bytes[],bytes[])"));
        bytes[] memory attrs2 = new bytes[](1);
        {
            uint32 gameType = 0;
            bytes memory extraData = hex"";
            bytes32[4] memory preimage;
            bytes[] memory acctProof = new bytes[](0);
            bytes[] memory storProof = new bytes[](0);
            attrs2[0] = abi.encodePacked(l1Attr, abi.encode(gameType, extraData, preimage, acctProof, storProof));
        }

        vm.prank(relayer);
        l1Gw.sendMessage(_recipientBytes(), payload2, attrs2);

        // Verify second relay succeeded
        assertEq(WorldIDSatellite(satelliteProxy).LATEST_ROOT(), 99999);
        assertEq(WorldIDSatellite(satelliteProxy).KECCAK_CHAIN().length, 4, "should have 4 total commitments");
        assertEq(WorldIDSatellite(satelliteProxy).KECCAK_CHAIN().head, head2);
    }
}
