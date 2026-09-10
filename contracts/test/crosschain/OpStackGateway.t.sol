// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {InteroperableAddress} from "openzeppelin-contracts/contracts/utils/draft-InteroperableAddress.sol";

import {OpStackGatewayAdapter} from "../../src/crosschain/adapters/OpStackGatewayAdapter.sol";
import {WorldIDSource} from "../../src/crosschain/WorldIDSource.sol";
import {WorldIDSatellite} from "../../src/crosschain/WorldIDSatellite.sol";
import {IStateBridge} from "../../src/crosschain/interfaces/IStateBridge.sol";
import {Lib} from "../../src/crosschain/lib/Lib.sol";
import {Verifier} from "../../src/core/Verifier.sol";

import {
    MockRegistry,
    MockIssuerRegistry,
    MockOprfRegistry,
    MockDisputeGameFactory,
    MockCrossDomainMessenger,
    TestableEthereumMPTAdapter
} from "./helpers/Mocks.sol";

/// @title OpStackGatewayTest
/// @notice End-to-end tests for the native OP Stack L1->L2 gateway path:
///   `EthereumMPTGatewayAdapter.forwardToL2` (L1 sender) -> `MockCrossDomainMessenger` (relay) ->
///   `OpStackGatewayAdapter` (L2 receiver) -> `WorldIDSatellite`.
contract OpStackGatewayTest is Test {
    using InteroperableAddress for bytes;

    bytes4 constant UPDATE_ROOT_SELECTOR = bytes4(keccak256("updateRoot(uint256,uint256,bytes32)"));
    bytes4 constant SET_ISSUER_PUBKEY_SELECTOR = bytes4(keccak256("setIssuerPubkey(uint64,uint256,uint256,bytes32)"));
    bytes4 constant SET_OPRF_KEY_SELECTOR = bytes4(keccak256("setOprfKey(uint160,uint256,uint256,bytes32)"));
    bytes4 constant CHAIN_HEAD_SELECTOR = bytes4(keccak256("chainHead(bytes32)"));
    bytes4 constant L1_PROOF_SELECTOR = bytes4(keccak256("l1ProofAttributes(uint32,bytes,bytes32[4],bytes[],bytes[])"));

    uint256 constant WC_CHAIN_ID = 480;
    uint256 constant L1_CHAIN_ID = 1;
    uint256 constant ROOT_VALIDITY_WINDOW = 3600;
    uint256 constant TREE_DEPTH = 30;
    uint64 constant MIN_EXPIRATION = 7200;
    uint64 constant ISSUER_SCHEMA_ID = 123;
    uint160 constant OPRF_KEY_ID = 123;
    uint32 constant MIN_GAS_LIMIT = 500_000;

    address owner = makeAddr("owner");
    address relayer = makeAddr("relayer");
    address l1Bridge = makeAddr("l1Bridge");

    MockRegistry registry;
    MockIssuerRegistry issuerRegistry;
    MockOprfRegistry oprfRegistry;

    WorldIDSource source;
    address sourceProxy;

    WorldIDSatellite satellite;
    address satelliteProxy;

    Verifier verifier;

    MockCrossDomainMessenger messenger;
    TestableEthereumMPTAdapter l1Adapter;
    OpStackGatewayAdapter l2Adapter;

    function setUp() public {
        registry = new MockRegistry();
        issuerRegistry = new MockIssuerRegistry();
        oprfRegistry = new MockOprfRegistry();

        registry.setLatestRoot(12345);
        issuerRegistry.setPubkey(ISSUER_SCHEMA_ID, 111, 222);
        oprfRegistry.setKey(OPRF_KEY_ID, 333, 444);

        // WorldIDSource (impl + proxy)
        source = new WorldIDSource(address(registry), address(issuerRegistry), address(oprfRegistry));
        address[] memory emptyGws = new address[](0);
        IStateBridge.InitConfig memory srcCfg = IStateBridge.InitConfig({
            name: "World ID Source", version: "1", owner: owner, authorizedGateways: emptyGws
        });
        sourceProxy = address(new ERC1967Proxy(address(source), abi.encodeCall(WorldIDSource.initialize, (srcCfg))));

        // WorldIDSatellite on the destination L2 (impl + proxy)
        verifier = new Verifier();
        satellite = new WorldIDSatellite(address(verifier), ROOT_VALIDITY_WINDOW, TREE_DEPTH, MIN_EXPIRATION);
        IStateBridge.InitConfig memory dstCfg = IStateBridge.InitConfig({
            name: "World ID Bridge", version: "1", owner: owner, authorizedGateways: emptyGws
        });
        satelliteProxy =
            address(new ERC1967Proxy(address(satellite), abi.encodeCall(WorldIDSatellite.initialize, (dstCfg))));

        // L1 sender: EthereumMPTGatewayAdapter (testable harness bypasses MPT verification).
        MockDisputeGameFactory dgf = new MockDisputeGameFactory();
        l1Adapter = new TestableEthereumMPTAdapter(owner, address(dgf), false, l1Bridge, sourceProxy, WC_CHAIN_ID);

        // L2 receiver: native OP Stack gateway. Trusts the L2 messenger + the L1 adapter as sender.
        messenger = new MockCrossDomainMessenger();
        l2Adapter =
            new OpStackGatewayAdapter(address(messenger), address(l1Adapter), satelliteProxy, l1Bridge, L1_CHAIN_ID);

        // Authorize the L2 gateway on the satellite.
        vm.prank(owner);
        WorldIDSatellite(satelliteProxy).addGateway(address(l2Adapter));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    function _propagateSource() internal returns (bytes32 chainHead) {
        uint64[] memory issuerIds = new uint64[](1);
        issuerIds[0] = ISSUER_SCHEMA_ID;
        uint160[] memory oprfIds = new uint160[](1);
        oprfIds[0] = OPRF_KEY_ID;

        WorldIDSource(sourceProxy).propagateState(issuerIds, oprfIds);
        chainHead = WorldIDSource(sourceProxy).KECCAK_CHAIN().head;
    }

    function _buildCommitPayload() internal view returns (bytes memory) {
        bytes32 blockHash = blockhash(block.number - 1);
        bytes32 proofId = bytes32(block.number);

        Lib.Commitment[] memory commits = new Lib.Commitment[](3);
        commits[0] = Lib.Commitment({
            blockHash: blockHash,
            data: abi.encodeWithSelector(UPDATE_ROOT_SELECTOR, registry.latestRoot(), block.timestamp, proofId)
        });
        commits[1] = Lib.Commitment({
            blockHash: blockHash,
            data: abi.encodeWithSelector(
                SET_ISSUER_PUBKEY_SELECTOR, ISSUER_SCHEMA_ID, uint256(111), uint256(222), proofId
            )
        });
        commits[2] = Lib.Commitment({
            blockHash: blockHash,
            data: abi.encodeWithSelector(SET_OPRF_KEY_SELECTOR, OPRF_KEY_ID, uint256(333), uint256(444), proofId)
        });
        return abi.encode(commits);
    }

    function _recipientBytes() internal view returns (bytes memory) {
        return InteroperableAddress.formatEvmV1(block.chainid, satelliteProxy);
    }

    /// @dev Builds the `l1ProofAttributes` attribute (values are ignored by the test harness).
    function _l1ProofAttributes() internal pure returns (bytes[] memory attributes) {
        uint32 gameType = 0;
        bytes memory extraData = hex"";
        bytes32[4] memory preimage;
        bytes[] memory accountProof = new bytes[](0);
        bytes[] memory storageProof = new bytes[](0);
        attributes = new bytes[](1);
        attributes[0] =
            abi.encodePacked(L1_PROOF_SELECTOR, abi.encode(gameType, extraData, preimage, accountProof, storageProof));
    }

    /// @dev Encodes the L2 `sendMessage` call delivered by the messenger (mirrors `forwardToL2`).
    function _l2Message(bytes32 chainHead, bytes memory payload) internal view returns (bytes memory) {
        bytes[] memory attrs = new bytes[](1);
        attrs[0] = abi.encodePacked(CHAIN_HEAD_SELECTOR, abi.encode(chainHead));
        return abi.encodeWithSignature("sendMessage(bytes,bytes,bytes[])", _recipientBytes(), payload, attrs);
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    function test_opStackGateway_e2e() public {
        bytes32 chainHead = _propagateSource();
        l1Adapter.setOverrideChainHead(chainHead);

        bytes memory payload = _buildCommitPayload();

        // Permissionless: anyone can trigger the L1 forward; trust comes from the re-verified proof.
        vm.prank(relayer);
        l1Adapter.forwardToL2(
            address(messenger), address(l2Adapter), _recipientBytes(), payload, _l1ProofAttributes(), MIN_GAS_LIMIT
        );

        // State landed on the destination satellite.
        assertEq(WorldIDSatellite(satelliteProxy).LATEST_ROOT(), registry.latestRoot());

        (bytes32 head, uint64 length) = _destChain();
        assertEq(head, chainHead, "destination head should match proven source head");
        assertEq(length, 3, "should have 3 commitments");
        assertTrue(WorldIDSatellite(satelliteProxy).isValidRoot(registry.latestRoot()), "root should be valid");
    }

    function test_opStackGateway_revert_notMessenger() public {
        bytes32 chainHead = _propagateSource();
        bytes memory payload = _buildCommitPayload();

        bytes[] memory attrs = new bytes[](1);
        attrs[0] = abi.encodePacked(CHAIN_HEAD_SELECTOR, abi.encode(chainHead));

        // Calling sendMessage directly (not via the messenger) must revert.
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSignature("InvalidCrossDomainSender()"));
        l2Adapter.sendMessage(_recipientBytes(), payload, attrs);
    }

    function test_opStackGateway_revert_wrongL1Sender() public {
        bytes32 chainHead = _propagateSource();
        bytes memory payload = _buildCommitPayload();

        // Relay through the messenger, but with an untrusted L1 sender.
        vm.expectRevert(abi.encodeWithSignature("InvalidCrossDomainSender()"));
        messenger.relayFrom(address(l2Adapter), makeAddr("attacker"), _l2Message(chainHead, payload));
    }

    function test_opStackGateway_revert_wrongChainHead() public {
        _propagateSource();
        l1Adapter.setOverrideChainHead(bytes32(uint256(0xdead)));

        bytes memory payload = _buildCommitPayload();

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSignature("InvalidChainHead()"));
        l1Adapter.forwardToL2(
            address(messenger), address(l2Adapter), _recipientBytes(), payload, _l1ProofAttributes(), MIN_GAS_LIMIT
        );
    }

    function test_opStackGateway_supportsAttribute() public view {
        assertTrue(l2Adapter.supportsAttribute(CHAIN_HEAD_SELECTOR));
        assertFalse(l2Adapter.supportsAttribute(bytes4(0xdeadbeef)));
    }

    function test_opStackGateway_immutables() public view {
        assertEq(address(l2Adapter.MESSENGER()), address(messenger));
        assertEq(l2Adapter.L1_SENDER(), address(l1Adapter));
        assertEq(l2Adapter.STATE_BRIDGE(), satelliteProxy);
        assertEq(l2Adapter.ANCHOR_BRIDGE(), l1Bridge);
        assertEq(l2Adapter.ANCHOR_CHAIN_ID(), L1_CHAIN_ID);
    }

    function _destChain() internal view returns (bytes32 head, uint64 length) {
        Lib.Chain memory c = WorldIDSatellite(satelliteProxy).KECCAK_CHAIN();
        return (c.head, c.length);
    }
}
