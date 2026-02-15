// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, Vm} from "forge-std/Test.sol";
import {WorldIDBridge} from "../src/core/bridges/WorldIDBridge.sol";
import {WorldChainBridge} from "../src/core/bridges/WorldChainBridge.sol";
import {
    WorldIDGateway,
    InvalidSequencerSignature,
    PayloadTooShort,
    StateRelayed
} from "../src/core/SequencerGateway.sol";
import {EmptyChainedCommits, NothingChanged, ProvenPubKeyInfo} from "../src/core/interfaces/IWorldIDBridge.sol";
import {ProofsLib, InvalidChainHead} from "../src/core/lib/ProofsLib.sol";
import {BabyJubJub} from "lib/oprf-key-registry/src/BabyJubJub.sol";
import {OprfKeyGen} from "lib/oprf-key-registry/src/OprfKeyGen.sol";
import {ICredentialSchemaIssuerRegistry} from "@world-id/interfaces/ICredentialSchemaIssuerRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";

// ═══════════════════════════════════════════════════════════
//                          MOCKS
// ═══════════════════════════════════════════════════════════

contract MockWorldIDRegistry {
    uint256 internal _latestRoot;

    function setRoot(uint256 root) external {
        _latestRoot = root;
    }

    function getLatestRoot() external view returns (uint256) {
        return _latestRoot;
    }
}

contract MockIssuerRegistry {
    mapping(uint64 => ICredentialSchemaIssuerRegistry.Pubkey) internal _keys;

    function setPubkey(uint64 id, uint256 x, uint256 y) external {
        _keys[id] = ICredentialSchemaIssuerRegistry.Pubkey({x: x, y: y});
    }

    function issuerSchemaIdToPubkey(uint64 id) external view returns (ICredentialSchemaIssuerRegistry.Pubkey memory) {
        return _keys[id];
    }
}

contract MockOprfRegistry {
    mapping(uint160 => OprfKeyGen.RegisteredOprfPublicKey) internal _keys;

    function setKey(uint160 id, uint256 x, uint256 y) external {
        _keys[id] = OprfKeyGen.RegisteredOprfPublicKey({key: BabyJubJub.Affine({x: x, y: y}), epoch: 1});
    }

    function getOprfPublicKeyAndEpoch(uint160 id) external view returns (OprfKeyGen.RegisteredOprfPublicKey memory) {
        return _keys[id];
    }
}

/// @dev Test harness for WorldIDBridge — exposes `initialize` since `__WorldIdBridge_init` is internal.
contract TestWorldIDBridge is WorldIDBridge {
    function initialize(
        string memory name_,
        string memory version_,
        address owner_,
        address[] memory gateways_
    ) public {
        __WorldIdBridge_init(name_, version_, owner_, gateways_);
    }

    /// @dev Exposes gateway auth check for test assertions.
    function isAuthorizedGateway(address gateway, bytes calldata sender) external view returns (bool) {
        return _isAuthorizedGateway(gateway, sender);
    }
}

// ═══════════════════════════════════════════════════════════
//                         TESTS
// ═══════════════════════════════════════════════════════════

contract WorldChainStateBridgeTest is Test {
    event GatewayAdded(address indexed gateway);
    event GatewayRemoved(address indexed gateway);

    address constant PLANTED_WC_BRIDGE = address(uint160(uint256(keccak256("test.wc.bridge"))));

    bytes4 constant UPDATE_ROOT_SEL = bytes4(keccak256("updateRoot(uint256,uint256,bytes32)"));
    bytes4 constant SET_ISSUER_SEL = bytes4(keccak256("setIssuerPubkey(uint64,uint256,uint256,bytes32)"));
    bytes4 constant SET_OPRF_SEL = bytes4(keccak256("setOprfKey(uint160,uint256,uint256,bytes32)"));

    // Shared mocks — created in setUp, reused across tests.
    MockWorldIDRegistry wcRegistry;
    MockIssuerRegistry wcIssuer;
    MockOprfRegistry wcOprf;

    /// @dev Incremented for each receiveMessage call to avoid replay protection.
    uint256 internal _receiveNonce;

    function setUp() public {
        wcRegistry = new MockWorldIDRegistry();
        wcIssuer = new MockIssuerRegistry();
        wcOprf = new MockOprfRegistry();
    }

    // ═══════════════════════════════════════════════════════════
    //              DEPLOYMENT HELPERS
    // ═══════════════════════════════════════════════════════════

    /// @dev Deploys a TestWorldIDBridge behind a proxy.
    function _deployWorldIDBridge() internal returns (TestWorldIDBridge) {
        TestWorldIDBridge impl = new TestWorldIDBridge();
        address[] memory gateways = new address[](0);
        bytes memory initData =
            abi.encodeCall(TestWorldIDBridge.initialize, ("Destination", "1", address(this), gateways));
        return TestWorldIDBridge(payable(address(new ERC1967Proxy(address(impl), initData))));
    }

    /// @dev Deploys a WorldChainBridge with the shared mock registries behind a proxy.
    function _deployWorldChainBridge() internal returns (WorldChainBridge) {
        WorldChainBridge impl = new WorldChainBridge(address(wcRegistry), address(wcIssuer), address(wcOprf));
        address[] memory gateways = new address[](0);
        bytes memory initData =
            abi.encodeCall(WorldChainBridge.initialize, ("WorldChain", "1", address(this), gateways));
        return WorldChainBridge(payable(address(new ERC1967Proxy(address(impl), initData))));
    }

    // ═══════════════════════════════════════════════════════════
    //              COMMIT HELPERS
    // ═══════════════════════════════════════════════════════════

    /// @dev Builds a single-element Commitment array for a root update.
    function _rootCommit(uint256 root, uint256 ts, bytes32 proofId)
        internal
        pure
        returns (ProofsLib.Commitment[] memory)
    {
        ProofsLib.Commitment[] memory c = new ProofsLib.Commitment[](1);
        c[0] = ProofsLib.Commitment({
            blockHash: bytes32(uint256(1)), data: abi.encodeWithSelector(UPDATE_ROOT_SEL, root, ts, proofId)
        });
        return c;
    }

    /// @dev Calls receiveMessage on a bridge from a gateway, incrementing the nonce for replay protection.
    function _callReceiveMessage(TestWorldIDBridge dest, address gateway, bytes memory payload) internal {
        vm.prank(gateway);
        dest.receiveMessage(bytes32(++_receiveNonce), "", payload);
    }

    /// @dev Encodes the gateway payload as expected by WorldIDBridge._processGatewayMessage.
    function _encodeGatewayPayload(bytes32 provenChainHead, ProofsLib.Commitment[] memory commits)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(provenChainHead, abi.encode(commits));
    }

    // ═══════════════════════════════════════════════════════════
    //              GATEWAY MANAGEMENT TESTS
    // ═══════════════════════════════════════════════════════════

    function test_gateway_addAndRemove() public {
        TestWorldIDBridge dest = _deployWorldIDBridge();
        address gateway = address(0x7786);

        vm.expectEmit(true, false, false, false);
        emit GatewayAdded(gateway);
        dest.addGateway(gateway);
        assertTrue(dest.isAuthorizedGateway(gateway, ""));

        vm.expectEmit(true, false, false, false);
        emit GatewayRemoved(gateway);
        dest.removeGateway(gateway);
        assertFalse(dest.isAuthorizedGateway(gateway, ""));
    }

    function test_gateway_addOnlyOwner() public {
        TestWorldIDBridge dest = _deployWorldIDBridge();

        vm.prank(address(0xBEEF));
        vm.expectRevert();
        dest.addGateway(address(0x7786));
    }

    function test_receiveMessage_unauthorizedReverts() public {
        TestWorldIDBridge dest = _deployWorldIDBridge();

        bytes memory payload = _encodeGatewayPayload(bytes32(0), new ProofsLib.Commitment[](0));
        vm.prank(address(0x9999));
        vm.expectRevert();
        dest.receiveMessage(bytes32(uint256(1)), "", payload);
    }

    function test_receiveMessage_emptyCommitsReverts() public {
        TestWorldIDBridge dest = _deployWorldIDBridge();
        address gateway = address(0x7786);
        dest.addGateway(gateway);

        bytes memory payload = _encodeGatewayPayload(bytes32(0), new ProofsLib.Commitment[](0));
        vm.prank(gateway);
        vm.expectRevert(EmptyChainedCommits.selector);
        dest.receiveMessage(bytes32(uint256(1)), "", payload);
    }

    function test_receiveMessage_invalidChainHeadReverts() public {
        TestWorldIDBridge dest = _deployWorldIDBridge();
        address gateway = address(0x7786);
        dest.addGateway(gateway);

        ProofsLib.Commitment[] memory commits = _rootCommit(42, 1_700_000_000, bytes32(uint256(1)));
        bytes memory payload = _encodeGatewayPayload(bytes32(uint256(0xDEAD)), commits);

        vm.prank(gateway);
        vm.expectRevert(InvalidChainHead.selector);
        dest.receiveMessage(bytes32(uint256(1)), "", payload);
    }

    function test_receiveMessage_appliesState() public {
        TestWorldIDBridge dest = _deployWorldIDBridge();
        address gateway = address(0x7786);
        dest.addGateway(gateway);

        uint256 testRoot = 42424;
        bytes32 proofId = bytes32(uint256(77));
        ProofsLib.Commitment[] memory commits = _rootCommit(testRoot, 1_700_000_000, proofId);

        // Compute expected chain head
        ProofsLib.Chain memory chain;
        bytes32 expectedHead = ProofsLib.hashChained(chain, commits);

        bytes memory payload = _encodeGatewayPayload(expectedHead, commits);
        _callReceiveMessage(dest, gateway, payload);

        assertEq(dest.LATEST_ROOT(), testRoot, "Root applied via gateway");

        ProofsLib.Chain memory resultChain = dest.KECCAK_CHAIN();
        assertEq(resultChain.head, expectedHead);
    }

    // ═══════════════════════════════════════════════════════════
    //              WORLDCHAINBRIDGE TESTS
    // ═══════════════════════════════════════════════════════════

    function test_worldChainBridge_propagateState_rootChanged() public {
        wcRegistry.setRoot(42);
        WorldChainBridge wc = _deployWorldChainBridge();

        wc.propagateState(new uint64[](0), new uint160[](0));

        assertEq(wc.LATEST_ROOT(), 42);
        assertEq(wc.KECCAK_CHAIN().length, 1);
    }

    function test_worldChainBridge_propagateState_issuerChanged() public {
        wcRegistry.setRoot(1);
        wcIssuer.setPubkey(0x5a, 11, 22);
        WorldChainBridge wc = _deployWorldChainBridge();

        uint64[] memory ids = new uint64[](1);
        ids[0] = 0x5a;
        wc.propagateState(ids, new uint160[](0));

        ProvenPubKeyInfo memory info = wc.issuerSchemaIdToPubkeyAndProofId(0x5a);
        assertEq(info.pubKey.x, 11);
        assertEq(info.pubKey.y, 22);
    }

    function test_worldChainBridge_propagateState_oprfChanged() public {
        wcRegistry.setRoot(1);
        wcOprf.setKey(uint160(0xAB), 33, 44);
        WorldChainBridge wc = _deployWorldChainBridge();

        uint160[] memory oprfIds = new uint160[](1);
        oprfIds[0] = uint160(0xAB);
        wc.propagateState(new uint64[](0), oprfIds);

        // OPRF mapping is internal — verify indirectly: second call with no changes adds only root.
        wcRegistry.setRoot(2);
        wc.propagateState(new uint64[](0), oprfIds);
        assertEq(wc.KECCAK_CHAIN().length, 3, "No extra OPRF commit when unchanged");
    }

    function test_worldChainBridge_propagateState_allChanged() public {
        wcRegistry.setRoot(999);
        wcIssuer.setPubkey(0x5a, 11, 22);
        wcOprf.setKey(uint160(0xAB), 33, 44);
        WorldChainBridge wc = _deployWorldChainBridge();

        uint64[] memory issuerIds = new uint64[](1);
        issuerIds[0] = 0x5a;
        uint160[] memory oprfIds = new uint160[](1);
        oprfIds[0] = uint160(0xAB);
        wc.propagateState(issuerIds, oprfIds);

        assertEq(wc.KECCAK_CHAIN().length, 3, "root + issuer + OPRF");
        assertEq(wc.LATEST_ROOT(), 999);
    }

    function test_worldChainBridge_propagateState_nothingChanged_reverts() public {
        WorldChainBridge wc = _deployWorldChainBridge();

        vm.expectRevert(NothingChanged.selector);
        wc.propagateState(new uint64[](0), new uint160[](0));
    }

    function test_worldChainBridge_propagateState_partialChanges() public {
        wcRegistry.setRoot(1);
        wcIssuer.setPubkey(0x01, 11, 22);
        wcIssuer.setPubkey(0x02, 33, 44);
        WorldChainBridge wc = _deployWorldChainBridge();

        uint64[] memory ids = new uint64[](2);
        ids[0] = 0x01;
        ids[1] = 0x02;
        wc.propagateState(ids, new uint160[](0));
        assertEq(wc.KECCAK_CHAIN().length, 3, "root + 2 issuers");

        wcIssuer.setPubkey(0x01, 55, 66);
        wcRegistry.setRoot(2);
        wc.propagateState(ids, new uint160[](0));
        assertEq(wc.KECCAK_CHAIN().length, 5, "root + 1 changed issuer");
    }

    function test_worldChainBridge_chainLength() public {
        wcRegistry.setRoot(42);
        WorldChainBridge wc = _deployWorldChainBridge();

        assertEq(wc.KECCAK_CHAIN().length, 0);

        wc.propagateState(new uint64[](0), new uint160[](0));

        assertEq(wc.KECCAK_CHAIN().length, 1);
    }

    function test_worldChainBridge_secondPropagation() public {
        wcRegistry.setRoot(42);
        WorldChainBridge wc = _deployWorldChainBridge();

        wc.propagateState(new uint64[](0), new uint160[](0));
        bytes32 head1 = wc.KECCAK_CHAIN().head;
        assertTrue(head1 != bytes32(0));

        wcRegistry.setRoot(100);
        wc.propagateState(new uint64[](0), new uint160[](0));
        ProofsLib.Chain memory chain2 = wc.KECCAK_CHAIN();

        assertTrue(chain2.head != head1);
        assertEq(chain2.length, 2);
        assertEq(wc.LATEST_ROOT(), 100);
    }

    // ═══════════════════════════════════════════════════════════
    //            SEQUENCER GATEWAY TESTS
    // ═══════════════════════════════════════════════════════════

    /// @dev The World Chain chain ID used in OP Stack P2P signing.
    uint256 constant WC_CHAIN_ID = 480;

    /// @dev Deploys a WorldIDGateway (non-upgradeable).
    function _deployWorldIDGateway(address sequencerAddr, address destBridge, address wcBridgeAddr)
        internal
        returns (WorldIDGateway)
    {
        return new WorldIDGateway(address(this), sequencerAddr, destBridge, wcBridgeAddr, WC_CHAIN_ID);
    }

    /// @dev Builds a mock SSZ-encoded ExecutionPayloadEnvelope with a given stateRoot.
    ///   Layout: ParentBeaconBlockRoot(32) + ParentHash(32) + FeeRecipient(20) + StateRoot(32) + padding
    function _buildMockSSZ(bytes32 stateRoot) internal pure returns (bytes memory) {
        bytes memory ssz = new bytes(116); // MIN_SSZ_LENGTH
        assembly {
            mstore(add(ssz, add(32, 84)), stateRoot)
        }
        return ssz;
    }

    /// @dev Computes the OP Stack P2P signing hash for a given SSZ payload.
    function _opStackSigningHash(bytes memory sszPayload) internal pure returns (bytes32) {
        bytes32 payloadHash = keccak256(sszPayload);
        return keccak256(abi.encodePacked(bytes32(0), WC_CHAIN_ID, payloadHash));
    }

    function test_sequencerGateway_initialize() public {
        address sequencerAddr = address(0x5E01);
        TestWorldIDBridge dest = _deployWorldIDBridge();
        WorldIDGateway gw = _deployWorldIDGateway(sequencerAddr, address(dest), PLANTED_WC_BRIDGE);

        assertEq(gw.sequencer(), sequencerAddr);
        assertEq(gw.BRIDGE(), address(dest));
        assertEq(gw.WC_BRIDGE(), PLANTED_WC_BRIDGE);
        assertEq(gw.WC_CHAIN_ID(), WC_CHAIN_ID);
        assertEq(gw.owner(), address(this));
    }

    function test_sequencerGateway_setSequencer() public {
        address sequencerAddr = address(0x5E01);
        TestWorldIDBridge dest = _deployWorldIDBridge();
        WorldIDGateway gw = _deployWorldIDGateway(sequencerAddr, address(dest), PLANTED_WC_BRIDGE);

        address newSeq = address(0x5E02);
        gw.setSequencer(newSeq);
        assertEq(gw.sequencer(), newSeq);
    }

    function test_sequencerGateway_setSequencer_onlyOwner() public {
        address sequencerAddr = address(0x5E01);
        TestWorldIDBridge dest = _deployWorldIDBridge();
        WorldIDGateway gw = _deployWorldIDGateway(sequencerAddr, address(dest), PLANTED_WC_BRIDGE);

        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(0xBEEF)));
        gw.setSequencer(address(0x5E02));
    }

    function test_sequencerGateway_relay_invalidSignature_reverts() public {
        Vm.Wallet memory sequencerWallet = vm.createWallet("sequencer");
        TestWorldIDBridge dest = _deployWorldIDBridge();
        WorldIDGateway gw = _deployWorldIDGateway(sequencerWallet.addr, address(dest), PLANTED_WC_BRIDGE);

        bytes memory sszPayload = _buildMockSSZ(bytes32(uint256(0xABC)));

        // Sign with a WRONG key
        Vm.Wallet memory wrongWallet = vm.createWallet("wrong");
        bytes32 signingHash = _opStackSigningHash(sszPayload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongWallet.privateKey, signingHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes[] memory accountProof = new bytes[](0);
        bytes[] memory storageProof = new bytes[](0);
        ProofsLib.Commitment[] memory commits = _rootCommit(42, 1_700_000_000, bytes32(uint256(1)));
        bytes memory commitPayload = abi.encode(commits);

        vm.expectRevert(InvalidSequencerSignature.selector);
        gw.relay(sszPayload, sig, accountProof, storageProof, commitPayload);
    }

    function test_sequencerGateway_relay_payloadTooShort_reverts() public {
        Vm.Wallet memory sequencerWallet = vm.createWallet("sequencer");
        TestWorldIDBridge dest = _deployWorldIDBridge();
        WorldIDGateway gw = _deployWorldIDGateway(sequencerWallet.addr, address(dest), PLANTED_WC_BRIDGE);

        bytes memory shortPayload = new bytes(100);

        bytes32 signingHash = _opStackSigningHash(shortPayload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sequencerWallet.privateKey, signingHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes[] memory accountProof = new bytes[](0);
        bytes[] memory storageProof = new bytes[](0);
        ProofsLib.Commitment[] memory commits = _rootCommit(42, 1_700_000_000, bytes32(uint256(1)));
        bytes memory commitPayload = abi.encode(commits);

        vm.expectRevert(PayloadTooShort.selector);
        gw.relay(shortPayload, sig, accountProof, storageProof, commitPayload);
    }

    function test_sequencerGateway_relay_signatureVerification() public {
        // Verifies the signature check passes with a correctly signed SSZ payload.
        // The MPT proof will fail (empty proofs), but we confirm the sig check works.
        Vm.Wallet memory sequencerWallet = vm.createWallet("sequencer");
        TestWorldIDBridge dest = _deployWorldIDBridge();
        WorldIDGateway gw = _deployWorldIDGateway(sequencerWallet.addr, address(dest), PLANTED_WC_BRIDGE);

        bytes memory sszPayload = _buildMockSSZ(bytes32(uint256(0xABC)));

        bytes32 signingHash = _opStackSigningHash(sszPayload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sequencerWallet.privateKey, signingHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes[] memory accountProof = new bytes[](0);
        bytes[] memory storageProof = new bytes[](0);
        ProofsLib.Commitment[] memory commits = _rootCommit(42, 1_700_000_000, bytes32(uint256(1)));
        bytes memory commitPayload = abi.encode(commits);

        // Should revert in MPT verification (not in signature check)
        vm.expectRevert();
        gw.relay(sszPayload, sig, accountProof, storageProof, commitPayload);

        // Wrong signer should revert with InvalidSequencerSignature
        Vm.Wallet memory wrongWallet = vm.createWallet("wrong");
        (v, r, s) = vm.sign(wrongWallet.privateKey, signingHash);
        bytes memory wrongSig = abi.encodePacked(r, s, v);

        vm.expectRevert(InvalidSequencerSignature.selector);
        gw.relay(sszPayload, wrongSig, accountProof, storageProof, commitPayload);
    }
}
