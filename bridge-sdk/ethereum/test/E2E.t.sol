// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ProofsLib} from "../src/lib/ProofsLib.sol";
import {InvalidChainHead, NothingChanged} from "../src/lib/BridgeErrors.sol";
import {IBridgeAdapter} from "../src/interfaces/IBridgeAdapter.sol";
import {IL1BlockHashOracle} from "../src/interfaces/IL1BlockHashOracle.sol";
import {CommitmentHelpers} from "./helpers/CommitmentHelpers.sol";

// ── Core contracts ──
import {WorldChainWorldId} from "../src/core/WorldChainWorldId.sol";
import {L1WorldId} from "../src/core/L1WorldId.sol";
import {UniversalWorldId} from "../src/core/UniversalWorldId.sol";
import {WorldIdBridge} from "../src/core/lib/WorldIdBridge.sol";

// ── Adapters + Receivers ──
import {ArbitrumAdapter} from "../src/adapters/arbitrum/ArbitrumAdapter.sol";
import {ArbitrumReceiver} from "../src/adapters/arbitrum/ArbitrumReceiver.sol";
import {ScrollAdapter} from "../src/adapters/scroll/ScrollAdapter.sol";
import {ScrollReceiver} from "../src/adapters/scroll/ScrollReceiver.sol";
import {ZkSyncAdapter} from "../src/adapters/zksync/ZkSyncAdapter.sol";
import {ZkSyncReceiver} from "../src/adapters/zksync/ZkSyncReceiver.sol";

// ── Vendored types ──
import {IDisputeGameFactory} from "../src/vendored/optimism/IDisputeGameFactory.sol";
import {IDisputeGame} from "../src/vendored/optimism/IDisputeGame.sol";
import {GameStatus, Claim, GameType, Timestamp} from "../src/vendored/optimism/DisputeTypes.sol";
import {IInbox} from "../src/vendored/arbitrum/IInbox.sol";
import {IL1ScrollMessenger} from "../src/vendored/scroll/IL1ScrollMessenger.sol";
import {IL2ScrollMessenger} from "../src/vendored/scroll/IL2ScrollMessenger.sol";
import {IMailbox} from "../src/vendored/zksync/IMailbox.sol";
import {IL1Block} from "../src/vendored/optimism/IL1Block.sol";
import {BabyJubJub} from "lib/oprf-key-registry/src/BabyJubJub.sol";

// ── Mock registries ──
import {MockWorldIDRegistry, MockIssuerRegistry, MockOprfKeyRegistry} from "./helpers/MockRegistries.sol";

// ═══════════════════════════════════════════════════════════
//                  MOCK CONTRACTS (local)
// ═══════════════════════════════════════════════════════════

/// @dev ABI-compatible mock for IDisputeGame.
contract MockDisputeGame {
    GameStatus internal _status;
    bytes32 internal _rootClaim;
    uint256 internal _l2BlockNumber;

    constructor(GameStatus s, bytes32 rc, uint256 bn) {
        _status = s;
        _rootClaim = rc;
        _l2BlockNumber = bn;
    }

    function status() external view returns (GameStatus) {
        return _status;
    }

    function rootClaim() external view returns (Claim) {
        return Claim.wrap(_rootClaim);
    }

    function l2BlockNumber() external view returns (uint256) {
        return _l2BlockNumber;
    }
}

/// @dev ABI-compatible mock for IDisputeGameFactory.
contract MockDisputeGameFactory {
    address[] internal _games;

    function addGame(address game) external {
        _games.push(game);
    }

    function gameCount() external view returns (uint256) {
        return _games.length;
    }

    function gameAtIndex(uint256 idx) external view returns (GameType, Timestamp, IDisputeGame) {
        return (GameType.wrap(0), Timestamp.wrap(0), IDisputeGame(_games[idx]));
    }
}

/// @dev Mock Arbitrum Inbox that records calls for assertion.
contract MockInbox is IInbox {
    struct RetryableTicket {
        address to;
        bytes data;
    }

    RetryableTicket[] public tickets;

    function createRetryableTicket(
        address to,
        uint256,
        uint256,
        address,
        address,
        uint256,
        uint256,
        bytes calldata data
    ) external payable returns (uint256) {
        tickets.push(RetryableTicket({to: to, data: data}));
        return tickets.length - 1;
    }

    function ticketCount() external view returns (uint256) {
        return tickets.length;
    }

    function getTicketData(uint256 index) external view returns (bytes memory) {
        return tickets[index].data;
    }
}

/// @dev Mock Scroll L1 Messenger that records calls.
contract MockL1ScrollMessenger is IL1ScrollMessenger {
    struct SentMessage {
        address target;
        bytes message;
    }

    SentMessage[] public messages;

    function sendMessage(address target, uint256, bytes calldata message, uint256) external payable {
        messages.push(SentMessage({target: target, message: message}));
    }

    function messageCount() external view returns (uint256) {
        return messages.length;
    }

    function getMessageData(uint256 index) external view returns (bytes memory) {
        return messages[index].message;
    }
}

/// @dev Mock Scroll L2 Messenger for cross-domain sender validation.
contract MockL2ScrollMessenger is IL2ScrollMessenger {
    address public xDomainSender;

    function setXDomainMessageSender(address sender) external {
        xDomainSender = sender;
    }

    function xDomainMessageSender() external view returns (address) {
        return xDomainSender;
    }
}

/// @dev Mock ZkSync Mailbox that records calls.
contract MockMailbox is IMailbox {
    struct L2Transaction {
        address contractL2;
        bytes calldata_;
    }

    L2Transaction[] public transactions;

    function requestL2Transaction(
        address _contractL2,
        uint256,
        bytes calldata _calldata,
        uint256,
        uint256,
        bytes[] calldata,
        address
    ) external payable returns (bytes32) {
        transactions.push(L2Transaction({contractL2: _contractL2, calldata_: _calldata}));
        return bytes32(transactions.length - 1);
    }

    function transactionCount() external view returns (uint256) {
        return transactions.length;
    }

    function getTransactionCalldata(uint256 index) external view returns (bytes memory) {
        return transactions[index].calldata_;
    }
}

/// @dev Mock L1 block hash oracle.
contract MockBlockHashOracle is IL1BlockHashOracle {
    mapping(bytes32 => bool) public validHashes;

    function setValid(bytes32 hash, bool valid) external {
        validHashes[hash] = valid;
    }

    function isValid(bytes32 blockHash) external view returns (bool) {
        return validHashes[blockHash];
    }
}

/// @dev Mock Verifier that always succeeds.
contract MockVerifier {
    function verifyCompressedProof(uint256[4] calldata, uint256[15] calldata) external pure {}
}

/// @dev Records all messages sent through it.
contract MockBridgeAdapter is IBridgeAdapter {
    bytes[] public receivedMessages;

    function sendMessage(bytes calldata message) external payable override {
        receivedMessages.push(message);
    }

    function receivedMessageCount() external view returns (uint256) {
        return receivedMessages.length;
    }

    function getReceivedMessage(uint256 index) external view returns (bytes memory) {
        return receivedMessages[index];
    }
}

// ═══════════════════════════════════════════════════════════
//                    E2E TEST BASE
// ═══════════════════════════════════════════════════════════

abstract contract E2EBase is CommitmentHelpers {
    using ProofsLib for ProofsLib.Chain;

    // ── Constants ──
    uint256 constant ROOT_VALIDITY_WINDOW = 1 hours;
    uint256 constant TREE_DEPTH = 30;
    uint64 constant MIN_EXPIRATION = 0;
    uint160 constant ALIAS_OFFSET = uint160(0x1111000000000000000000000000000000001111);

    address constant PLANTED_BRIDGE = address(uint160(uint256(keccak256("test.l1.bridge"))));
    address constant PLANTED_WC_BRIDGE = address(uint160(uint256(keccak256("test.wc.bridge"))));

    /// @dev Compute the chain head from a series of commitments starting at head=0.
    function _computeChainHead(ProofsLib.Commitment[] memory commits) internal pure returns (bytes32) {
        bytes32 head = bytes32(0);
        for (uint256 i; i < commits.length; ++i) {
            head = _chainHash(head, commits[i]);
        }
        return head;
    }

    // ── FFI helpers (reuse existing script) ──

    function _generateL1Proof(string memory rpc, bytes32 chainHead)
        internal
        returns (bytes memory mptProof, bytes32 rootClaim)
    {
        string[] memory args = new string[](6);
        args[0] = "bash";
        args[1] = "test/scripts/generate-bridge-proof.sh";
        args[2] = "wc-to-l1";
        args[3] = rpc;
        args[4] = vm.toString(PLANTED_WC_BRIDGE);
        args[5] = vm.toString(chainHead);
        bytes memory result = vm.ffi(args);
        (mptProof, rootClaim) = abi.decode(result, (bytes, bytes32));
    }

    function _generateDestProof(string memory rpc, bytes32 chainHead)
        internal
        returns (bytes memory mptProof, bytes32 blockHash)
    {
        string[] memory args = new string[](6);
        args[0] = "bash";
        args[1] = "test/scripts/generate-bridge-proof.sh";
        args[2] = "l1-to-dest";
        args[3] = rpc;
        args[4] = vm.toString(PLANTED_BRIDGE);
        args[5] = vm.toString(chainHead);
        bytes memory result = vm.ffi(args);
        (mptProof, blockHash) = abi.decode(result, (bytes, bytes32));
    }
}

// ═══════════════════════════════════════════════════════════
//       E2E: Full Pipeline — WC → L1 → All Destinations
// ═══════════════════════════════════════════════════════════

contract E2EFullPipelineTest is E2EBase {
    // ── Phase 1: WorldChainWorldId ──

    function test_e2e_fullPipeline_worldChainToAllDestinations() public {
        // ──────── Phase 1: World Chain propagateState ────────
        // Deploy mock registries with test state
        MockWorldIDRegistry wcRegistry = new MockWorldIDRegistry();
        MockIssuerRegistry wcIssuerRegistry = new MockIssuerRegistry();
        MockOprfKeyRegistry wcOprfRegistry = new MockOprfKeyRegistry();

        wcRegistry.setLatestRoot(TEST_ROOT);
        wcIssuerRegistry.setPubkey(TEST_ISSUER_ID, 111, 222);
        wcOprfRegistry.setKey(TEST_OPRF_ID, 333, 444);

        // Deploy WorldChainWorldId
        WorldChainWorldId wcSource = new WorldChainWorldId(
            address(wcRegistry),
            address(wcIssuerRegistry),
            address(wcOprfRegistry),
            ROOT_VALIDITY_WINDOW,
            TREE_DEPTH,
            MIN_EXPIRATION
        );

        // Mock IL1Block(address(0)).hash() → return test block hash
        vm.mockCall(address(0), abi.encodeWithSelector(IL1Block.hash.selector), abi.encode(TEST_BLOCK_HASH));

        // Call propagateState
        uint64[] memory issuerIds = new uint64[](1);
        issuerIds[0] = TEST_ISSUER_ID;
        uint160[] memory oprfIds = new uint160[](1);
        oprfIds[0] = TEST_OPRF_ID;

        wcSource.propagateState(issuerIds, oprfIds);

        // Read the chain head
        (bytes32 wcChainHead, uint64 wcChainLength) = wcSource.keccakChain();
        assertGt(uint256(wcChainHead), 0, "WC chain head should be non-zero");
        assertEq(wcChainLength, 3, "WC chain length = 3 (root + issuer + oprf)");

        // Verify WC state was written
        assertEq(wcSource.latestRoot(), TEST_ROOT, "WC latestRoot");
        assertTrue(wcSource.isValidRoot(TEST_ROOT), "WC isValidRoot");

        // ──────── Phase 2: Reconstruct commitments ────────
        // Reconstruct the same commitments that WorldChainWorldId produced
        bytes32 proofId = bytes32(block.number);
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](3);
        commits[0] = ProofsLib.Commitment({
            blockHash: TEST_BLOCK_HASH,
            data: abi.encodeWithSelector(UPDATE_ROOT_SEL, TEST_ROOT, block.timestamp, proofId)
        });
        commits[1] = ProofsLib.Commitment({
            blockHash: TEST_BLOCK_HASH,
            data: abi.encodeWithSelector(SET_ISSUER_SEL, TEST_ISSUER_ID, uint256(111), uint256(222), proofId)
        });
        commits[2] = ProofsLib.Commitment({
            blockHash: TEST_BLOCK_HASH,
            data: abi.encodeWithSelector(SET_OPRF_SEL, TEST_OPRF_ID, uint256(333), uint256(444), proofId)
        });

        // Verify chain head matches our reconstruction
        bytes32 expectedChainHead = _computeChainHead(commits);
        assertEq(wcChainHead, expectedChainHead, "WC chain head matches reconstruction");

        // ──────── Phase 3: L1 Relay commitChained with WC→L1 proof ────────
        string memory wcRpc = vm.envString("WORLDCHAIN_PROVIDER");
        (bytes memory wcMptProof, bytes32 rootClaim) = _generateL1Proof(wcRpc, expectedChainHead);

        // Deploy mock DisputeGame + Factory
        MockDisputeGame game = new MockDisputeGame(GameStatus.DEFENDER_WINS, rootClaim, 12345);
        MockDisputeGameFactory factory = new MockDisputeGameFactory();
        factory.addGame(address(game));

        // Deploy L1WorldId
        L1WorldId l1Relay = new L1WorldId(
            address(0),
            IDisputeGameFactory(address(factory)),
            PLANTED_WC_BRIDGE,
            ROOT_VALIDITY_WINDOW,
            TREE_DEPTH,
            MIN_EXPIRATION
        );

        // Register mock adapters for each destination
        MockBridgeAdapter arbAdapter = new MockBridgeAdapter();
        MockBridgeAdapter scrollAdapter = new MockBridgeAdapter();
        MockBridgeAdapter zkSyncAdapter = new MockBridgeAdapter();

        l1Relay.registerAdapter(IBridgeAdapter(address(arbAdapter)));
        l1Relay.registerAdapter(IBridgeAdapter(address(scrollAdapter)));
        l1Relay.registerAdapter(IBridgeAdapter(address(zkSyncAdapter)));

        // Encode mptProof with disputeGameIndex
        (bytes[] memory outputRootProof, bytes[] memory accountProof, bytes[] memory storageValidityProof) =
            abi.decode(wcMptProof, (bytes[], bytes[], bytes[]));
        bytes memory mptProofWithIndex = abi.encode(outputRootProof, accountProof, storageValidityProof, uint256(0));

        // Call commitChained on L1WorldId
        l1Relay.commitChained(ProofsLib.CommitmentWithProof({mptProof: mptProofWithIndex, commits: commits}));

        // Assert L1 state
        assertEq(l1Relay.latestRoot(), TEST_ROOT, "L1 latestRoot");
        assertTrue(l1Relay.isValidRoot(TEST_ROOT), "L1 isValidRoot");
        (bytes32 l1ChainHead, uint64 l1ChainLength) = l1Relay.keccakChain();
        assertEq(l1ChainHead, expectedChainHead, "L1 chain head matches WC");
        assertEq(l1ChainLength, 3, "L1 chain length");

        // Assert all adapters received the dispatched message
        assertEq(arbAdapter.receivedMessageCount(), 1, "Arb adapter received 1 message");
        assertEq(scrollAdapter.receivedMessageCount(), 1, "Scroll adapter received 1 message");
        assertEq(zkSyncAdapter.receivedMessageCount(), 1, "ZkSync adapter received 1 message");

        // ──────── Phase 4: Native Receivers ────────
        MockVerifier verifier = new MockVerifier();

        // 4a. ArbitrumReceiver
        ArbitrumReceiver arbReceiver =
            new ArbitrumReceiver(address(verifier), address(l1Relay), ROOT_VALIDITY_WINDOW, TREE_DEPTH, MIN_EXPIRATION);
        {
            address aliased = address(uint160(address(l1Relay)) + ALIAS_OFFSET);
            vm.prank(aliased);
            arbReceiver.commitFromL1(commits);
        }
        assertEq(arbReceiver.latestRoot(), TEST_ROOT, "Arb latestRoot");
        assertTrue(arbReceiver.isValidRoot(TEST_ROOT), "Arb isValidRoot");
        {
            (bytes32 arbHead, uint64 arbLen) = arbReceiver.keccakChain();
            assertEq(arbHead, expectedChainHead, "Arb chain head");
            assertEq(arbLen, 3, "Arb chain length");
        }

        // 4b. ScrollReceiver
        MockL2ScrollMessenger scrollMessenger = new MockL2ScrollMessenger();
        ScrollReceiver scrollReceiver = new ScrollReceiver(
            address(verifier),
            address(l1Relay),
            IL2ScrollMessenger(address(scrollMessenger)),
            ROOT_VALIDITY_WINDOW,
            TREE_DEPTH,
            MIN_EXPIRATION
        );
        scrollMessenger.setXDomainMessageSender(address(l1Relay));
        {
            vm.prank(address(scrollMessenger));
            scrollReceiver.commitFromL1(commits);
        }
        assertEq(scrollReceiver.latestRoot(), TEST_ROOT, "Scroll latestRoot");
        assertTrue(scrollReceiver.isValidRoot(TEST_ROOT), "Scroll isValidRoot");
        {
            (bytes32 scrollHead, uint64 scrollLen) = scrollReceiver.keccakChain();
            assertEq(scrollHead, expectedChainHead, "Scroll chain head");
            assertEq(scrollLen, 3, "Scroll chain length");
        }

        // 4c. ZkSyncReceiver
        ZkSyncReceiver zkReceiver =
            new ZkSyncReceiver(address(verifier), address(l1Relay), ROOT_VALIDITY_WINDOW, TREE_DEPTH, MIN_EXPIRATION);
        {
            address aliased = address(uint160(address(l1Relay)) + ALIAS_OFFSET);
            vm.prank(aliased);
            zkReceiver.commitFromL1(commits);
        }
        assertEq(zkReceiver.latestRoot(), TEST_ROOT, "ZkSync latestRoot");
        assertTrue(zkReceiver.isValidRoot(TEST_ROOT), "ZkSync isValidRoot");
        {
            (bytes32 zkHead, uint64 zkLen) = zkReceiver.keccakChain();
            assertEq(zkHead, expectedChainHead, "ZkSync chain head");
            assertEq(zkLen, 3, "ZkSync chain length");
        }

        // ──────── Phase 5: UniversalWorldId with L1→dest proof ────────
        string memory l1Rpc = vm.envString("ETHEREUM_PROVIDER");
        (bytes memory l1MptProof, bytes32 l1BlockHash) = _generateDestProof(l1Rpc, expectedChainHead);

        MockBlockHashOracle oracle = new MockBlockHashOracle();
        oracle.setValid(l1BlockHash, true);

        UniversalWorldId universalReceiver = new UniversalWorldId(
            address(verifier), address(oracle), PLANTED_BRIDGE, ROOT_VALIDITY_WINDOW, TREE_DEPTH, MIN_EXPIRATION
        );

        universalReceiver.commitChained(ProofsLib.CommitmentWithProof({mptProof: l1MptProof, commits: commits}));

        assertEq(universalReceiver.latestRoot(), TEST_ROOT, "Universal latestRoot");
        assertTrue(universalReceiver.isValidRoot(TEST_ROOT), "Universal isValidRoot");
        {
            (bytes32 uniHead, uint64 uniLen) = universalReceiver.keccakChain();
            assertEq(uniHead, expectedChainHead, "Universal chain head");
            assertEq(uniLen, 3, "Universal chain length");
        }

        // ──────── Phase 6: Cross-chain Consistency ────────
        // All 5 bridges should have identical state
        _assertBridgeState(l1Relay, expectedChainHead, 3, "L1WorldId");
        _assertBridgeState(arbReceiver, expectedChainHead, 3, "Arb");
        _assertBridgeState(scrollReceiver, expectedChainHead, 3, "Scroll");
        _assertBridgeState(zkReceiver, expectedChainHead, 3, "ZkSync");
        _assertBridgeState(universalReceiver, expectedChainHead, 3, "Universal");

        // Verify issuer pubkey on L1 and receivers that expose it
        _assertIssuerPubkey(l1Relay, TEST_ISSUER_ID, 111, 222, "L1WorldId");
        _assertIssuerPubkey(arbReceiver, TEST_ISSUER_ID, 111, 222, "Arb");
        _assertIssuerPubkey(scrollReceiver, TEST_ISSUER_ID, 111, 222, "Scroll");
        _assertIssuerPubkey(zkReceiver, TEST_ISSUER_ID, 111, 222, "ZkSync");
        _assertIssuerPubkey(universalReceiver, TEST_ISSUER_ID, 111, 222, "Universal");
    }

    // ── Helpers ──

    function _assertBridgeState(WorldIdBridge bridge, bytes32 expectedHead, uint64 expectedLen, string memory label)
        internal
        view
    {
        assertEq(bridge.latestRoot(), TEST_ROOT, string.concat(label, " latestRoot"));
        assertTrue(bridge.isValidRoot(TEST_ROOT), string.concat(label, " isValidRoot"));
        (bytes32 head, uint64 length) = bridge.keccakChain();
        assertEq(head, expectedHead, string.concat(label, " chain head"));
        assertEq(length, expectedLen, string.concat(label, " chain length"));
    }

    function _assertIssuerPubkey(WorldIdBridge bridge, uint64 schemaId, uint256 x, uint256 y, string memory label)
        internal
        view
    {
        (BabyJubJub.Affine memory pk,) = bridge.issuerSchemaIdToPubkeyAndProofId(schemaId);
        assertEq(pk.x, x, string.concat(label, " issuer x"));
        assertEq(pk.y, y, string.concat(label, " issuer y"));
    }
}

// ═══════════════════════════════════════════════════════════
//       E2E: Multiple Rounds — State Accumulation
// ═══════════════════════════════════════════════════════════

contract E2EMultipleRoundsTest is E2EBase {
    function test_e2e_multipleRounds_stateAccumulation() public {
        // Deploy mock registries
        MockWorldIDRegistry wcRegistry = new MockWorldIDRegistry();
        MockIssuerRegistry wcIssuerRegistry = new MockIssuerRegistry();
        MockOprfKeyRegistry wcOprfRegistry = new MockOprfKeyRegistry();

        // Deploy WorldChainWorldId
        WorldChainWorldId wcSource = new WorldChainWorldId(
            address(wcRegistry),
            address(wcIssuerRegistry),
            address(wcOprfRegistry),
            ROOT_VALIDITY_WINDOW,
            TREE_DEPTH,
            MIN_EXPIRATION
        );

        // Mock IL1Block
        vm.mockCall(address(0), abi.encodeWithSelector(IL1Block.hash.selector), abi.encode(TEST_BLOCK_HASH));

        uint64[] memory issuerIds = new uint64[](0);
        uint160[] memory oprfIds = new uint160[](0);

        // ── Round 1: propagate root 100 ──
        uint256 root1 = 100;
        wcRegistry.setLatestRoot(root1);
        wcSource.propagateState(issuerIds, oprfIds);

        (bytes32 head1, uint64 len1) = wcSource.keccakChain();
        assertEq(len1, 1, "Round 1: chain length = 1");
        assertEq(wcSource.latestRoot(), root1, "Round 1: latestRoot");
        assertTrue(wcSource.isValidRoot(root1), "Round 1: isValidRoot");

        // ── Round 2: propagate root 200 (in a new block) ──
        uint256 root2 = 200;
        wcRegistry.setLatestRoot(root2);
        vm.roll(block.number + 1);
        wcSource.propagateState(issuerIds, oprfIds);

        (bytes32 head2, uint64 len2) = wcSource.keccakChain();
        assertEq(len2, 2, "Round 2: chain length = 2");
        assertEq(wcSource.latestRoot(), root2, "Round 2: latestRoot");
        assertTrue(wcSource.isValidRoot(root2), "Round 2: new root valid");

        // Previous root should still be valid within window
        assertTrue(wcSource.isValidRoot(root1), "Round 2: old root still valid within window");

        // Chain head should have advanced
        assertNotEq(head1, head2, "Chain head changed between rounds");
    }

    function test_e2e_nothingChanged_reverts() public {
        MockWorldIDRegistry wcRegistry = new MockWorldIDRegistry();
        MockIssuerRegistry wcIssuerRegistry = new MockIssuerRegistry();
        MockOprfKeyRegistry wcOprfRegistry = new MockOprfKeyRegistry();

        WorldChainWorldId wcSource = new WorldChainWorldId(
            address(wcRegistry),
            address(wcIssuerRegistry),
            address(wcOprfRegistry),
            ROOT_VALIDITY_WINDOW,
            TREE_DEPTH,
            MIN_EXPIRATION
        );

        vm.mockCall(address(0), abi.encodeWithSelector(IL1Block.hash.selector), abi.encode(TEST_BLOCK_HASH));

        // Set root and propagate once
        wcRegistry.setLatestRoot(42);
        uint64[] memory issuerIds = new uint64[](0);
        uint160[] memory oprfIds = new uint160[](0);
        wcSource.propagateState(issuerIds, oprfIds);

        // Try to propagate again without changes — should revert
        vm.expectRevert(NothingChanged.selector);
        wcSource.propagateState(issuerIds, oprfIds);
    }
}

// ═══════════════════════════════════════════════════════════
//      E2E: ProofId Invalidation Propagation
// ═══════════════════════════════════════════════════════════

contract E2EProofIdInvalidationTest is E2EBase {
    function test_e2e_proofIdInvalidation_propagatesAcrossChain() public {
        // Build initial commitments (root + issuer) then follow with invalidation
        bytes32 proofId = bytes32(uint256(42));

        // Round 1: valid commitments
        ProofsLib.Commitment[] memory setup = new ProofsLib.Commitment[](1);
        setup[0] = _makeUpdateRootCommitment(TEST_ROOT, block.timestamp, proofId, TEST_BLOCK_HASH);
        bytes32 setupHead = _computeChainHead(setup);

        // Round 2: invalidation commitment (separate batch)
        ProofsLib.Commitment[] memory inv = new ProofsLib.Commitment[](1);
        inv[0] = _makeInvalidateCommitment(proofId, TEST_BLOCK_HASH);

        // Compute final chain head from both rounds
        bytes32 invHead;
        {
            bytes32 h = _chainHash(setupHead, inv[0]);
            invHead = h;
        }

        // Deploy ArbitrumReceiver and apply both rounds
        MockVerifier verifier = new MockVerifier();
        address l1Bridge = address(0xBEEF);
        ArbitrumReceiver receiver =
            new ArbitrumReceiver(address(verifier), l1Bridge, ROOT_VALIDITY_WINDOW, TREE_DEPTH, MIN_EXPIRATION);

        address aliased = address(uint160(l1Bridge) + ALIAS_OFFSET);

        // Round 1
        vm.prank(aliased);
        receiver.commitFromL1(setup);
        assertTrue(receiver.isValidRoot(TEST_ROOT), "Root valid before invalidation");

        // Round 2
        vm.prank(aliased);
        receiver.commitFromL1(inv);
        assertFalse(receiver.isValidRoot(TEST_ROOT), "Root invalid after proofId invalidation");
        assertTrue(receiver.invalidatedProofIds(proofId), "ProofId marked invalidated");

        (bytes32 head, uint64 length) = receiver.keccakChain();
        assertEq(head, invHead, "Chain head correct after both rounds");
        assertEq(length, 2, "Chain length = 2");
    }
}

// ═══════════════════════════════════════════════════════════
//      E2E: Wrong Proof Reverts
// ═══════════════════════════════════════════════════════════

contract E2EWrongProofTest is E2EBase {
    function test_e2e_wrongProof_revertsOnUniversalReceiver() public {
        // Build commitments hashing to chainHead1 but generate proof for chainHead2
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, block.timestamp, TEST_PROOF_ID, TEST_BLOCK_HASH);
        bytes32 realHead = _computeChainHead(commits);

        // Wrong head — different from what the commits hash to
        bytes32 wrongHead = keccak256(abi.encodePacked(realHead, bytes32(uint256(1))));

        // Generate proof for wrongHead
        string memory l1Rpc = vm.envString("ETHEREUM_PROVIDER");
        (bytes memory mptProof, bytes32 blockHash) = _generateDestProof(l1Rpc, wrongHead);

        MockBlockHashOracle oracle = new MockBlockHashOracle();
        oracle.setValid(blockHash, true);
        MockVerifier verifier = new MockVerifier();

        UniversalWorldId receiver = new UniversalWorldId(
            address(verifier), address(oracle), PLANTED_BRIDGE, ROOT_VALIDITY_WINDOW, TREE_DEPTH, MIN_EXPIRATION
        );

        // Should revert because the chain head computed from commits != the chain head in the proof
        vm.expectRevert(InvalidChainHead.selector);
        receiver.commitChained(ProofsLib.CommitmentWithProof({mptProof: mptProof, commits: commits}));
    }

    function test_e2e_wrongProof_revertsOnL1Relay() public {
        // Build a commitment and generate WC→L1 proof for a different chain head
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, block.timestamp, TEST_PROOF_ID, TEST_BLOCK_HASH);
        bytes32 realHead = _computeChainHead(commits);
        bytes32 wrongHead = keccak256(abi.encodePacked(realHead, bytes32(uint256(0xBAD))));

        string memory wcRpc = vm.envString("WORLDCHAIN_PROVIDER");
        (bytes memory wcMptProof, bytes32 rootClaim) = _generateL1Proof(wcRpc, wrongHead);

        MockDisputeGame game = new MockDisputeGame(GameStatus.DEFENDER_WINS, rootClaim, 12345);
        MockDisputeGameFactory factory = new MockDisputeGameFactory();
        factory.addGame(address(game));

        L1WorldId l1Relay = new L1WorldId(
            address(0),
            IDisputeGameFactory(address(factory)),
            PLANTED_WC_BRIDGE,
            ROOT_VALIDITY_WINDOW,
            TREE_DEPTH,
            MIN_EXPIRATION
        );

        (bytes[] memory outputRootProof, bytes[] memory accountProof, bytes[] memory storageValidityProof) =
            abi.decode(wcMptProof, (bytes[], bytes[], bytes[]));
        bytes memory mptProofWithIndex = abi.encode(outputRootProof, accountProof, storageValidityProof, uint256(0));

        vm.expectRevert();
        l1Relay.commitChained(ProofsLib.CommitmentWithProof({mptProof: mptProofWithIndex, commits: commits}));
    }
}

// ═══════════════════════════════════════════════════════════
//      E2E: Adapter Dispatch Message Integrity
// ═══════════════════════════════════════════════════════════

contract E2EAdapterDispatchTest is E2EBase {
    function test_e2e_adapterDispatch_messageIntegrity() public {
        // Build commitments and push through L1WorldId → mock adapters
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](2);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, block.timestamp, TEST_PROOF_ID, TEST_BLOCK_HASH);
        commits[1] = _makeSetIssuerCommitment(TEST_ISSUER_ID, 111, 222, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes32 expectedHead = _computeChainHead(commits);

        // Deploy L1WorldId with real WC proof
        string memory wcRpc = vm.envString("WORLDCHAIN_PROVIDER");
        (bytes memory wcMptProof, bytes32 rootClaim) = _generateL1Proof(wcRpc, expectedHead);

        MockDisputeGame game = new MockDisputeGame(GameStatus.DEFENDER_WINS, rootClaim, 12345);
        MockDisputeGameFactory factory = new MockDisputeGameFactory();
        factory.addGame(address(game));

        L1WorldId l1Relay = new L1WorldId(
            address(0),
            IDisputeGameFactory(address(factory)),
            PLANTED_WC_BRIDGE,
            ROOT_VALIDITY_WINDOW,
            TREE_DEPTH,
            MIN_EXPIRATION
        );

        // Register real mock adapters (Arb inbox, Scroll messenger, ZkSync mailbox)
        MockInbox arbInbox = new MockInbox();
        address arbTarget = address(0xA1);
        ArbitrumAdapter arbAdapter =
            new ArbitrumAdapter(IInbox(address(arbInbox)), arbTarget, 0.01 ether, 1_000_000, 100 gwei);

        MockL1ScrollMessenger scrollMessenger = new MockL1ScrollMessenger();
        address scrollTarget = address(0x5C01);
        ScrollAdapter scrollAdapt =
            new ScrollAdapter(IL1ScrollMessenger(address(scrollMessenger)), scrollTarget, 500_000);

        MockMailbox zkMailbox = new MockMailbox();
        address zkTarget = address(0x2C01);
        ZkSyncAdapter zkAdapter = new ZkSyncAdapter(IMailbox(address(zkMailbox)), zkTarget, 2_000_000, 800);

        l1Relay.registerAdapter(IBridgeAdapter(address(arbAdapter)));
        l1Relay.registerAdapter(IBridgeAdapter(address(scrollAdapt)));
        l1Relay.registerAdapter(IBridgeAdapter(address(zkAdapter)));

        // Commit
        (bytes[] memory outputRootProof, bytes[] memory accountProof, bytes[] memory storageValidityProof) =
            abi.decode(wcMptProof, (bytes[], bytes[], bytes[]));
        bytes memory mptProofWithIndex = abi.encode(outputRootProof, accountProof, storageValidityProof, uint256(0));

        l1Relay.commitChained(ProofsLib.CommitmentWithProof({mptProof: mptProofWithIndex, commits: commits}));

        // Build the expected commitFromL1 message
        bytes memory expectedMessage = _encodeCommitFromL1(commits);

        // Verify Arbitrum inbox received the message
        assertEq(arbInbox.ticketCount(), 1, "Arb inbox ticket count");
        bytes memory arbData = arbInbox.getTicketData(0);
        assertEq(keccak256(arbData), keccak256(expectedMessage), "Arb message matches");

        // Verify Scroll messenger received the message
        assertEq(scrollMessenger.messageCount(), 1, "Scroll message count");
        bytes memory scrollData = scrollMessenger.getMessageData(0);
        assertEq(keccak256(scrollData), keccak256(expectedMessage), "Scroll message matches");

        // Verify ZkSync mailbox received the message
        assertEq(zkMailbox.transactionCount(), 1, "ZkSync tx count");
        bytes memory zkData = zkMailbox.getTransactionCalldata(0);
        assertEq(keccak256(zkData), keccak256(expectedMessage), "ZkSync message matches");

        // Decode the dispatched message to verify commitment integrity
        // The message is abi.encodeCall(INativeReceiver.commitFromL1, (commits))
        // Skip the 4-byte selector
        bytes memory encodedCommits = new bytes(arbData.length - 4);
        for (uint256 i = 4; i < arbData.length; ++i) {
            encodedCommits[i - 4] = arbData[i];
        }
        ProofsLib.Commitment[] memory decodedCommits = abi.decode(encodedCommits, (ProofsLib.Commitment[]));

        assertEq(decodedCommits.length, 2, "Decoded 2 commits from dispatch");
        assertEq(decodedCommits[0].blockHash, commits[0].blockHash, "Commit 0 blockHash");
        assertEq(keccak256(decodedCommits[0].data), keccak256(commits[0].data), "Commit 0 data");
        assertEq(decodedCommits[1].blockHash, commits[1].blockHash, "Commit 1 blockHash");
        assertEq(keccak256(decodedCommits[1].data), keccak256(commits[1].data), "Commit 1 data");
    }
}
