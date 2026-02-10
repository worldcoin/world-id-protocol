// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {WorldChainStateAdapter} from "../src/bridge-sdk/adapters/WorldChainStateAdapter.sol";
import {L1StateAdapter} from "../src/bridge-sdk/adapters/L1StateAdapter.sol";
import {BridgedStateAdapter} from "../src/bridge-sdk/adapters/BridgedStateAdapter.sol";
import {OpStackBridgeAdapter} from "../src/bridge-sdk/adapters/op/OpStackBridgeAdapter.sol";
import {WorldIdStateBridge} from "../src/bridge-sdk/abstract/WorldIdStateBridge.sol";
import {IWorldIdStateBridge} from "../src/bridge-sdk/interfaces/IWorldIdStateBridge.sol";
import {IBridgeAdapter} from "../src/bridge-sdk/interfaces/IBridgeAdapter.sol";
import {IL1BlockHashOracle} from "../src/bridge-sdk/interfaces/IL1BlockHashOracle.sol";
import {StateChainTypes} from "../src/bridge-sdk/libraries/StateChainTypes.sol";
import {IDisputeGameFactory} from "../src/bridge-sdk/vendored/optimism/IDisputeGameFactory.sol";
import {IDisputeGame} from "../src/bridge-sdk/vendored/optimism/IDisputeGame.sol";
import {ICrossDomainMessenger} from "../src/bridge-sdk/vendored/optimism/ICrossDomainMessenger.sol";
import {GameStatus, Claim, GameType, Timestamp} from "../src/bridge-sdk/vendored/optimism/DisputeTypes.sol";

// ═══════════════════════════════════════════════════════════════
//                         MOCKS & HARNESSES
// ═══════════════════════════════════════════════════════════════

contract MockBridgeAdapter is IBridgeAdapter {
    bytes[] internal _msgs;

    function sendMessage(bytes calldata message) external payable {
        _msgs.push(message);
    }

    function msgCount() external view returns (uint256) {
        return _msgs.length;
    }

    function getMsg(uint256 i) external view returns (bytes memory) {
        return _msgs[i];
    }
}

contract MockL1BlockHashOracle is IL1BlockHashOracle {
    mapping(bytes32 => bool) public known;

    function setKnown(bytes32 h) external {
        known[h] = true;
    }

    function isKnownL1BlockHash(bytes32 h) external view returns (bool) {
        return known[h];
    }
}

contract MockWorldIDRegistry {
    uint256 public latestRoot;

    function setLatestRoot(uint256 root) external {
        latestRoot = root;
    }

    function getLatestRoot() external view returns (uint256) {
        return latestRoot;
    }
}

contract MockIssuerRegistry {
    mapping(uint64 => uint256) internal _x;
    mapping(uint64 => uint256) internal _y;

    function setPubkey(uint64 id, uint256 x, uint256 y) external {
        _x[id] = x;
        _y[id] = y;
    }

    function issuerSchemaIdToPubkey(uint64 id) external view returns (uint256, uint256) {
        return (_x[id], _y[id]);
    }
}

contract MockOprfRegistry {
    mapping(uint160 => uint256) internal _x;
    mapping(uint160 => uint256) internal _y;

    function setKey(uint160 id, uint256 x, uint256 y) external {
        _x[id] = x;
        _y[id] = y;
    }

    function getOprfPublicKey(uint160 id) external view returns (uint256, uint256) {
        return (_x[id], _y[id]);
    }
}

/// @dev Mock dispute game — ABI-compatible with IDisputeGame but uses view (not pure) for
///   rootClaim/l2BlockNumber since values are stored in state.
contract MockDisputeGame {
    GameStatus internal _status;
    Claim internal _rootClaim;
    uint256 internal _l2BlockNumber;

    constructor(GameStatus status_, Claim rootClaim_, uint256 l2BlockNumber_) {
        _status = status_;
        _rootClaim = rootClaim_;
        _l2BlockNumber = l2BlockNumber_;
    }

    function status() external view returns (GameStatus) {
        return _status;
    }

    function rootClaim() external view returns (Claim) {
        return _rootClaim;
    }

    function l2BlockNumber() external view returns (uint256) {
        return _l2BlockNumber;
    }
}

contract MockDisputeGameFactory is IDisputeGameFactory {
    IDisputeGame[] internal _games;

    function addGame(IDisputeGame game) external {
        _games.push(game);
    }

    function gameAtIndex(uint256 index) external view returns (GameType, Timestamp, IDisputeGame) {
        return (GameType.wrap(0), Timestamp.wrap(0), _games[index]);
    }

    function gameCount() external view returns (uint256) {
        return _games.length;
    }
}

/// @dev Mock cross-domain messenger that records outbound messages and can simulate relays.
contract MockCrossDomainMessenger {
    address internal _xDomainMessageSender;
    address public lastTarget;
    bytes public lastMessage;
    uint32 public lastMinGasLimit;

    function sendMessage(address target, bytes calldata message, uint32 minGasLimit) external payable {
        lastTarget = target;
        lastMessage = message;
        lastMinGasLimit = minGasLimit;
    }

    function xDomainMessageSender() external view returns (address) {
        return _xDomainMessageSender;
    }

    /// @dev Simulates messenger relay: sets xDomainSender, calls target, clears sender.
    function relayMessage(address target, address sender, bytes calldata message) external {
        _xDomainMessageSender = sender;
        (bool ok, bytes memory ret) = target.call(message);
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        _xDomainMessageSender = address(0);
    }
}

/// @dev WC harness: WorldChainStateAdapter with mock registries. Exposes chain state for testing.
contract WCHarness is WorldChainStateAdapter {
    constructor(address registry, address issuerRegistry, address oprfRegistry)
        WorldChainStateAdapter(registry, issuerRegistry, oprfRegistry, 1 hours, 30)
    {}

    function isValidHead(bytes32 head) external view returns (bool) {
        return _validChainHeads[head];
    }
}

/// @dev L1 harness: L1StateAdapter with direct chain head manipulation for testing.
contract L1Harness is L1StateAdapter {
    constructor(IDisputeGameFactory factory, ICrossDomainMessenger messenger, address remoteAdapter)
        L1StateAdapter(factory, address(2), messenger, remoteAdapter, 1 hours, 30)
    {}

    function setValidChainHead(bytes32 head) external {
        _validChainHeads[head] = true;
    }

    function isValidChainHead(bytes32 head) external view returns (bool) {
        return _validChainHeads[head];
    }
}

/// @dev Destination harness that replaces MPT verification with a simple expected-head check.
contract DestHarness is BridgedStateAdapter {
    bytes32 public validHead;

    constructor(IL1BlockHashOracle oracle, address l1Bridge, ICrossDomainMessenger messenger, address remoteAdapter)
        BridgedStateAdapter(oracle, l1Bridge, messenger, remoteAdapter, address(5), 1 hours, 30)
    {}

    function setValidHead(bytes32 head) external {
        validHead = head;
    }

    function _verifyChainHead(bytes32 computedHead, bytes calldata) internal view override {
        require(computedHead == validHead, "DestHarness: chain head mismatch");
    }
}

// ═══════════════════════════════════════════════════════════════
//                          TEST SUITE
// ═══════════════════════════════════════════════════════════════

contract StateChainTest is Test {
    WCHarness wc;
    L1Harness l1;
    DestHarness dest;
    MockBridgeAdapter adapter1;
    MockBridgeAdapter adapter2;
    MockL1BlockHashOracle oracle;
    MockWorldIDRegistry mockRegistry;
    MockIssuerRegistry mockIssuerRegistry;
    MockOprfRegistry mockOprfRegistry;
    MockDisputeGameFactory mockFactory;
    MockCrossDomainMessenger l1Messenger;
    MockCrossDomainMessenger destMessenger;

    address constant REMOTE_ADAPTER = address(0x7777);

    uint256 constant ROOT = 0xdeadbeef;
    uint64 constant ISSUER_ID = 0x5a7400653dd6d18a;
    uint160 constant OPRF_ID = uint160(ISSUER_ID);
    uint256 constant PK_X = 123_456_789;
    uint256 constant PK_Y = 987_654_321;

    function setUp() public {
        mockRegistry = new MockWorldIDRegistry();
        mockIssuerRegistry = new MockIssuerRegistry();
        mockOprfRegistry = new MockOprfRegistry();
        mockFactory = new MockDisputeGameFactory();
        l1Messenger = new MockCrossDomainMessenger();
        destMessenger = new MockCrossDomainMessenger();

        wc = new WCHarness(address(mockRegistry), address(mockIssuerRegistry), address(mockOprfRegistry));
        l1 = new L1Harness(
            IDisputeGameFactory(address(mockFactory)), ICrossDomainMessenger(address(l1Messenger)), REMOTE_ADAPTER
        );

        oracle = new MockL1BlockHashOracle();
        adapter1 = new MockBridgeAdapter();
        adapter2 = new MockBridgeAdapter();
        dest = new DestHarness(
            IL1BlockHashOracle(address(oracle)),
            address(l1),
            ICrossDomainMessenger(address(destMessenger)),
            REMOTE_ADAPTER
        );

        mockRegistry.setLatestRoot(ROOT);
        mockIssuerRegistry.setPubkey(ISSUER_ID, PK_X, PK_Y);
        mockOprfRegistry.setKey(OPRF_ID, PK_X, PK_Y);
    }

    // ════════════════════════════════════════════════
    //          WC PROPAGATION
    // ════════════════════════════════════════════════

    function test_propagateRoot() public {
        assertEq(wc.chainHead(), bytes32(0));

        wc.propagateRoot();

        assertTrue(wc.chainHead() != bytes32(0));
        assertEq(wc.getLatestRoot(), ROOT);
        assertTrue(wc.isValidHead(wc.chainHead()));
    }

    function test_propagateIssuerPubkey() public {
        wc.propagateIssuerPubkey(ISSUER_ID);

        assertTrue(wc.chainHead() != bytes32(0));
        (uint256 x, uint256 y) = wc.issuerPubkey(ISSUER_ID);
        assertEq(x, PK_X);
        assertEq(y, PK_Y);
        assertTrue(wc.isValidHead(wc.chainHead()));
    }

    function test_propagateOprfKey() public {
        wc.propagateOprfKey(OPRF_ID);

        assertTrue(wc.chainHead() != bytes32(0));
        (uint256 x, uint256 y) = wc.oprfKey(OPRF_ID);
        assertEq(x, PK_X);
        assertEq(y, PK_Y);
        assertTrue(wc.isValidHead(wc.chainHead()));
    }

    function test_propagateRoot_proofIdIsBlockNumber() public {
        wc.propagateRoot();

        uint256 root = wc.getLatestRoot();
        assertTrue(wc.isValidRoot(root));
        assertEq(wc.getRootTimestamp(root), block.timestamp);
    }

    function test_propagateRoot_duplicateReverts() public {
        wc.propagateRoot();

        vm.expectRevert(WorldChainStateAdapter.RootNotChanged.selector);
        wc.propagateRoot();
    }

    function test_propagateIssuerPubkey_duplicateReverts() public {
        wc.propagateIssuerPubkey(ISSUER_ID);

        vm.expectRevert(WorldChainStateAdapter.IssuerPubkeyNotChanged.selector);
        wc.propagateIssuerPubkey(ISSUER_ID);
    }

    function test_propagateOprfKey_duplicateReverts() public {
        wc.propagateOprfKey(OPRF_ID);

        vm.expectRevert(WorldChainStateAdapter.OprfKeyNotChanged.selector);
        wc.propagateOprfKey(OPRF_ID);
    }

    // ════════════════════════════════════════════════
    //          WC CHAIN EXTENSION
    // ════════════════════════════════════════════════

    function test_chainExtension_rollingHash() public {
        wc.propagateRoot();
        bytes32 head1 = wc.chainHead();

        wc.propagateIssuerPubkey(ISSUER_ID);
        bytes32 head2 = wc.chainHead();

        wc.propagateOprfKey(OPRF_ID);
        bytes32 head3 = wc.chainHead();

        assertTrue(head1 != head2 && head2 != head3);
        assertTrue(wc.isValidHead(head1));
        assertTrue(wc.isValidHead(head2));
        assertTrue(wc.isValidHead(head3));
    }

    function test_chainExtension_emitsChainExtended() public {
        bytes32 bh = blockhash(block.number - 1);
        bytes memory data = abi.encode(ROOT, block.timestamp, bytes32(block.number));
        bytes32 expected = keccak256(abi.encode(bytes32(0), bh, StateChainTypes.ACTION_SET_ROOT, data));

        vm.expectEmit(true, false, false, true, address(wc));
        emit WorldChainStateAdapter.ChainExtended(expected, StateChainTypes.ACTION_SET_ROOT, data);

        wc.propagateRoot();
    }

    // ════════════════════════════════════════════════
    //      WC processChainedCommits (disabled)
    // ════════════════════════════════════════════════

    function test_wc_processChainedCommits_reverts() public {
        StateChainTypes.ChainedCommit[] memory commits = new StateChainTypes.ChainedCommit[](1);
        commits[0] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_ROOT,
            blockHash: bytes32(0),
            data: abi.encode(ROOT, block.timestamp, bytes32(block.number))
        });

        vm.expectRevert(IWorldIdStateBridge.InvalidChainHead.selector);
        wc.processChainedCommits(commits, "");
    }

    // ════════════════════════════════════════════════
    //      WC receiveChainedCommit (disabled)
    // ════════════════════════════════════════════════

    function test_wc_receiveChainedCommit_reverts() public {
        vm.expectRevert(IWorldIdStateBridge.Unauthorized.selector);
        wc.receiveChainedCommit(
            StateChainTypes.ACTION_SET_ROOT, bytes32(0), abi.encode(ROOT, block.timestamp, bytes32(block.number))
        );
    }

    // ════════════════════════════════════════════════
    //   L1/DEST receiveChainedCommit (auth reverts)
    // ════════════════════════════════════════════════

    function test_l1_receiveChainedCommit_directCallReverts() public {
        vm.expectRevert(IWorldIdStateBridge.Unauthorized.selector);
        l1.receiveChainedCommit(
            StateChainTypes.ACTION_SET_ROOT, bytes32(0), abi.encode(ROOT, block.timestamp, bytes32(block.number))
        );
    }

    function test_dest_receiveChainedCommit_directCallReverts() public {
        vm.expectRevert(IWorldIdStateBridge.Unauthorized.selector);
        dest.receiveChainedCommit(
            StateChainTypes.ACTION_SET_ROOT, bytes32(0), abi.encode(ROOT, block.timestamp, bytes32(block.number))
        );
    }

    // ════════════════════════════════════════════════
    //          ADAPTER DISPATCH (WC)
    // ════════════════════════════════════════════════

    function test_adapterDispatch_singleAdapter() public {
        wc.registerAdapter(IBridgeAdapter(address(adapter1)));
        wc.propagateRoot();

        assertEq(adapter1.msgCount(), 1);
    }

    function test_adapterDispatch_multipleAdapters() public {
        wc.registerAdapter(IBridgeAdapter(address(adapter1)));
        wc.registerAdapter(IBridgeAdapter(address(adapter2)));
        wc.propagateRoot();

        assertEq(adapter1.msgCount(), 1);
        assertEq(adapter2.msgCount(), 1);
        assertEq(adapter1.getMsg(0), adapter2.getMsg(0));
    }

    function test_adapterDispatch_messageFormat() public {
        wc.registerAdapter(IBridgeAdapter(address(adapter1)));

        bytes32 bh = blockhash(block.number - 1);
        wc.propagateRoot();

        bytes4 sel = bytes4(keccak256("receiveChainedCommit(uint8,bytes32,bytes)"));
        bytes memory data = abi.encode(ROOT, block.timestamp, bytes32(block.number));
        bytes memory expected = abi.encodeWithSelector(sel, StateChainTypes.ACTION_SET_ROOT, bh, data);

        assertEq(adapter1.getMsg(0), expected);
    }

    function test_adapterDispatch_noAdaptersNoRevert() public {
        wc.propagateRoot();
        assertTrue(wc.chainHead() != bytes32(0));
    }

    // ════════════════════════════════════════════════
    //       L1 CHAIN HEAD VALIDATION (mocked)
    // ════════════════════════════════════════════════

    function test_l1_setValidChainHead() public {
        wc.propagateRoot();
        bytes32 wcHead = wc.chainHead();

        l1.setValidChainHead(wcHead);

        assertTrue(l1.isValidChainHead(wcHead));
    }

    // ════════════════════════════════════════════════
    //    L1 processChainedCommits
    // ════════════════════════════════════════════════

    function test_l1_processChainedCommits() public {
        bytes32 bh = blockhash(block.number - 1);

        wc.propagateRoot();
        bytes32 wcHead = wc.chainHead();

        // First prove the chain head
        l1.setValidChainHead(wcHead);

        // Then process chained commits
        StateChainTypes.ChainedCommit[] memory commits = new StateChainTypes.ChainedCommit[](1);
        commits[0] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_ROOT,
            blockHash: bh,
            data: abi.encode(ROOT, block.timestamp, bytes32(block.number))
        });

        l1.processChainedCommits(commits, "");

        assertEq(l1.chainHead(), wcHead);
        assertEq(l1.getLatestRoot(), ROOT);
        assertTrue(l1.isValidRoot(ROOT));
    }

    function test_l1_processChainedCommits_invalidChainHead() public {
        bytes32 bh = blockhash(block.number - 1);

        wc.propagateRoot();

        // Don't prove chain head — should revert
        StateChainTypes.ChainedCommit[] memory commits = new StateChainTypes.ChainedCommit[](1);
        commits[0] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_ROOT,
            blockHash: bh,
            data: abi.encode(ROOT, block.timestamp, bytes32(block.number))
        });

        vm.expectRevert(IWorldIdStateBridge.InvalidChainHead.selector);
        l1.processChainedCommits(commits, "");
    }

    // ════════════════════════════════════════════════
    //   E2E: TRUSTLESS DELIVERY (processChainedCommits)
    // ════════════════════════════════════════════════

    function test_processChainedCommits_singleRoot() public {
        bytes32 bh = blockhash(block.number - 1);

        wc.propagateRoot();

        StateChainTypes.ChainedCommit[] memory commits = new StateChainTypes.ChainedCommit[](1);
        commits[0] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_ROOT,
            blockHash: bh,
            data: abi.encode(ROOT, block.timestamp, bytes32(block.number))
        });

        dest.setValidHead(wc.chainHead());
        dest.processChainedCommits(commits, "");

        assertEq(dest.chainHead(), wc.chainHead());
        assertEq(dest.getLatestRoot(), ROOT);
        assertTrue(dest.isValidRoot(ROOT));
    }

    function test_processChainedCommits_batch() public {
        bytes32 bh = blockhash(block.number - 1);

        wc.propagateRoot();
        wc.propagateIssuerPubkey(ISSUER_ID);

        StateChainTypes.ChainedCommit[] memory commits = new StateChainTypes.ChainedCommit[](2);
        commits[0] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_ROOT,
            blockHash: bh,
            data: abi.encode(ROOT, block.timestamp, bytes32(block.number))
        });
        commits[1] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_ISSUER_PUBKEY,
            blockHash: bh,
            data: abi.encode(ISSUER_ID, PK_X, PK_Y, bytes32(block.number))
        });

        dest.setValidHead(wc.chainHead());
        dest.processChainedCommits(commits, "");

        assertEq(dest.chainHead(), wc.chainHead());
        assertEq(dest.getLatestRoot(), ROOT);
        (uint256 x, uint256 y) = dest.issuerPubkey(ISSUER_ID);
        assertEq(x, PK_X);
        assertEq(y, PK_Y);
    }

    function test_processChainedCommits_emptyReverts() public {
        StateChainTypes.ChainedCommit[] memory commits = new StateChainTypes.ChainedCommit[](0);
        vm.expectRevert(IWorldIdStateBridge.EmptyChainedCommits.selector);
        dest.processChainedCommits(commits, "");
    }

    // ════════════════════════════════════════════════
    //          TAMPER DETECTION
    // ════════════════════════════════════════════════

    function test_tamperDetection_modifiedData() public {
        bytes32 bh = blockhash(block.number - 1);
        wc.propagateRoot();

        StateChainTypes.ChainedCommit[] memory commits = new StateChainTypes.ChainedCommit[](1);
        commits[0] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_ROOT,
            blockHash: bh,
            data: abi.encode(ROOT + 1, block.timestamp, bytes32(block.number)) // tampered root
        });

        dest.setValidHead(wc.chainHead());
        vm.expectRevert("DestHarness: chain head mismatch");
        dest.processChainedCommits(commits, "");
    }

    function test_tamperDetection_modifiedBlockHash() public {
        wc.propagateRoot();

        StateChainTypes.ChainedCommit[] memory commits = new StateChainTypes.ChainedCommit[](1);
        commits[0] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_ROOT,
            blockHash: bytes32(uint256(0xbad)), // wrong blockhash
            data: abi.encode(ROOT, block.timestamp, bytes32(block.number))
        });

        dest.setValidHead(wc.chainHead());
        vm.expectRevert("DestHarness: chain head mismatch");
        dest.processChainedCommits(commits, "");
    }

    function test_tamperDetection_skippedCommit() public {
        bytes32 bh = blockhash(block.number - 1);

        wc.propagateRoot();
        wc.propagateIssuerPubkey(ISSUER_ID);
        wc.propagateOprfKey(OPRF_ID);

        // Submit commits 1 and 3 only (skip the middle issuer pubkey commit)
        StateChainTypes.ChainedCommit[] memory commits = new StateChainTypes.ChainedCommit[](2);
        commits[0] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_ROOT,
            blockHash: bh,
            data: abi.encode(ROOT, block.timestamp, bytes32(block.number))
        });
        commits[1] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_OPRF_KEY,
            blockHash: bh,
            data: abi.encode(OPRF_ID, PK_X, PK_Y, bytes32(block.number))
        });

        dest.setValidHead(wc.chainHead());
        vm.expectRevert("DestHarness: chain head mismatch");
        dest.processChainedCommits(commits, "");
    }

    // ════════════════════════════════════════════════
    //    L1 INVALIDATION (verifiably proved)
    // ════════════════════════════════════════════════

    function test_l1_invalidateProofId_viaChallengerWins() public {
        l1.registerAdapter(IBridgeAdapter(address(adapter1)));

        MockDisputeGame game = new MockDisputeGame(GameStatus.CHALLENGER_WINS, Claim.wrap(bytes32(0)), 42);
        mockFactory.addGame(IDisputeGame(address(game)));

        l1.invalidateProofId(0);

        assertEq(adapter1.msgCount(), 1);

        bytes4 sel = bytes4(keccak256("receiveChainedCommit(uint8,bytes32,bytes)"));
        bytes memory data = abi.encode(bytes32(uint256(42)));
        bytes memory expected =
            abi.encodeWithSelector(sel, StateChainTypes.ACTION_INVALIDATE_PROOF_ID, bytes32(0), data);
        assertEq(adapter1.getMsg(0), expected);
    }

    function test_l1_invalidateProofId_defenderWinsReverts() public {
        MockDisputeGame game = new MockDisputeGame(GameStatus.DEFENDER_WINS, Claim.wrap(bytes32(0)), 42);
        mockFactory.addGame(IDisputeGame(address(game)));

        vm.expectRevert(L1StateAdapter.GameNotChallengerWins.selector);
        l1.invalidateProofId(0);
    }

    function test_l1_invalidateProofId_invalidIndex() public {
        vm.expectRevert(L1StateAdapter.InvalidDisputeGameIndex.selector);
        l1.invalidateProofId(999);
    }

    // ════════════════════════════════════════════════
    //  INVALIDATION PROPAGATION TO DESTINATION
    // ════════════════════════════════════════════════

    function test_invalidationPropagation_viaProcessChainedCommits() public {
        bytes32 bh = blockhash(block.number - 1);

        wc.propagateRoot();
        bytes32 proofId = bytes32(block.number);

        StateChainTypes.ChainedCommit[] memory commits = new StateChainTypes.ChainedCommit[](2);
        commits[0] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_ROOT, blockHash: bh, data: abi.encode(ROOT, block.timestamp, proofId)
        });

        bytes32 head0 = keccak256(abi.encode(bytes32(0), bh, StateChainTypes.ACTION_SET_ROOT, commits[0].data));

        commits[1] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_INVALIDATE_PROOF_ID, blockHash: bh, data: abi.encode(proofId)
        });

        bytes32 head1 = keccak256(abi.encode(head0, bh, StateChainTypes.ACTION_INVALIDATE_PROOF_ID, commits[1].data));

        DestHarness freshDest = new DestHarness(
            IL1BlockHashOracle(address(oracle)),
            address(l1),
            ICrossDomainMessenger(address(destMessenger)),
            REMOTE_ADAPTER
        );
        freshDest.setValidHead(head1);
        freshDest.processChainedCommits(commits, "");

        assertEq(freshDest.chainHead(), head1);
        assertFalse(freshDest.isValidRoot(ROOT));
    }

    function test_invalidationCannotBeSkipped() public {
        bytes32 bh = blockhash(block.number - 1);

        wc.propagateRoot();
        bytes32 proofId = bytes32(block.number);

        bytes memory rootData = abi.encode(ROOT, block.timestamp, proofId);
        bytes memory invalidData = abi.encode(proofId);
        bytes32 head0 = keccak256(abi.encode(bytes32(0), bh, StateChainTypes.ACTION_SET_ROOT, rootData));
        bytes32 head1 = keccak256(abi.encode(head0, bh, StateChainTypes.ACTION_INVALIDATE_PROOF_ID, invalidData));

        StateChainTypes.ChainedCommit[] memory commits = new StateChainTypes.ChainedCommit[](1);
        commits[0] =
            StateChainTypes.ChainedCommit({action: StateChainTypes.ACTION_SET_ROOT, blockHash: bh, data: rootData});

        dest.setValidHead(head1);
        vm.expectRevert("DestHarness: chain head mismatch");
        dest.processChainedCommits(commits, "");
    }

    // ════════════════════════════════════════════════
    //          PARTIAL CATCH-UP
    // ════════════════════════════════════════════════

    function test_partialCatchUp() public {
        bytes32 bh = blockhash(block.number - 1);

        wc.propagateRoot();
        wc.propagateIssuerPubkey(ISSUER_ID);
        bytes32 head2 = wc.chainHead();
        wc.propagateOprfKey(OPRF_ID);
        bytes32 head3 = wc.chainHead();

        // Batch 1: first 2 commits
        StateChainTypes.ChainedCommit[] memory batch1 = new StateChainTypes.ChainedCommit[](2);
        batch1[0] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_ROOT,
            blockHash: bh,
            data: abi.encode(ROOT, block.timestamp, bytes32(block.number))
        });
        batch1[1] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_ISSUER_PUBKEY,
            blockHash: bh,
            data: abi.encode(ISSUER_ID, PK_X, PK_Y, bytes32(block.number))
        });

        dest.setValidHead(head2);
        dest.processChainedCommits(batch1, "");

        assertEq(dest.chainHead(), head2);
        assertEq(dest.getLatestRoot(), ROOT);

        // Batch 2: remaining commit
        StateChainTypes.ChainedCommit[] memory batch2 = new StateChainTypes.ChainedCommit[](1);
        batch2[0] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_OPRF_KEY,
            blockHash: bh,
            data: abi.encode(OPRF_ID, PK_X, PK_Y, bytes32(block.number))
        });

        dest.setValidHead(head3);
        dest.processChainedCommits(batch2, "");

        assertEq(dest.chainHead(), head3);
        (uint256 ox, uint256 oy) = dest.oprfKey(OPRF_ID);
        assertEq(ox, PK_X);
        assertEq(oy, PK_Y);
    }

    // ════════════════════════════════════════════════
    //          EDGE CASES
    // ════════════════════════════════════════════════

    function test_destinationInvalidation_idempotent() public {
        bytes32 bh = blockhash(block.number - 1);
        bytes32 proofId = bytes32(uint256(0x111));

        StateChainTypes.ChainedCommit[] memory commits = new StateChainTypes.ChainedCommit[](2);
        commits[0] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_INVALIDATE_PROOF_ID, blockHash: bh, data: abi.encode(proofId)
        });
        commits[1] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_INVALIDATE_PROOF_ID, blockHash: bh, data: abi.encode(proofId)
        });

        bytes32 head0 =
            keccak256(abi.encode(bytes32(0), bh, StateChainTypes.ACTION_INVALIDATE_PROOF_ID, commits[0].data));
        bytes32 head1 = keccak256(abi.encode(head0, bh, StateChainTypes.ACTION_INVALIDATE_PROOF_ID, commits[1].data));

        dest.setValidHead(head1);
        dest.processChainedCommits(commits, "");
    }

    function test_unknownAction_reverts() public {
        bytes32 bh = blockhash(block.number - 1);

        StateChainTypes.ChainedCommit[] memory commits = new StateChainTypes.ChainedCommit[](1);
        commits[0] = StateChainTypes.ChainedCommit({action: 99, blockHash: bh, data: abi.encode(uint256(0))});

        vm.expectRevert(abi.encodeWithSelector(IWorldIdStateBridge.UnknownAction.selector, uint8(99)));
        dest.processChainedCommits(commits, "");
    }

    function test_rootValidityWindow_respected() public {
        bytes32 bh = blockhash(block.number - 1);

        mockRegistry.setLatestRoot(111);
        wc.propagateRoot();
        bytes32 head1 = wc.chainHead();

        StateChainTypes.ChainedCommit[] memory commits1 = new StateChainTypes.ChainedCommit[](1);
        commits1[0] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_ROOT,
            blockHash: bh,
            data: abi.encode(uint256(111), block.timestamp, bytes32(block.number))
        });
        dest.setValidHead(head1);
        dest.processChainedCommits(commits1, "");

        vm.warp(block.timestamp + 100);

        mockRegistry.setLatestRoot(222);
        wc.propagateRoot();
        bytes32 head2 = wc.chainHead();

        StateChainTypes.ChainedCommit[] memory commits2 = new StateChainTypes.ChainedCommit[](1);
        commits2[0] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_ROOT,
            blockHash: bh,
            data: abi.encode(uint256(222), block.timestamp, bytes32(block.number))
        });
        dest.setValidHead(head2);
        dest.processChainedCommits(commits2, "");

        assertTrue(dest.isValidRoot(111));
        assertTrue(dest.isValidRoot(222));

        vm.warp(block.timestamp + 1 hours + 1);

        assertFalse(dest.isValidRoot(111));
        assertTrue(dest.isValidRoot(222));
    }

    // ════════════════════════════════════════════════
    //    ADAPTER MANAGEMENT (owner-only)
    // ════════════════════════════════════════════════

    function test_l1_adapterManagement_unauthorized() public {
        vm.prank(address(0xdead));
        vm.expectRevert(IWorldIdStateBridge.Unauthorized.selector);
        l1.registerAdapter(IBridgeAdapter(address(adapter1)));

        l1.registerAdapter(IBridgeAdapter(address(adapter1)));

        vm.prank(address(0xdead));
        vm.expectRevert(IWorldIdStateBridge.Unauthorized.selector);
        l1.removeAdapter(0);
    }

    function test_wc_adapterManagement_unauthorized() public {
        vm.prank(address(0xdead));
        vm.expectRevert(IWorldIdStateBridge.Unauthorized.selector);
        wc.registerAdapter(IBridgeAdapter(address(adapter1)));

        wc.registerAdapter(IBridgeAdapter(address(adapter1)));

        vm.prank(address(0xdead));
        vm.expectRevert(IWorldIdStateBridge.Unauthorized.selector);
        wc.removeAdapter(0);
    }

    // ════════════════════════════════════════════════
    //    POLYMORPHISM: all adapters share base
    // ════════════════════════════════════════════════

    function test_allAdapters_implementIWorldIdStateBridge() public view {
        // All adapters expose the same state getter interface
        assertEq(wc.getLatestRoot(), 0);
        assertEq(l1.getLatestRoot(), 0);
        assertEq(dest.getLatestRoot(), 0);

        assertEq(wc.rootValidityWindow(), 1 hours);
        assertEq(l1.rootValidityWindow(), 1 hours);
        assertEq(dest.rootValidityWindow(), 1 hours);

        assertEq(wc.chainHead(), bytes32(0));
        assertEq(l1.chainHead(), bytes32(0));
        assertEq(dest.chainHead(), bytes32(0));
    }

    function test_allAdapters_shareStorageLayout() public {
        // After propagation on WC and delivery to L1 and dest, state is identical
        bytes32 bh = blockhash(block.number - 1);

        wc.propagateRoot();
        wc.propagateIssuerPubkey(ISSUER_ID);
        bytes32 wcHead = wc.chainHead();

        // Deliver to L1
        l1.setValidChainHead(wcHead);

        StateChainTypes.ChainedCommit[] memory commits = new StateChainTypes.ChainedCommit[](2);
        commits[0] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_ROOT,
            blockHash: bh,
            data: abi.encode(ROOT, block.timestamp, bytes32(block.number))
        });
        commits[1] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_ISSUER_PUBKEY,
            blockHash: bh,
            data: abi.encode(ISSUER_ID, PK_X, PK_Y, bytes32(block.number))
        });

        l1.processChainedCommits(commits, "");

        // Deliver to dest
        dest.setValidHead(wcHead);
        dest.processChainedCommits(commits, "");

        // All three have identical state
        assertEq(wc.getLatestRoot(), l1.getLatestRoot());
        assertEq(l1.getLatestRoot(), dest.getLatestRoot());

        (uint256 wcX, uint256 wcY) = wc.issuerPubkey(ISSUER_ID);
        (uint256 l1X, uint256 l1Y) = l1.issuerPubkey(ISSUER_ID);
        (uint256 dX, uint256 dY) = dest.issuerPubkey(ISSUER_ID);

        assertEq(wcX, l1X);
        assertEq(l1X, dX);
        assertEq(wcY, l1Y);
        assertEq(l1Y, dY);
    }

    // ════════════════════════════════════════════════
    //    OpStackBridgeAdapter
    // ════════════════════════════════════════════════

    function test_opStackAdapter_callsMessenger() public {
        MockCrossDomainMessenger messenger = new MockCrossDomainMessenger();
        address target = address(0xBEEF);
        uint32 gasLimit = 200_000;

        OpStackBridgeAdapter adapter =
            new OpStackBridgeAdapter(ICrossDomainMessenger(address(messenger)), target, gasLimit);

        bytes memory message = abi.encodeWithSelector(
            IWorldIdStateBridge.receiveChainedCommit.selector,
            StateChainTypes.ACTION_SET_ROOT,
            bytes32(0),
            abi.encode(ROOT, block.timestamp, bytes32(block.number))
        );

        adapter.sendMessage(message);

        assertEq(messenger.lastTarget(), target);
        assertEq(messenger.lastMessage(), message);
        assertEq(messenger.lastMinGasLimit(), gasLimit);
    }

    function test_opStackAdapter_forwardsValue() public {
        MockCrossDomainMessenger messenger = new MockCrossDomainMessenger();
        OpStackBridgeAdapter adapter =
            new OpStackBridgeAdapter(ICrossDomainMessenger(address(messenger)), address(0xBEEF), 200_000);

        vm.deal(address(this), 1 ether);
        adapter.sendMessage{value: 0.5 ether}(hex"deadbeef");

        assertEq(address(messenger).balance, 0.5 ether);
    }

    // ════════════════════════════════════════════════
    //    OPTIMISTIC RECEIVE — SUCCESS
    // ════════════════════════════════════════════════

    function test_l1_optimisticReceive_appliesState() public {
        bytes memory data = abi.encode(ROOT, block.timestamp, bytes32(block.number));
        bytes memory message = abi.encodeWithSelector(
            IWorldIdStateBridge.receiveChainedCommit.selector, StateChainTypes.ACTION_SET_ROOT, bytes32(0), data
        );

        l1Messenger.relayMessage(address(l1), REMOTE_ADAPTER, message);

        assertEq(l1.getLatestRoot(), ROOT);
        assertTrue(l1.chainHead() != bytes32(0));
    }

    function test_dest_optimisticReceive_appliesState() public {
        bytes memory data = abi.encode(ROOT, block.timestamp, bytes32(block.number));
        bytes memory message = abi.encodeWithSelector(
            IWorldIdStateBridge.receiveChainedCommit.selector, StateChainTypes.ACTION_SET_ROOT, bytes32(0), data
        );

        destMessenger.relayMessage(address(dest), REMOTE_ADAPTER, message);

        assertEq(dest.getLatestRoot(), ROOT);
        assertTrue(dest.chainHead() != bytes32(0));
    }

    // ════════════════════════════════════════════════
    //    OPTIMISTIC RECEIVE — AUTH FAILURES
    // ════════════════════════════════════════════════

    function test_l1_optimisticReceive_wrongXDomainSenderReverts() public {
        bytes memory data = abi.encode(ROOT, block.timestamp, bytes32(block.number));
        bytes memory message = abi.encodeWithSelector(
            IWorldIdStateBridge.receiveChainedCommit.selector, StateChainTypes.ACTION_SET_ROOT, bytes32(0), data
        );

        vm.expectRevert(IWorldIdStateBridge.Unauthorized.selector);
        l1Messenger.relayMessage(address(l1), address(0xBAD), message);
    }

    function test_dest_optimisticReceive_wrongXDomainSenderReverts() public {
        bytes memory data = abi.encode(ROOT, block.timestamp, bytes32(block.number));
        bytes memory message = abi.encodeWithSelector(
            IWorldIdStateBridge.receiveChainedCommit.selector, StateChainTypes.ACTION_SET_ROOT, bytes32(0), data
        );

        vm.expectRevert(IWorldIdStateBridge.Unauthorized.selector);
        destMessenger.relayMessage(address(dest), address(0xBAD), message);
    }

    // ════════════════════════════════════════════════
    //    E2E OPTIMISTIC DELIVERY (WC → L1)
    // ════════════════════════════════════════════════

    function test_e2e_optimisticDelivery_wcToL1() public {
        // Step 1: Deploy OpStackBridgeAdapter targeting L1
        MockCrossDomainMessenger wcMessenger = new MockCrossDomainMessenger();
        OpStackBridgeAdapter opAdapter =
            new OpStackBridgeAdapter(ICrossDomainMessenger(address(wcMessenger)), address(l1), 200_000);

        // Step 2: Register the adapter on WC and propagate
        wc.registerAdapter(IBridgeAdapter(address(opAdapter)));
        wc.propagateRoot();

        // Step 3: Verify the adapter captured the message
        bytes memory capturedMessage = wcMessenger.lastMessage();
        assertEq(wcMessenger.lastTarget(), address(l1));

        // Step 4: Simulate the messenger relaying to L1
        // The L1 messenger relays from REMOTE_ADAPTER (the WC-side adapter address)
        l1Messenger.relayMessage(address(l1), REMOTE_ADAPTER, capturedMessage);

        // Step 5: Verify L1 state matches WC
        assertEq(l1.getLatestRoot(), wc.getLatestRoot());
        assertTrue(l1.chainHead() != bytes32(0));
    }
}
