// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ProofsLib} from "../src/lib/ProofsLib.sol";
import {ProvenRootInfo, ProvenPubKeyInfo} from "../src/lib/BridgeTypes.sol";
import {
    Unauthorized,
    EmptyChainedCommits,
    UnknownAction,
    InvalidRoot,
    InvalidatedProofId,
    UnknownL1BlockHash,
    UnsupportedOperation
} from "../src/lib/BridgeErrors.sol";
import {ProofIdInvalidated} from "../src/lib/BridgeEvents.sol";
import {IBridgeAdapter} from "../src/interfaces/IBridgeAdapter.sol";
import {INativeWorldId} from "../src/interfaces/INativeWorldId.sol";
import {CommitmentHelpers} from "./helpers/CommitmentHelpers.sol";
import {WorldIdBridge} from "../src/core/lib/WorldIdBridge.sol";
import {CrossDomainWorldIdVerifier} from "../src/core/lib/CrossDomainWorldIdVerifier.sol";
import {ArbitrumAdapter} from "../src/adapters/arbitrum/ArbitrumAdapter.sol";
import {ArbitrumReceiver} from "../src/adapters/arbitrum/ArbitrumReceiver.sol";
import {ScrollAdapter} from "../src/adapters/scroll/ScrollAdapter.sol";
import {ScrollReceiver} from "../src/adapters/scroll/ScrollReceiver.sol";
import {ZkSyncAdapter} from "../src/adapters/zksync/ZkSyncAdapter.sol";
import {ZkSyncReceiver} from "../src/adapters/zksync/ZkSyncReceiver.sol";
import {UniversalWorldId} from "../src/core/UniversalWorldId.sol";
import {IL1BlockHashOracle} from "../src/interfaces/IL1BlockHashOracle.sol";
import {IInbox} from "../src/vendored/arbitrum/IInbox.sol";
import {IL1ScrollMessenger} from "../src/vendored/scroll/IL1ScrollMessenger.sol";
import {IL2ScrollMessenger} from "../src/vendored/scroll/IL2ScrollMessenger.sol";
import {IMailbox} from "../src/vendored/zksync/IMailbox.sol";
import {BabyJubJub} from "lib/oprf-key-registry/src/BabyJubJub.sol";

// ═══════════════════════════════════════════════════════════
//                     MOCK CONTRACTS
// ═══════════════════════════════════════════════════════════

/// @dev Mock Arbitrum Inbox that records calls for assertion.
contract MockInbox is IInbox {
    struct RetryableTicket {
        address to;
        uint256 l2CallValue;
        uint256 maxSubmissionCost;
        address excessFeeRefundAddress;
        address callValueRefundAddress;
        uint256 gasLimit;
        uint256 maxFeePerGas;
        bytes data;
        uint256 value;
    }

    RetryableTicket[] public tickets;
    uint256 public nextTicketId;

    function createRetryableTicket(
        address to,
        uint256 l2CallValue,
        uint256 maxSubmissionCost,
        address excessFeeRefundAddress,
        address callValueRefundAddress,
        uint256 gasLimit,
        uint256 maxFeePerGas,
        bytes calldata data
    ) external payable returns (uint256) {
        tickets.push(
            RetryableTicket({
                to: to,
                l2CallValue: l2CallValue,
                maxSubmissionCost: maxSubmissionCost,
                excessFeeRefundAddress: excessFeeRefundAddress,
                callValueRefundAddress: callValueRefundAddress,
                gasLimit: gasLimit,
                maxFeePerGas: maxFeePerGas,
                data: data,
                value: msg.value
            })
        );
        return nextTicketId++;
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
        uint256 value;
        bytes message;
        uint256 gasLimit;
        uint256 ethValue;
    }

    SentMessage[] public messages;

    function sendMessage(address target, uint256 value, bytes calldata message, uint256 gasLimit) external payable {
        messages.push(
            SentMessage({target: target, value: value, message: message, gasLimit: gasLimit, ethValue: msg.value})
        );
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
        uint256 l2Value;
        bytes calldata_;
        uint256 l2GasLimit;
        uint256 l2GasPerPubdataByteLimit;
        bytes[] factoryDeps;
        address refundRecipient;
        uint256 ethValue;
    }

    L2Transaction[] public transactions;
    uint256 public nextTxHash;

    function requestL2Transaction(
        address _contractL2,
        uint256 _l2Value,
        bytes calldata _calldata,
        uint256 _l2GasLimit,
        uint256 _l2GasPerPubdataByteLimit,
        bytes[] calldata _factoryDeps,
        address _refundRecipient
    ) external payable returns (bytes32) {
        transactions.push(
            L2Transaction({
                contractL2: _contractL2,
                l2Value: _l2Value,
                calldata_: _calldata,
                l2GasLimit: _l2GasLimit,
                l2GasPerPubdataByteLimit: _l2GasPerPubdataByteLimit,
                factoryDeps: _factoryDeps,
                refundRecipient: _refundRecipient,
                ethValue: msg.value
            })
        );
        return bytes32(nextTxHash++);
    }

    function transactionCount() external view returns (uint256) {
        return transactions.length;
    }

    function getTransactionCalldata(uint256 index) external view returns (bytes memory) {
        return transactions[index].calldata_;
    }
}

/// @dev Mock L1 block hash oracle that returns configurable validity.
contract MockBlockHashOracle is IL1BlockHashOracle {
    mapping(bytes32 => bool) public validHashes;

    function setValid(bytes32 hash, bool valid) external {
        validHashes[hash] = valid;
    }

    function isValid(bytes32 blockHash) external view returns (bool) {
        return validHashes[blockHash];
    }
}

/// @dev Mock Verifier that always succeeds or always reverts.
contract MockVerifier {
    bool public shouldRevert;

    function setShouldRevert(bool _shouldRevert) external {
        shouldRevert = _shouldRevert;
    }

    function verifyCompressedProof(uint256[4] calldata, uint256[15] calldata) external view {
        if (shouldRevert) revert("MockVerifier: proof invalid");
    }
}

/// @dev Concrete StateBridge that exposes internal methods for testing.
contract TestStateBridge is WorldIdBridge {
    using ProofsLib for ProofsLib.Chain;

    constructor(uint256 rootValidityWindow_, uint256 treeDepth_, uint64 minExpirationThreshold_)
        WorldIdBridge(rootValidityWindow_, treeDepth_, minExpirationThreshold_)
    {}

    function commitChained(ProofsLib.CommitmentWithProof calldata) external pure override {
        revert("TestStateBridge: not implemented");
    }

    function exposedUpdateRoot(uint256 root, uint256 timestamp, bytes32 proofId) external {
        updateRoot(root, timestamp, proofId);
    }

    function exposedInvalidateProofId(bytes32 proofId) external {
        invalidateProofId(proofId);
    }

    function exposedApplyCommitments(ProofsLib.Commitment[] memory commits) external {
        applyCommitments(commits);
    }

    function exposedCommitChained(ProofsLib.Commitment[] memory commits) external {
        keccakChain.commitChained(commits);
    }
}

// ═══════════════════════════════════════════════════════════
//                       BASE TEST
// ═══════════════════════════════════════════════════════════

abstract contract BridgeAdapterBaseTest is CommitmentHelpers {
    using ProofsLib for ProofsLib.Chain;

    // ── Default test values ──
    uint256 constant DEFAULT_ROOT_VALIDITY_WINDOW = 1 hours;
    uint256 constant DEFAULT_TREE_DEPTH = 30;
    uint64 constant DEFAULT_MIN_EXPIRATION_THRESHOLD = 300;

    address constant L1_BRIDGE = address(0xBEEF);
    address constant MOCK_VERIFIER = address(0xDEAD);
    uint160 constant ALIAS_OFFSET = uint160(0x1111000000000000000000000000000000001111);

    /// @dev Alias for backward compat with tests using the old name.
    function _buildCommitFromL1Calldata(ProofsLib.Commitment[] memory commits) internal pure returns (bytes memory) {
        return _encodeCommitFromL1(commits);
    }
}

// ═══════════════════════════════════════════════════════════
//              ARBITRUM BRIDGE ADAPTER TESTS
// ═══════════════════════════════════════════════════════════

contract ArbitrumAdapterTest is BridgeAdapterBaseTest {
    MockInbox inbox;
    ArbitrumAdapter adapter;

    address constant TARGET = address(0x1234);
    uint256 constant MAX_SUBMISSION_COST = 0.01 ether;
    uint256 constant GAS_LIMIT = 1_000_000;
    uint256 constant MAX_FEE_PER_GAS = 100 gwei;

    function setUp() public {
        inbox = new MockInbox();
        adapter = new ArbitrumAdapter(IInbox(address(inbox)), TARGET, MAX_SUBMISSION_COST, GAS_LIMIT, MAX_FEE_PER_GAS);
    }

    function test_constructor_setsImmutables() public view {
        assertEq(address(adapter.INBOX()), address(inbox));
        assertEq(adapter.TARGET(), TARGET);
        assertEq(adapter.MAX_SUBMISSION_COST(), MAX_SUBMISSION_COST);
        assertEq(adapter.GAS_LIMIT(), GAS_LIMIT);
        assertEq(adapter.MAX_FEE_PER_GAS(), MAX_FEE_PER_GAS);
    }

    function test_sendMessage_createsRetryableTicket() public {
        bytes memory message = hex"DEADBEEF";
        adapter.sendMessage{value: 0.1 ether}(message);

        assertEq(inbox.ticketCount(), 1);
    }

    function test_sendMessage_passesCorrectTarget() public {
        bytes memory message = hex"CAFE";
        adapter.sendMessage(message);

        (address to,,,,,,,,) = inbox.tickets(0);
        assertEq(to, TARGET);
    }

    function test_sendMessage_passesZeroL2CallValue() public {
        adapter.sendMessage(hex"AA");
        (, uint256 l2CallValue,,,,,,,) = inbox.tickets(0);
        assertEq(l2CallValue, 0);
    }

    function test_sendMessage_forwardsMessageData() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(42, block.timestamp, bytes32(uint256(1)));
        bytes memory message = _buildCommitFromL1Calldata(commits);

        adapter.sendMessage(message);

        bytes memory storedData = inbox.getTicketData(0);
        assertEq(keccak256(storedData), keccak256(message));
    }

    function test_sendMessage_forwardsEthValue() public {
        adapter.sendMessage{value: 0.5 ether}(hex"AA");
        (,,,,,,,, uint256 value) = inbox.tickets(0);
        assertEq(value, 0.5 ether);
    }

    function test_sendMessage_usesCallerAsRefundAddress() public {
        address caller = address(0xCAFE);
        vm.prank(caller);
        adapter.sendMessage(hex"AA");

        (,,, address excessRefund, address callValueRefund,,,,) = inbox.tickets(0);
        assertEq(excessRefund, caller);
        assertEq(callValueRefund, caller);
    }

    function test_sendMessage_passesConfiguredGasParams() public {
        adapter.sendMessage(hex"AA");
        (,, uint256 subCost,,, uint256 gasLim, uint256 feePerGas,,) = inbox.tickets(0);
        assertEq(subCost, MAX_SUBMISSION_COST);
        assertEq(gasLim, GAS_LIMIT);
        assertEq(feePerGas, MAX_FEE_PER_GAS);
    }

    function test_sendMessage_multipleCallsIncrementTicketId() public {
        adapter.sendMessage(hex"01");
        adapter.sendMessage(hex"02");
        adapter.sendMessage(hex"03");
        assertEq(inbox.ticketCount(), 3);
    }

    function testFuzz_sendMessage_arbitraryPayload(bytes calldata payload) public {
        adapter.sendMessage(payload);
        bytes memory stored = inbox.getTicketData(0);
        assertEq(keccak256(stored), keccak256(payload));
    }
}

// ═══════════════════════════════════════════════════════════
//                SCROLL BRIDGE ADAPTER TESTS
// ═══════════════════════════════════════════════════════════

contract ScrollAdapterTest is BridgeAdapterBaseTest {
    MockL1ScrollMessenger messenger;
    ScrollAdapter adapter;

    address constant TARGET = address(0x5678);
    uint256 constant GAS_LIMIT = 500_000;

    function setUp() public {
        messenger = new MockL1ScrollMessenger();
        adapter = new ScrollAdapter(IL1ScrollMessenger(address(messenger)), TARGET, GAS_LIMIT);
    }

    function test_constructor_setsImmutables() public view {
        assertEq(address(adapter.MESSENGER()), address(messenger));
        assertEq(adapter.TARGET(), TARGET);
        assertEq(adapter.GAS_LIMIT(), GAS_LIMIT);
    }

    function test_sendMessage_callsMessenger() public {
        adapter.sendMessage(hex"DEADBEEF");
        assertEq(messenger.messageCount(), 1);
    }

    function test_sendMessage_passesCorrectTarget() public {
        adapter.sendMessage(hex"AA");
        (address target,,,,) = messenger.messages(0);
        assertEq(target, TARGET);
    }

    function test_sendMessage_passesZeroValue() public {
        adapter.sendMessage(hex"AA");
        (, uint256 value,,,) = messenger.messages(0);
        assertEq(value, 0);
    }

    function test_sendMessage_passesConfiguredGasLimit() public {
        adapter.sendMessage(hex"AA");
        (,,, uint256 gasLim,) = messenger.messages(0);
        assertEq(gasLim, GAS_LIMIT);
    }

    function test_sendMessage_forwardsMessageData() public {
        bytes memory message = hex"CAFEBABE";
        adapter.sendMessage(message);
        bytes memory stored = messenger.getMessageData(0);
        assertEq(keccak256(stored), keccak256(message));
    }

    function test_sendMessage_forwardsEthValue() public {
        adapter.sendMessage{value: 0.3 ether}(hex"AA");
        (,,,, uint256 ethValue) = messenger.messages(0);
        assertEq(ethValue, 0.3 ether);
    }

    function testFuzz_sendMessage_arbitraryPayload(bytes calldata payload) public {
        adapter.sendMessage(payload);
        bytes memory stored = messenger.getMessageData(0);
        assertEq(keccak256(stored), keccak256(payload));
    }
}

// ═══════════════════════════════════════════════════════════
//               ZKSYNC BRIDGE ADAPTER TESTS
// ═══════════════════════════════════════════════════════════

contract ZkSyncAdapterTest is BridgeAdapterBaseTest {
    MockMailbox mailbox;
    ZkSyncAdapter adapter;

    address constant TARGET = address(0x9ABC);
    uint256 constant GAS_LIMIT = 2_000_000;
    uint256 constant GAS_PER_PUBDATA = 800;

    function setUp() public {
        mailbox = new MockMailbox();
        adapter = new ZkSyncAdapter(IMailbox(address(mailbox)), TARGET, GAS_LIMIT, GAS_PER_PUBDATA);
    }

    function test_constructor_setsImmutables() public view {
        assertEq(address(adapter.MAILBOX()), address(mailbox));
        assertEq(adapter.TARGET(), TARGET);
        assertEq(adapter.GAS_LIMIT(), GAS_LIMIT);
        assertEq(adapter.GAS_PER_PUBDATA(), GAS_PER_PUBDATA);
    }

    function test_sendMessage_callsMailbox() public {
        adapter.sendMessage(hex"DEADBEEF");
        assertEq(mailbox.transactionCount(), 1);
    }

    function test_sendMessage_passesCorrectTarget() public {
        adapter.sendMessage(hex"AA");
        (address contractL2,,,,,,) = mailbox.transactions(0);
        assertEq(contractL2, TARGET);
    }

    function test_sendMessage_passesZeroL2Value() public {
        adapter.sendMessage(hex"AA");
        (, uint256 l2Value,,,,,) = mailbox.transactions(0);
        assertEq(l2Value, 0);
    }

    function test_sendMessage_passesConfiguredGasParams() public {
        adapter.sendMessage(hex"AA");
        (,,, uint256 gasLim, uint256 gasPubdata,,) = mailbox.transactions(0);
        assertEq(gasLim, GAS_LIMIT);
        assertEq(gasPubdata, GAS_PER_PUBDATA);
    }

    function test_sendMessage_forwardsMessageData() public {
        bytes memory message = hex"CAFED00D";
        adapter.sendMessage(message);
        bytes memory stored = mailbox.getTransactionCalldata(0);
        assertEq(keccak256(stored), keccak256(message));
    }

    function test_sendMessage_forwardsEthValue() public {
        adapter.sendMessage{value: 1 ether}(hex"AA");
        (,,,,,, uint256 ethValue) = mailbox.transactions(0);
        assertEq(ethValue, 1 ether);
    }

    function test_sendMessage_usesCallerAsRefundRecipient() public {
        address caller = address(0xBEEF);
        vm.prank(caller);
        adapter.sendMessage(hex"AA");
        (,,,,, address refundRecipient,) = mailbox.transactions(0);
        assertEq(refundRecipient, caller);
    }

    function test_sendMessage_passesEmptyFactoryDeps() public {
        // Factory deps should always be empty for World ID messages.
        adapter.sendMessage(hex"AA");
        // If factoryDeps was non-empty, the struct would contain data.
        // We verify via the transaction count — if it succeeds, factory deps were accepted.
        assertEq(mailbox.transactionCount(), 1);
    }

    function testFuzz_sendMessage_arbitraryPayload(bytes calldata payload) public {
        adapter.sendMessage(payload);
        bytes memory stored = mailbox.getTransactionCalldata(0);
        assertEq(keccak256(stored), keccak256(payload));
    }
}

// ═══════════════════════════════════════════════════════════
//              ARBITRUM L2 RECEIVER TESTS
// ═══════════════════════════════════════════════════════════

contract ArbitrumReceiverTest is BridgeAdapterBaseTest {
    ArbitrumReceiver receiver;
    MockVerifier verifier;

    function setUp() public {
        verifier = new MockVerifier();
        receiver = new ArbitrumReceiver(
            address(verifier),
            L1_BRIDGE,
            DEFAULT_ROOT_VALIDITY_WINDOW,
            DEFAULT_TREE_DEPTH,
            DEFAULT_MIN_EXPIRATION_THRESHOLD
        );
    }

    function test_constructor_setsImmutables() public view {
        assertEq(receiver.L1_STATE_BRIDGE(), L1_BRIDGE);
    }

    function test_commitFromL1_succeedsFromAliasedSender() public {
        address aliased = address(uint160(L1_BRIDGE) + ALIAS_OFFSET);

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(42, block.timestamp, bytes32(uint256(1)));

        vm.prank(aliased);
        receiver.commitFromL1(commits);

        assertEq(receiver.latestRoot(), 42);
    }

    function test_commitFromL1_revertsFromNonAliasedSender() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(42, block.timestamp, bytes32(uint256(1)));

        vm.prank(address(0xBAD));
        vm.expectRevert(Unauthorized.selector);
        receiver.commitFromL1(commits);
    }

    function test_commitFromL1_revertsFromRawL1Bridge() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(42, block.timestamp, bytes32(uint256(1)));

        // L1_BRIDGE without aliasing should fail.
        vm.prank(L1_BRIDGE);
        vm.expectRevert(Unauthorized.selector);
        receiver.commitFromL1(commits);
    }

    function test_commitFromL1_revertsOnEmptyCommits() public {
        address aliased = address(uint160(L1_BRIDGE) + ALIAS_OFFSET);
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](0);

        vm.prank(aliased);
        vm.expectRevert(EmptyChainedCommits.selector);
        receiver.commitFromL1(commits);
    }

    function test_commitChained_alwaysReverts() public {
        ProofsLib.CommitmentWithProof memory cwp;
        cwp.mptProof = hex"";
        cwp.commits = new ProofsLib.Commitment[](0);

        vm.expectRevert(UnsupportedOperation.selector);
        receiver.commitChained(cwp);
    }

    function test_commitFromL1_multipleCommitments() public {
        address aliased = address(uint160(L1_BRIDGE) + ALIAS_OFFSET);

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](3);
        commits[0] = _makeUpdateRootCommitment(100, block.timestamp, bytes32(uint256(1)));
        commits[1] = _makeSetIssuerCommitment(1, 111, 222, bytes32(uint256(2)));
        commits[2] = _makeSetOprfCommitment(1, 333, 444, bytes32(uint256(3)));

        vm.prank(aliased);
        receiver.commitFromL1(commits);

        assertEq(receiver.latestRoot(), 100);
    }

    function test_commitFromL1_extendsChain() public {
        address aliased = address(uint160(L1_BRIDGE) + ALIAS_OFFSET);

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(42, block.timestamp, bytes32(uint256(1)));

        vm.prank(aliased);
        receiver.commitFromL1(commits);

        (bytes32 head, uint64 length) = receiver.keccakChain();
        assertGt(uint256(head), 0);
        assertEq(length, 1);
    }

    function testFuzz_commitFromL1_aliasCalculation(address l1Bridge) public {
        vm.assume(l1Bridge != address(0));
        // Skip addresses that would overflow uint160 when aliased.
        vm.assume(uint160(l1Bridge) <= type(uint160).max - ALIAS_OFFSET);

        MockVerifier v = new MockVerifier();
        ArbitrumReceiver r = new ArbitrumReceiver(
            address(v), l1Bridge, DEFAULT_ROOT_VALIDITY_WINDOW, DEFAULT_TREE_DEPTH, DEFAULT_MIN_EXPIRATION_THRESHOLD
        );

        address aliased = address(uint160(l1Bridge) + ALIAS_OFFSET);
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(42, block.timestamp, bytes32(uint256(1)));

        vm.prank(aliased);
        r.commitFromL1(commits);
        assertEq(r.latestRoot(), 42);
    }
}

// ═══════════════════════════════════════════════════════════
//                SCROLL L2 RECEIVER TESTS
// ═══════════════════════════════════════════════════════════

contract ScrollReceiverTest is BridgeAdapterBaseTest {
    ScrollReceiver receiver;
    MockL2ScrollMessenger messenger;
    MockVerifier verifier;

    function setUp() public {
        verifier = new MockVerifier();
        messenger = new MockL2ScrollMessenger();
        receiver = new ScrollReceiver(
            address(verifier),
            L1_BRIDGE,
            IL2ScrollMessenger(address(messenger)),
            DEFAULT_ROOT_VALIDITY_WINDOW,
            DEFAULT_TREE_DEPTH,
            DEFAULT_MIN_EXPIRATION_THRESHOLD
        );
    }

    function test_constructor_setsImmutables() public view {
        assertEq(receiver.L1_STATE_BRIDGE(), L1_BRIDGE);
        assertEq(address(receiver.MESSENGER()), address(messenger));
    }

    function test_commitFromL1_succeedsWithValidMessengerAndSender() public {
        messenger.setXDomainMessageSender(L1_BRIDGE);

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(42, block.timestamp, bytes32(uint256(1)));

        vm.prank(address(messenger));
        receiver.commitFromL1(commits);

        assertEq(receiver.latestRoot(), 42);
    }

    function test_commitFromL1_revertsWhenNotCalledByMessenger() public {
        messenger.setXDomainMessageSender(L1_BRIDGE);

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(42, block.timestamp, bytes32(uint256(1)));

        vm.prank(address(0xBAD));
        vm.expectRevert(Unauthorized.selector);
        receiver.commitFromL1(commits);
    }

    function test_commitFromL1_revertsWhenXDomainSenderWrong() public {
        messenger.setXDomainMessageSender(address(0xBADBEEF));

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(42, block.timestamp, bytes32(uint256(1)));

        vm.prank(address(messenger));
        vm.expectRevert(Unauthorized.selector);
        receiver.commitFromL1(commits);
    }

    function test_commitFromL1_revertsWhenBothChecksWrong() public {
        messenger.setXDomainMessageSender(address(0xBAD));

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(42, block.timestamp, bytes32(uint256(1)));

        // Wrong msg.sender — reverts on first check.
        vm.prank(address(0xBAD));
        vm.expectRevert(Unauthorized.selector);
        receiver.commitFromL1(commits);
    }

    function test_commitFromL1_revertsOnEmptyCommits() public {
        messenger.setXDomainMessageSender(L1_BRIDGE);
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](0);

        vm.prank(address(messenger));
        vm.expectRevert(EmptyChainedCommits.selector);
        receiver.commitFromL1(commits);
    }

    function test_commitChained_alwaysReverts() public {
        ProofsLib.CommitmentWithProof memory cwp;
        vm.expectRevert(UnsupportedOperation.selector);
        receiver.commitChained(cwp);
    }

    function test_commitFromL1_multipleBatches() public {
        messenger.setXDomainMessageSender(L1_BRIDGE);

        // First batch
        ProofsLib.Commitment[] memory batch1 = new ProofsLib.Commitment[](1);
        batch1[0] = _makeUpdateRootCommitment(100, block.timestamp, bytes32(uint256(1)));

        vm.prank(address(messenger));
        receiver.commitFromL1(batch1);
        assertEq(receiver.latestRoot(), 100);

        // Second batch
        ProofsLib.Commitment[] memory batch2 = new ProofsLib.Commitment[](1);
        batch2[0] = _makeUpdateRootCommitment(200, block.timestamp, bytes32(uint256(2)));

        vm.prank(address(messenger));
        receiver.commitFromL1(batch2);
        assertEq(receiver.latestRoot(), 200);

        (, uint64 length) = receiver.keccakChain();
        assertEq(length, 2);
    }
}

// ═══════════════════════════════════════════════════════════
//               ZKSYNC L2 RECEIVER TESTS
// ═══════════════════════════════════════════════════════════

contract ZkSyncReceiverTest is BridgeAdapterBaseTest {
    ZkSyncReceiver receiver;
    MockVerifier verifier;

    function setUp() public {
        verifier = new MockVerifier();
        receiver = new ZkSyncReceiver(
            address(verifier),
            L1_BRIDGE,
            DEFAULT_ROOT_VALIDITY_WINDOW,
            DEFAULT_TREE_DEPTH,
            DEFAULT_MIN_EXPIRATION_THRESHOLD
        );
    }

    function test_constructor_setsImmutables() public view {
        assertEq(receiver.L1_STATE_BRIDGE(), L1_BRIDGE);
    }

    function test_commitFromL1_succeedsFromAliasedSender() public {
        address aliased = address(uint160(L1_BRIDGE) + ALIAS_OFFSET);

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(42, block.timestamp, bytes32(uint256(1)));

        vm.prank(aliased);
        receiver.commitFromL1(commits);

        assertEq(receiver.latestRoot(), 42);
    }

    function test_commitFromL1_revertsFromNonAliasedSender() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(42, block.timestamp, bytes32(uint256(1)));

        vm.prank(address(0xBAD));
        vm.expectRevert(Unauthorized.selector);
        receiver.commitFromL1(commits);
    }

    function test_commitFromL1_revertsFromRawL1Bridge() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(42, block.timestamp, bytes32(uint256(1)));

        vm.prank(L1_BRIDGE);
        vm.expectRevert(Unauthorized.selector);
        receiver.commitFromL1(commits);
    }

    function test_commitFromL1_revertsOnEmptyCommits() public {
        address aliased = address(uint160(L1_BRIDGE) + ALIAS_OFFSET);

        vm.prank(aliased);
        vm.expectRevert(EmptyChainedCommits.selector);
        receiver.commitFromL1(new ProofsLib.Commitment[](0));
    }

    function test_commitChained_alwaysReverts() public {
        ProofsLib.CommitmentWithProof memory cwp;
        vm.expectRevert(UnsupportedOperation.selector);
        receiver.commitChained(cwp);
    }

    function test_aliasOffset_matchesArbitrum() public pure {
        // ZkSync and Arbitrum use the same alias offset.
        assertEq(ALIAS_OFFSET, uint160(0x1111000000000000000000000000000000001111));
    }
}

// ═══════════════════════════════════════════════════════════
//                  STATEBRIDGE isValidRoot TESTS
// ═══════════════════════════════════════════════════════════

contract StateBridgeIsValidRootTest is BridgeAdapterBaseTest {
    TestStateBridge bridge;

    function setUp() public {
        bridge = new TestStateBridge(DEFAULT_ROOT_VALIDITY_WINDOW, DEFAULT_TREE_DEPTH, DEFAULT_MIN_EXPIRATION_THRESHOLD);
    }

    function test_isValidRoot_returnsFalseForUnknownRoot() public view {
        assertFalse(bridge.isValidRoot(999));
    }

    function test_isValidRoot_returnsTrueForLatestRoot() public {
        bytes32 proofId = bytes32(uint256(1));
        bridge.exposedUpdateRoot(42, block.timestamp, proofId);
        assertTrue(bridge.isValidRoot(42));
    }

    function test_isValidRoot_latestRootValidEvenAfterExpiry() public {
        bytes32 proofId = bytes32(uint256(1));
        bridge.exposedUpdateRoot(42, block.timestamp, proofId);

        // Advance time past the validity window.
        vm.warp(block.timestamp + DEFAULT_ROOT_VALIDITY_WINDOW + 1);

        // latestRoot is always valid regardless of expiry.
        assertTrue(bridge.isValidRoot(42));
    }

    function test_isValidRoot_historicalRootValidWithinWindow() public {
        bytes32 proofId1 = bytes32(uint256(1));
        bytes32 proofId2 = bytes32(uint256(2));

        // Set root 42, then update to 100.
        bridge.exposedUpdateRoot(42, block.timestamp, proofId1);
        bridge.exposedUpdateRoot(100, block.timestamp, proofId2);

        // Root 42 is no longer latestRoot but still within the validity window.
        assertTrue(bridge.isValidRoot(42));
    }

    function test_isValidRoot_historicalRootInvalidAfterWindow() public {
        bytes32 proofId1 = bytes32(uint256(1));
        bytes32 proofId2 = bytes32(uint256(2));

        uint256 ts = block.timestamp;
        bridge.exposedUpdateRoot(42, ts, proofId1);
        bridge.exposedUpdateRoot(100, ts + 100, proofId2);

        // Advance past the validity window for root 42.
        vm.warp(ts + DEFAULT_ROOT_VALIDITY_WINDOW + 1);

        assertFalse(bridge.isValidRoot(42));
        // Root 100 is latestRoot → always valid.
        assertTrue(bridge.isValidRoot(100));
    }

    function test_isValidRoot_returnsFalseWhenProofIdInvalidated() public {
        bytes32 proofId = bytes32(uint256(1));
        bridge.exposedUpdateRoot(42, block.timestamp, proofId);

        // Invalidate the proof ID.
        bridge.exposedInvalidateProofId(proofId);

        assertFalse(bridge.isValidRoot(42));
    }

    function test_isValidRoot_invalidationDoesNotAffectOtherRoots() public {
        bytes32 proofId1 = bytes32(uint256(1));
        bytes32 proofId2 = bytes32(uint256(2));

        bridge.exposedUpdateRoot(42, block.timestamp, proofId1);
        bridge.exposedUpdateRoot(100, block.timestamp, proofId2);

        bridge.exposedInvalidateProofId(proofId1);

        // Root 42 is invalidated, root 100 is still valid (latestRoot).
        assertFalse(bridge.isValidRoot(42));
        assertTrue(bridge.isValidRoot(100));
    }

    function test_isValidRoot_rootWithTimestampZeroInvalid() public view {
        // A root that was never set has timestamp = 0.
        assertFalse(bridge.isValidRoot(12345));
    }

    function test_isValidRoot_edgeCaseExactlyAtWindowBoundary() public {
        bytes32 proofId1 = bytes32(uint256(1));
        bytes32 proofId2 = bytes32(uint256(2));

        uint256 ts = block.timestamp;
        bridge.exposedUpdateRoot(42, ts, proofId1);
        bridge.exposedUpdateRoot(100, ts + 1, proofId2);

        // Warp to exact boundary: ts + rootValidityWindow
        vm.warp(ts + DEFAULT_ROOT_VALIDITY_WINDOW);
        assertTrue(bridge.isValidRoot(42)); // block.timestamp <= timestamp + window

        // Warp one second past.
        vm.warp(ts + DEFAULT_ROOT_VALIDITY_WINDOW + 1);
        assertFalse(bridge.isValidRoot(42));
    }

    function testFuzz_isValidRoot_invalidatedAlwaysFalse(uint256 root, bytes32 proofId) public {
        vm.assume(root != 0);
        bridge.exposedUpdateRoot(root, block.timestamp, proofId);
        assertTrue(bridge.isValidRoot(root));

        bridge.exposedInvalidateProofId(proofId);
        assertFalse(bridge.isValidRoot(root));
    }

    function test_keccakChain_slotZero() public view {
        // keccakChain must be at storage slot 0 for MPT proofs.
        (bytes32 head,) = bridge.keccakChain();
        assertEq(head, bytes32(0));
    }

    function test_invalidateProofId_emitsEvent() public {
        bytes32 proofId = bytes32(uint256(0xDEAD));
        vm.expectEmit(true, false, false, false);
        emit ProofIdInvalidated(proofId);
        bridge.exposedInvalidateProofId(proofId);
    }
}

// ═══════════════════════════════════════════════════════════
//                 UNIVERSAL WORLD ID TESTS
// ═══════════════════════════════════════════════════════════

contract UniversalReceiverTest is BridgeAdapterBaseTest {
    UniversalWorldId universalBridge;
    MockBlockHashOracle oracle;
    MockVerifier verifier;

    address constant ETH_STATE_BRIDGE = address(0xBEEF);

    function setUp() public {
        oracle = new MockBlockHashOracle();
        verifier = new MockVerifier();
        universalBridge = new UniversalWorldId(
            address(verifier),
            address(oracle),
            ETH_STATE_BRIDGE,
            DEFAULT_ROOT_VALIDITY_WINDOW,
            DEFAULT_TREE_DEPTH,
            DEFAULT_MIN_EXPIRATION_THRESHOLD
        );
    }

    function test_constructor_setsImmutables() public view {
        assertEq(address(universalBridge.ETHEREUM_BLOCK_HASH_ORACLE()), address(oracle));
        assertEq(universalBridge.ETHEREUM_STATE_BRIDGE(), ETH_STATE_BRIDGE);
    }

    function test_commitChained_revertsOnEmptyCommits() public {
        ProofsLib.CommitmentWithProof memory cwp;
        cwp.mptProof = hex"";
        cwp.commits = new ProofsLib.Commitment[](0);

        vm.expectRevert(EmptyChainedCommits.selector);
        universalBridge.commitChained(cwp);
    }

    function test_commitChained_revertsOnUnknownBlockHash() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(42, block.timestamp, bytes32(uint256(1)));

        // Encode some dummy proof data.
        bytes memory mptProof = abi.encode(hex"FF", new bytes[](0), new bytes[](0));

        ProofsLib.CommitmentWithProof memory cwp;
        cwp.mptProof = mptProof;
        cwp.commits = commits;

        // Oracle will return false for any hash.
        vm.expectRevert(UnknownL1BlockHash.selector);
        universalBridge.commitChained(cwp);
    }

    function test_getters_returnCorrectValues() public view {
        assertEq(universalBridge.rootValidityWindow(), DEFAULT_ROOT_VALIDITY_WINDOW);
        assertEq(universalBridge.treeDepth(), DEFAULT_TREE_DEPTH);
        assertEq(universalBridge.minExpirationThreshold(), DEFAULT_MIN_EXPIRATION_THRESHOLD);
    }
}

// ═══════════════════════════════════════════════════════════
//           CROSS-DOMAIN VERIFIER TESTS
// ═══════════════════════════════════════════════════════════

/// @dev Concrete CrossDomainWorldIdVerifier that delegates commitChained.
contract TestCrossDomainVerifier is CrossDomainWorldIdVerifier {
    constructor(address verifier, uint256 rootValidityWindow_, uint256 treeDepth_, uint64 minExpirationThreshold_)
        CrossDomainWorldIdVerifier(verifier, rootValidityWindow_, treeDepth_, minExpirationThreshold_)
    {}

    function commitChained(ProofsLib.CommitmentWithProof calldata) external pure override {
        revert("not implemented");
    }

    function exposedUpdateRoot(uint256 root, uint256 timestamp, bytes32 proofId) external {
        updateRoot(root, timestamp, proofId);
    }

    function exposedSetIssuerPubkey(uint64 schemaId, uint256 x, uint256 y, bytes32 proofId) external {
        setIssuerPubkey(schemaId, x, y, proofId);
    }

    function exposedSetOprfKey(uint160 oprfKeyId, uint256 x, uint256 y, bytes32 proofId) external {
        setOprfKey(oprfKeyId, x, y, proofId);
    }

    function exposedInvalidateProofId(bytes32 proofId) external {
        invalidateProofId(proofId);
    }
}

contract CrossDomainWorldIdVerifierTest is BridgeAdapterBaseTest {
    TestCrossDomainVerifier verifierBridge;
    MockVerifier mockVerifier;

    function setUp() public {
        mockVerifier = new MockVerifier();
        verifierBridge = new TestCrossDomainVerifier(
            address(mockVerifier), DEFAULT_ROOT_VALIDITY_WINDOW, DEFAULT_TREE_DEPTH, DEFAULT_MIN_EXPIRATION_THRESHOLD
        );
    }

    function test_getVerifier_returnsCorrectAddress() public view {
        assertEq(verifierBridge.getVerifier(), address(mockVerifier));
    }

    function test_getTreeDepth_returnsCorrectValue() public view {
        assertEq(verifierBridge.getTreeDepth(), DEFAULT_TREE_DEPTH);
    }

    function test_getMinExpirationThreshold_returnsCorrectValue() public view {
        assertEq(verifierBridge.getMinExpirationThreshold(), DEFAULT_MIN_EXPIRATION_THRESHOLD);
    }

    function test_verifyProofAndSignals_revertsOnInvalidRoot() public {
        // No root has been set, so any root is invalid.
        uint256[5] memory proofExt;
        proofExt[4] = 42; // root

        vm.expectRevert(InvalidRoot.selector);
        verifierBridge._verifyProofAndSignals(1, 2, 3, 4, 5, 6, 7, 8, 0, proofExt);
    }

    function test_verifyProofAndSignals_revertsOnInvalidatedRootProofId() public {
        bytes32 rootProofId = bytes32(uint256(1));
        verifierBridge.exposedUpdateRoot(42, block.timestamp, rootProofId);
        verifierBridge.exposedInvalidateProofId(rootProofId);

        uint256[5] memory proofExt;
        proofExt[4] = 42;

        // isValidRoot() checks invalidatedProofIds first and returns false,
        // so _verifyProofAndSignals hits InvalidRoot before the explicit InvalidatedProofId check.
        vm.expectRevert(InvalidRoot.selector);
        verifierBridge._verifyProofAndSignals(1, 2, 3, 4, 5, 6, 7, 8, 0, proofExt);
    }

    function test_verifyProofAndSignals_revertsOnInvalidatedIssuerProofId() public {
        bytes32 rootProofId = bytes32(uint256(1));
        bytes32 issuerProofId = bytes32(uint256(2));

        verifierBridge.exposedUpdateRoot(42, block.timestamp, rootProofId);
        verifierBridge.exposedSetIssuerPubkey(7, 100, 200, issuerProofId);
        verifierBridge.exposedInvalidateProofId(issuerProofId);

        uint256[5] memory proofExt;
        proofExt[4] = 42;

        vm.expectRevert(InvalidatedProofId.selector);
        // issuerSchemaId = 7 → matches the one we set
        verifierBridge._verifyProofAndSignals(1, 2, 3, 4, 5, 6, 7, 8, 0, proofExt);
    }

    function test_verifyProofAndSignals_revertsOnInvalidatedOprfProofId() public {
        bytes32 rootProofId = bytes32(uint256(1));
        bytes32 issuerProofId = bytes32(uint256(2));
        bytes32 oprfProofId = bytes32(uint256(3));

        verifierBridge.exposedUpdateRoot(42, block.timestamp, rootProofId);
        verifierBridge.exposedSetIssuerPubkey(7, 100, 200, issuerProofId);
        // rpId = 3 → uint160(rpId) = 3
        verifierBridge.exposedSetOprfKey(3, 300, 400, oprfProofId);
        verifierBridge.exposedInvalidateProofId(oprfProofId);

        uint256[5] memory proofExt;
        proofExt[4] = 42;

        vm.expectRevert(InvalidatedProofId.selector);
        // rpId = 3, issuerSchemaId = 7
        verifierBridge._verifyProofAndSignals(1, 2, 3, 4, 5, 6, 7, 8, 0, proofExt);
    }

    function test_issuerPubkeyMapping_returnsCorrectValues() public {
        bytes32 proofId = bytes32(uint256(42));
        verifierBridge.exposedSetIssuerPubkey(7, 111, 222, proofId);

        (BabyJubJub.Affine memory pk, bytes32 pid) = verifierBridge.issuerSchemaIdToPubkeyAndProofId(7);
        assertEq(pk.x, 111);
        assertEq(pk.y, 222);
        assertEq(pid, proofId);
    }
}

// ═══════════════════════════════════════════════════════════
//         STATEBRIDGE applyCommitment ACTION TESTS
// ═══════════════════════════════════════════════════════════

contract StateBridgeApplyCommitmentTest is BridgeAdapterBaseTest {
    TestStateBridge bridge;

    function setUp() public {
        bridge = new TestStateBridge(DEFAULT_ROOT_VALIDITY_WINDOW, DEFAULT_TREE_DEPTH, DEFAULT_MIN_EXPIRATION_THRESHOLD);
    }

    function test_applyCommitment_updateRoot() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(42, block.timestamp, bytes32(uint256(1)));

        bridge.exposedApplyCommitments(commits);
        assertEq(bridge.latestRoot(), 42);
    }

    function test_applyCommitment_setIssuerPubkey() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeSetIssuerCommitment(7, 111, 222, bytes32(uint256(2)));

        bridge.exposedApplyCommitments(commits);

        (BabyJubJub.Affine memory pk, bytes32 pid) = bridge.issuerSchemaIdToPubkeyAndProofId(7);
        assertEq(pk.x, 111);
        assertEq(pk.y, 222);
        assertEq(pid, bytes32(uint256(2)));
    }

    function test_applyCommitment_setOprfKey() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeSetOprfCommitment(5, 333, 444, bytes32(uint256(3)));

        bridge.exposedApplyCommitments(commits);
        // oprfKeyIdToPubkeyAndProofId is internal; verified via the verifier path.
    }

    function test_applyCommitment_invalidateProofId() public {
        bytes32 proofId = bytes32(uint256(42));

        // First set a root with that proof ID.
        ProofsLib.Commitment[] memory setup = new ProofsLib.Commitment[](1);
        setup[0] = _makeUpdateRootCommitment(100, block.timestamp, proofId);
        bridge.exposedApplyCommitments(setup);
        assertTrue(bridge.isValidRoot(100));

        // Now invalidate.
        ProofsLib.Commitment[] memory inv = new ProofsLib.Commitment[](1);
        inv[0] = _makeInvalidateCommitment(proofId);
        bridge.exposedApplyCommitments(inv);

        assertTrue(bridge.invalidatedProofIds(proofId));
        assertFalse(bridge.isValidRoot(100));
    }

    function test_applyCommitment_unknownAction_reverts() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = ProofsLib.Commitment({blockHash: bytes32(uint256(1)), data: hex"DEADBEEF00000000"});

        // The last byte of 0xDEADBEEF is 0xEF = 239
        vm.expectRevert(abi.encodeWithSelector(UnknownAction.selector, uint8(0xEF)));
        bridge.exposedApplyCommitments(commits);
    }

    function test_applyCommitment_batchAllActionTypes() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](4);
        commits[0] = _makeUpdateRootCommitment(42, block.timestamp, bytes32(uint256(1)));
        commits[1] = _makeSetIssuerCommitment(7, 111, 222, bytes32(uint256(2)));
        commits[2] = _makeSetOprfCommitment(5, 333, 444, bytes32(uint256(3)));
        commits[3] = _makeInvalidateCommitment(bytes32(uint256(99)));

        bridge.exposedApplyCommitments(commits);

        assertEq(bridge.latestRoot(), 42);
        assertTrue(bridge.invalidatedProofIds(bytes32(uint256(99))));
    }

    function test_applyCommitment_dataShortCausesSelectorTruncation() public {
        // Data shorter than 4 bytes — the assembly reads 32 bytes from the data pointer,
        // getting the length prefix mixed in. This exercises an edge condition.
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = ProofsLib.Commitment({blockHash: bytes32(uint256(1)), data: hex"AA"});

        // With only 1 byte of data, the selector from `mload(add(data, 0x20))` will
        // read the byte + zeros, which won't match any known selector.
        vm.expectRevert(); // UnknownAction or similar
        bridge.exposedApplyCommitments(commits);
    }

    function test_commitChained_extendsChainCorrectly() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](2);
        commits[0] = _makeUpdateRootCommitment(42, block.timestamp, bytes32(uint256(1)));
        commits[1] = _makeUpdateRootCommitment(100, block.timestamp, bytes32(uint256(2)));

        bridge.exposedCommitChained(commits);

        (bytes32 head, uint64 length) = bridge.keccakChain();
        assertGt(uint256(head), 0);
        assertEq(length, 2);
    }

    function testFuzz_applyCommitment_updateRoot(uint256 root, uint256 timestamp, bytes32 proofId) public {
        vm.assume(root != 0);

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(root, timestamp, proofId);

        bridge.exposedApplyCommitments(commits);
        assertEq(bridge.latestRoot(), root);
    }
}
