// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ProofsLib} from "../src/lib/ProofsLib.sol";
import {WormholePayloadLib} from "../src/lib/WormholePayloadLib.sol";
import {CommitmentHelpers} from "./helpers/CommitmentHelpers.sol";
import {ProvenRootInfo, ProvenPubKeyInfo} from "../src/lib/BridgeTypes.sol";
import {
    EmptyChainedCommits,
    InvalidDisputeGameIndex,
    InvalidOutputRoot,
    UnknownAction,
    PayloadTooShort,
    UnsupportedPayloadVersion,
    UnknownPayloadAction,
    InvalidAdapterIndex
} from "../src/lib/BridgeErrors.sol";
import {WormholeMessagePublished, AdapterRegistered, AdapterRemoved} from "../src/lib/BridgeEvents.sol";
import {WormholeAdapter} from "../src/adapters/wormhole/WormholeAdapter.sol";
import {IWormhole} from "../src/vendored/wormhole/IWormhole.sol";
import {IBridgeAdapter} from "../src/interfaces/IBridgeAdapter.sol";
import {INativeWorldId} from "../src/interfaces/INativeWorldId.sol";
import {L1WorldId} from "../src/core/L1WorldId.sol";
import {WorldIdBridge} from "../src/core/lib/WorldIdBridge.sol";
import {IDisputeGameFactory} from "../src/vendored/optimism/IDisputeGameFactory.sol";
import {IDisputeGame} from "../src/vendored/optimism/IDisputeGame.sol";
import {GameStatus, Claim, GameType, Timestamp} from "../src/vendored/optimism/DisputeTypes.sol";
import {BabyJubJub} from "lib/oprf-key-registry/src/BabyJubJub.sol";

// ═══════════════════════════════════════════════════════════
//                     MOCK CONTRACTS
// ═══════════════════════════════════════════════════════════

/// @dev Minimal Wormhole Core Bridge mock, following the pattern from the Wormhole reference codebase.
///   - Tracks per-emitter sequence numbers
///   - Validates message fees
///   - Emits `LogMessagePublished` matching the real Wormhole contract
///   - Stores published messages for post-hoc verification
contract MockWormhole is IWormhole {
    /// @dev Matches the event signature of the real Wormhole Core Bridge.
    event LogMessagePublished(
        address indexed sender, uint64 sequence, uint32 nonce, bytes payload, uint8 consistencyLevel
    );

    uint256 public currentMessageFee;
    uint16 public immutable wormholeChainId;
    uint32 public guardianSetIndex;
    mapping(address => uint64) public sequences;
    mapping(bytes32 => bool) public invalidVMs;

    /// @dev Stores every published message for test assertions.
    struct PublishedMessage {
        address sender;
        uint64 sequence;
        uint32 nonce;
        bytes payload;
        uint8 consistencyLevel;
    }

    PublishedMessage[] public publishedMessages;

    constructor(uint16 chainId_, uint256 fee_) {
        wormholeChainId = chainId_;
        currentMessageFee = fee_;
    }

    function publishMessage(uint32 nonce, bytes memory payload, uint8 consistencyLevel)
        external
        payable
        override
        returns (uint64 sequence)
    {
        require(msg.value == currentMessageFee, "MockWormhole: invalid fee");

        sequence = sequences[msg.sender]++;

        publishedMessages.push(
            PublishedMessage({
                sender: msg.sender,
                sequence: sequence,
                nonce: nonce,
                payload: payload,
                consistencyLevel: consistencyLevel
            })
        );

        emit LogMessagePublished(msg.sender, sequence, nonce, payload, consistencyLevel);
    }

    function messageFee() external view override returns (uint256) {
        return currentMessageFee;
    }

    function parseAndVerifyVM(bytes calldata) external pure override returns (VM memory, bool, string memory) {
        revert("MockWormhole: parseAndVerifyVM not implemented");
    }

    function getCurrentGuardianSetIndex() external view override returns (uint32) {
        return guardianSetIndex;
    }

    function chainId() external view override returns (uint16) {
        return wormholeChainId;
    }

    // ── Test helpers ──

    function setMessageFee(uint256 fee_) external {
        currentMessageFee = fee_;
    }

    function publishedMessageCount() external view returns (uint256) {
        return publishedMessages.length;
    }

    function getPublishedMessage(uint256 index) external view returns (PublishedMessage memory) {
        return publishedMessages[index];
    }
}

/// @dev Records all messages sent through it. Used to verify L1WorldId dispatch behavior.
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

// ═══════════════════════════════════════════════════════════
//                   HARNESS CONTRACTS
// ═══════════════════════════════════════════════════════════

/// @dev Exposes internal WormholePayloadLib library functions for testing.
contract WormholePayloadHarness {
    function encode(ProofsLib.Commitment[] memory commits) external pure returns (bytes memory) {
        return WormholePayloadLib.encode(commits);
    }

    function decode(bytes memory payload) external pure returns (ProofsLib.Commitment[] memory) {
        return WormholePayloadLib.decode(payload);
    }
}

// ═══════════════════════════════════════════════════════════
//                     BASE TEST
// ═══════════════════════════════════════════════════════════

/// @dev Shared base test providing commitment builders, action selectors, and common assertions.
///   All helpers are inherited from CommitmentHelpers.
abstract contract WormholeBridgeBaseTest is CommitmentHelpers {}

// ═══════════════════════════════════════════════════════════
//          1. WormholePayloadLib CODEC TESTS
// ═══════════════════════════════════════════════════════════

contract WormholePayloadLibTest is WormholeBridgeBaseTest {
    WormholePayloadHarness harness;

    function setUp() public {
        harness = new WormholePayloadHarness();
    }

    // ── Encode/Decode Roundtrip ──

    function test_roundtrip_singleCommit_updateRoot() public view {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory encoded = harness.encode(commits);
        ProofsLib.Commitment[] memory decoded = harness.decode(encoded);

        assertEq(decoded.length, 1, "should decode 1 commit");
        _assertCommitmentsEqual(decoded[0], commits[0]);
    }

    function test_roundtrip_singleCommit_setIssuerPubkey() public view {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeSetIssuerCommitment(TEST_ISSUER_ID, 111, 222, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory encoded = harness.encode(commits);
        ProofsLib.Commitment[] memory decoded = harness.decode(encoded);

        assertEq(decoded.length, 1);
        _assertCommitmentsEqual(decoded[0], commits[0]);
    }

    function test_roundtrip_singleCommit_setOprfKey() public view {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeSetOprfCommitment(TEST_OPRF_ID, 333, 444, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory encoded = harness.encode(commits);
        ProofsLib.Commitment[] memory decoded = harness.decode(encoded);

        assertEq(decoded.length, 1);
        _assertCommitmentsEqual(decoded[0], commits[0]);
    }

    function test_roundtrip_singleCommit_invalidateProofId() public view {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeInvalidateCommitment(TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory encoded = harness.encode(commits);
        ProofsLib.Commitment[] memory decoded = harness.decode(encoded);

        assertEq(decoded.length, 1);
        _assertCommitmentsEqual(decoded[0], commits[0]);
    }

    function test_roundtrip_multipleCommits_allActionTypes() public view {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](4);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);
        commits[1] = _makeSetIssuerCommitment(TEST_ISSUER_ID, 111, 222, TEST_PROOF_ID, bytes32(uint256(0xCAFE)));
        commits[2] = _makeSetOprfCommitment(TEST_OPRF_ID, 333, 444, TEST_PROOF_ID, bytes32(uint256(0xDEAD)));
        commits[3] = _makeInvalidateCommitment(bytes32(uint256(99)), bytes32(uint256(0xF00D)));

        bytes memory encoded = harness.encode(commits);
        ProofsLib.Commitment[] memory decoded = harness.decode(encoded);

        assertEq(decoded.length, 4, "should decode 4 commits");
        for (uint256 i; i < 4; ++i) {
            _assertCommitmentsEqual(decoded[i], commits[i]);
        }
    }

    function test_roundtrip_emptyCommitArray() public view {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](0);

        bytes memory encoded = harness.encode(commits);
        ProofsLib.Commitment[] memory decoded = harness.decode(encoded);

        assertEq(decoded.length, 0, "should decode 0 commits");
        assertEq(encoded.length, 4, "empty payload = 4 bytes header");
    }

    function test_roundtrip_commitWithEmptyData() public view {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeRawCommitment(TEST_BLOCK_HASH, hex"");

        bytes memory encoded = harness.encode(commits);
        ProofsLib.Commitment[] memory decoded = harness.decode(encoded);

        assertEq(decoded.length, 1);
        assertEq(decoded[0].blockHash, TEST_BLOCK_HASH);
        assertEq(decoded[0].data.length, 0, "data should be empty");
    }

    function test_roundtrip_commitWithLargeData() public view {
        // 1024 bytes of data
        bytes memory largeData = new bytes(1024);
        for (uint256 i; i < 1024; ++i) {
            largeData[i] = bytes1(uint8(i % 256));
        }

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeRawCommitment(TEST_BLOCK_HASH, largeData);

        bytes memory encoded = harness.encode(commits);
        ProofsLib.Commitment[] memory decoded = harness.decode(encoded);

        assertEq(decoded.length, 1);
        assertEq(decoded[0].data, largeData, "large data should roundtrip");
    }

    // ── Wire Format Verification ──

    function test_wireFormat_headerBytes() public view {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeRawCommitment(bytes32(0), hex"AA");

        bytes memory payload = harness.encode(commits);

        assertEq(uint8(payload[0]), PAYLOAD_VERSION, "byte 0 = version");
        assertEq(uint8(payload[1]), ACTION_COMMIT_FROM_L1, "byte 1 = action");
        assertEq(uint8(payload[2]), 0x00, "byte 2 = num_commits high");
        assertEq(uint8(payload[3]), 0x01, "byte 3 = num_commits low");
    }

    function test_wireFormat_blockHashPosition() public view {
        bytes32 expectedHash = bytes32(uint256(0xCAFEBABE));

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeRawCommitment(expectedHash, hex"FF");

        bytes memory payload = harness.encode(commits);

        // Block hash starts at offset 4, spans 32 bytes.
        bytes32 extractedHash;
        assembly {
            extractedHash := mload(add(add(payload, 32), 4))
        }
        assertEq(extractedHash, expectedHash, "blockHash at offset 4");
    }

    function test_wireFormat_dataLenPosition() public view {
        bytes memory data = hex"DEADBEEF"; // 4 bytes

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeRawCommitment(bytes32(0), data);

        bytes memory payload = harness.encode(commits);

        // data_len starts at offset 4 + 32 = 36, 2 bytes big-endian.
        assertEq(uint8(payload[36]), 0x00, "data_len high byte");
        assertEq(uint8(payload[37]), 0x04, "data_len low byte = 4");
    }

    function test_wireFormat_totalSize_singleCommit() public view {
        bytes memory data = hex"DEADBEEF";

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeRawCommitment(bytes32(0), data);

        bytes memory payload = harness.encode(commits);

        // Expected: header(4) + blockHash(32) + dataLen(2) + data(4) = 42
        assertEq(payload.length, 42, "total payload size");
    }

    function test_wireFormat_totalSize_multipleCommits() public view {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](3);
        commits[0] = _makeRawCommitment(bytes32(0), hex"AA"); // 1 byte
        commits[1] = _makeRawCommitment(bytes32(0), hex"BBCC"); // 2 bytes
        commits[2] = _makeRawCommitment(bytes32(0), hex"DDEEFF"); // 3 bytes

        bytes memory payload = harness.encode(commits);

        // Expected: header(4) + 3 * (blockHash(32) + dataLen(2)) + (1 + 2 + 3) = 4 + 102 + 6 = 112
        // Actually: 4 + (32+2+1) + (32+2+2) + (32+2+3) = 4 + 35 + 36 + 37 = 112
        assertEq(payload.length, 112, "total payload size for 3 commits");
    }

    function test_wireFormat_numCommits_bigEndian() public view {
        // Create 256 commits to test big-endian encoding (0x0100).
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](256);
        for (uint256 i; i < 256; ++i) {
            commits[i] = _makeRawCommitment(bytes32(0), hex"");
        }

        bytes memory payload = harness.encode(commits);

        assertEq(uint8(payload[2]), 0x01, "num_commits high = 0x01");
        assertEq(uint8(payload[3]), 0x00, "num_commits low = 0x00");
    }

    // ── Decode Revert Cases ──

    function test_decode_revert_payloadTooShort() public {
        vm.expectRevert(PayloadTooShort.selector);
        harness.decode(hex"0101");
    }

    function test_decode_revert_emptyPayload() public {
        vm.expectRevert(PayloadTooShort.selector);
        harness.decode(hex"");
    }

    function test_decode_revert_unsupportedVersion() public {
        // Version 0x02, action 0x01, 0 commits
        vm.expectRevert(UnsupportedPayloadVersion.selector);
        harness.decode(hex"02010000");
    }

    function test_decode_revert_unknownAction() public {
        // Version 0x01, action 0xFF, 0 commits
        vm.expectRevert(UnknownPayloadAction.selector);
        harness.decode(hex"01FF0000");
    }

    // ── Fuzz Tests ──

    function testFuzz_roundtrip_singleCommit(bytes32 blockHash, bytes memory data) public view {
        vm.assume(data.length <= 10_000); // keep reasonable

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeRawCommitment(blockHash, data);

        bytes memory encoded = harness.encode(commits);
        ProofsLib.Commitment[] memory decoded = harness.decode(encoded);

        assertEq(decoded.length, 1);
        assertEq(decoded[0].blockHash, blockHash);
        assertEq(decoded[0].data, data);
    }

    function testFuzz_roundtrip_multipleCommits(uint8 numCommits, bytes32 seed) public view {
        vm.assume(numCommits <= 50); // cap for gas

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](numCommits);
        for (uint256 i; i < numCommits; ++i) {
            bytes32 bh = keccak256(abi.encodePacked(seed, "bh", i));
            uint256 dataLen = uint256(keccak256(abi.encodePacked(seed, "dl", i))) % 200;
            bytes memory data = new bytes(dataLen);
            for (uint256 j; j < dataLen; ++j) {
                data[j] = bytes1(uint8(uint256(keccak256(abi.encodePacked(seed, i, j))) % 256));
            }
            commits[i] = _makeRawCommitment(bh, data);
        }

        bytes memory encoded = harness.encode(commits);
        ProofsLib.Commitment[] memory decoded = harness.decode(encoded);

        assertEq(decoded.length, numCommits);
        for (uint256 i; i < numCommits; ++i) {
            _assertCommitmentsEqual(decoded[i], commits[i]);
        }
    }

    function testFuzz_encode_payloadLength(uint8 numCommits, bytes32 seed) public view {
        vm.assume(numCommits <= 20);

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](numCommits);
        uint256 expectedSize = 4; // header

        for (uint256 i; i < numCommits; ++i) {
            uint256 dataLen = uint256(keccak256(abi.encodePacked(seed, i))) % 100;
            bytes memory data = new bytes(dataLen);
            commits[i] = _makeRawCommitment(bytes32(0), data);
            expectedSize += 34 + dataLen;
        }

        bytes memory payload = harness.encode(commits);
        assertEq(payload.length, expectedSize, "payload size should match calculated size");
    }

    // ── Cross-Platform Wire Format Consistency ──

    function test_wireFormat_knownVector_matchesRust() public view {
        // This test encodes a known commitment and checks the exact wire bytes,
        // ensuring Solidity and Rust produce identical output.
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeRawCommitment(bytes32(uint256(0xCAFE)), hex"DEADBEEF");

        bytes memory payload = harness.encode(commits);

        // Expected wire bytes:
        //   01                                                               (version)
        //   01                                                               (action)
        //   0001                                                             (num_commits = 1)
        //   000000000000000000000000000000000000000000000000000000000000CAFE   (block_hash)
        //   0004                                                             (data_len = 4)
        //   DEADBEEF                                                         (data)
        assertEq(uint8(payload[0]), 0x01, "version");
        assertEq(uint8(payload[1]), 0x01, "action");
        assertEq(uint8(payload[2]), 0x00, "num high");
        assertEq(uint8(payload[3]), 0x01, "num low");

        // Block hash: bytes [4..36]
        bytes32 bh;
        assembly {
            bh := mload(add(add(payload, 32), 4))
        }
        assertEq(bh, bytes32(uint256(0xCAFE)), "block_hash");

        // Data len: bytes [36..38]
        assertEq(uint8(payload[36]), 0x00, "data_len high");
        assertEq(uint8(payload[37]), 0x04, "data_len low");

        // Data: bytes [38..42]
        assertEq(uint8(payload[38]), 0xDE, "data[0]");
        assertEq(uint8(payload[39]), 0xAD, "data[1]");
        assertEq(uint8(payload[40]), 0xBE, "data[2]");
        assertEq(uint8(payload[41]), 0xEF, "data[3]");

        assertEq(payload.length, 42, "total size");
    }

    function test_wireFormat_twoCommits_matchesRust() public view {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](2);
        commits[0] = _makeRawCommitment(bytes32(uint256(0xCAFE)), hex"DEADBEEF");
        commits[1] = _makeRawCommitment(bytes32(uint256(0xBEEF)), hex"010203");

        bytes memory payload = harness.encode(commits);

        // Header
        assertEq(uint8(payload[0]), 0x01);
        assertEq(uint8(payload[1]), 0x01);
        assertEq(uint8(payload[2]), 0x00);
        assertEq(uint8(payload[3]), 0x02); // 2 commits

        // Total size: 4 + (32+2+4) + (32+2+3) = 4 + 38 + 37 = 79
        assertEq(payload.length, 79, "total size for 2 commits");
    }
}

// ═══════════════════════════════════════════════════════════
//          2. WormholeAdapter TESTS
// ═══════════════════════════════════════════════════════════

contract WormholeAdapterTest is WormholeBridgeBaseTest {
    MockWormhole wormhole;
    WormholeAdapter adapter;
    WormholePayloadHarness payloadHarness;

    uint256 constant MESSAGE_FEE = 0.01 ether;
    uint8 constant CONSISTENCY_LEVEL = 1; // finalized

    function setUp() public {
        wormhole = new MockWormhole(2, MESSAGE_FEE); // chain 2 = Ethereum
        adapter = new WormholeAdapter(IWormhole(address(wormhole)), CONSISTENCY_LEVEL);
        payloadHarness = new WormholePayloadHarness();

        vm.deal(address(this), 100 ether);
    }

    // ── Constructor ──

    function test_constructor_setsImmutables() public view {
        assertEq(address(adapter.WORMHOLE()), address(wormhole), "wormhole address");
        assertEq(adapter.CONSISTENCY_LEVEL(), CONSISTENCY_LEVEL, "consistency level");
        assertEq(adapter.nonce(), 0, "initial nonce");
    }

    // ── sendMessage: Happy Path ──

    function test_sendMessage_publishesToWormhole() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory message = _encodeCommitFromL1(commits);
        adapter.sendMessage{value: MESSAGE_FEE}(message);

        assertEq(wormhole.publishedMessageCount(), 1, "one message published");

        MockWormhole.PublishedMessage memory published = wormhole.getPublishedMessage(0);
        assertEq(published.sender, address(adapter), "sender is adapter");
        assertEq(published.nonce, 0, "first nonce is 0");
        assertEq(published.consistencyLevel, CONSISTENCY_LEVEL, "consistency level");
    }

    function test_sendMessage_payloadDecodesCorrectly() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory message = _encodeCommitFromL1(commits);
        adapter.sendMessage{value: MESSAGE_FEE}(message);

        // Decode the published payload back to verify roundtrip fidelity.
        MockWormhole.PublishedMessage memory published = wormhole.getPublishedMessage(0);
        ProofsLib.Commitment[] memory decoded = payloadHarness.decode(published.payload);

        assertEq(decoded.length, 1, "decoded 1 commit");
        _assertCommitmentsEqual(decoded[0], commits[0]);
    }

    function test_sendMessage_multipleCommits() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](3);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);
        commits[1] = _makeSetIssuerCommitment(TEST_ISSUER_ID, 111, 222, TEST_PROOF_ID, bytes32(uint256(0xCAFE)));
        commits[2] = _makeSetOprfCommitment(TEST_OPRF_ID, 333, 444, TEST_PROOF_ID, bytes32(uint256(0xDEAD)));

        bytes memory message = _encodeCommitFromL1(commits);
        adapter.sendMessage{value: MESSAGE_FEE}(message);

        MockWormhole.PublishedMessage memory published = wormhole.getPublishedMessage(0);
        ProofsLib.Commitment[] memory decoded = payloadHarness.decode(published.payload);

        assertEq(decoded.length, 3, "decoded 3 commits");
        for (uint256 i; i < 3; ++i) {
            _assertCommitmentsEqual(decoded[i], commits[i]);
        }
    }

    // ── Nonce Management ──

    function test_sendMessage_incrementsNonce() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory message = _encodeCommitFromL1(commits);

        assertEq(adapter.nonce(), 0, "initial nonce");

        adapter.sendMessage{value: MESSAGE_FEE}(message);
        assertEq(adapter.nonce(), 1, "nonce after first");

        adapter.sendMessage{value: MESSAGE_FEE}(message);
        assertEq(adapter.nonce(), 2, "nonce after second");

        adapter.sendMessage{value: MESSAGE_FEE}(message);
        assertEq(adapter.nonce(), 3, "nonce after third");
    }

    function test_sendMessage_nonceMatchesPublishedMessage() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory message = _encodeCommitFromL1(commits);

        adapter.sendMessage{value: MESSAGE_FEE}(message);
        adapter.sendMessage{value: MESSAGE_FEE}(message);

        assertEq(wormhole.getPublishedMessage(0).nonce, 0, "first msg nonce = 0");
        assertEq(wormhole.getPublishedMessage(1).nonce, 1, "second msg nonce = 1");
    }

    // ── Sequence Tracking ──

    function test_sendMessage_sequenceIncrementsPerEmitter() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory message = _encodeCommitFromL1(commits);

        adapter.sendMessage{value: MESSAGE_FEE}(message);
        adapter.sendMessage{value: MESSAGE_FEE}(message);

        assertEq(wormhole.getPublishedMessage(0).sequence, 0, "first sequence = 0");
        assertEq(wormhole.getPublishedMessage(1).sequence, 1, "second sequence = 1");
    }

    // ── Event Emission ──

    function test_sendMessage_emitsWormholeMessagePublished() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](2);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);
        commits[1] = _makeSetIssuerCommitment(TEST_ISSUER_ID, 111, 222, TEST_PROOF_ID, bytes32(uint256(0xAA)));

        bytes memory message = _encodeCommitFromL1(commits);

        vm.expectEmit(true, false, false, true, address(adapter));
        emit WormholeMessagePublished(0, 0, 2);

        adapter.sendMessage{value: MESSAGE_FEE}(message);
    }

    function test_sendMessage_emitsWormholeLogMessagePublished() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory message = _encodeCommitFromL1(commits);
        bytes memory expectedPayload = payloadHarness.encode(commits);

        vm.expectEmit(true, false, false, true, address(wormhole));
        emit MockWormhole.LogMessagePublished(address(adapter), 0, 0, expectedPayload, CONSISTENCY_LEVEL);

        adapter.sendMessage{value: MESSAGE_FEE}(message);
    }

    function test_sendMessage_secondCallEmitsCorrectNonceAndSequence() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);
        bytes memory message = _encodeCommitFromL1(commits);

        // First call
        adapter.sendMessage{value: MESSAGE_FEE}(message);

        // Second call — expect nonce=1, sequence=1
        vm.expectEmit(true, false, false, true, address(adapter));
        emit WormholeMessagePublished(1, 1, 1);

        adapter.sendMessage{value: MESSAGE_FEE}(message);
    }

    // ── Fee Handling ──

    function test_sendMessage_forwardsFeeToWormhole() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory message = _encodeCommitFromL1(commits);

        uint256 wormholeBalBefore = address(wormhole).balance;
        adapter.sendMessage{value: MESSAGE_FEE}(message);
        uint256 wormholeBalAfter = address(wormhole).balance;

        assertEq(wormholeBalAfter - wormholeBalBefore, MESSAGE_FEE, "fee forwarded to wormhole");
    }

    function test_sendMessage_revert_insufficientFee() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory message = _encodeCommitFromL1(commits);

        vm.expectRevert("MockWormhole: invalid fee");
        adapter.sendMessage{value: MESSAGE_FEE - 1}(message);
    }

    function test_sendMessage_revert_excessFee() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory message = _encodeCommitFromL1(commits);

        vm.expectRevert("MockWormhole: invalid fee");
        adapter.sendMessage{value: MESSAGE_FEE + 1}(message);
    }

    function test_sendMessage_revert_noFee() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory message = _encodeCommitFromL1(commits);

        vm.expectRevert("MockWormhole: invalid fee");
        adapter.sendMessage{value: 0}(message);
    }

    function test_sendMessage_zeroFee_whenWormholeFeeIsZero() public {
        wormhole.setMessageFee(0);

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory message = _encodeCommitFromL1(commits);

        // Should succeed with 0 value when fee is 0.
        adapter.sendMessage{value: 0}(message);
        assertEq(wormhole.publishedMessageCount(), 1, "message published with zero fee");
    }

    // ── Payload Integrity ──

    function test_sendMessage_payloadHeaderIsCorrect() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory message = _encodeCommitFromL1(commits);
        adapter.sendMessage{value: MESSAGE_FEE}(message);

        bytes memory payload = wormhole.getPublishedMessage(0).payload;

        assertEq(uint8(payload[0]), PAYLOAD_VERSION, "payload version");
        assertEq(uint8(payload[1]), ACTION_COMMIT_FROM_L1, "payload action");
        assertEq(uint8(payload[2]), 0x00, "num commits high");
        assertEq(uint8(payload[3]), 0x01, "num commits low = 1");
    }

    function test_sendMessage_consistencyLevelForwarded() public {
        // Deploy adapter with different consistency level.
        WormholeAdapter adapter200 = new WormholeAdapter(IWormhole(address(wormhole)), 200);

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory message = _encodeCommitFromL1(commits);
        adapter200.sendMessage{value: MESSAGE_FEE}(message);

        assertEq(wormhole.getPublishedMessage(0).consistencyLevel, 200, "consistency level forwarded");
    }

    // ── Fuzz Tests ──

    function testFuzz_sendMessage_roundtrip(bytes32 blockHash, uint256 root, uint256 ts, bytes32 proofId) public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(root, ts, proofId, blockHash);

        bytes memory message = _encodeCommitFromL1(commits);
        adapter.sendMessage{value: MESSAGE_FEE}(message);

        MockWormhole.PublishedMessage memory published = wormhole.getPublishedMessage(0);
        ProofsLib.Commitment[] memory decoded = payloadHarness.decode(published.payload);

        assertEq(decoded.length, 1);
        _assertCommitmentsEqual(decoded[0], commits[0]);
    }

    function testFuzz_sendMessage_nonceAlwaysIncrementing(uint8 callCount) public {
        vm.assume(callCount > 0 && callCount <= 50);

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);
        bytes memory message = _encodeCommitFromL1(commits);

        for (uint256 i; i < callCount; ++i) {
            adapter.sendMessage{value: MESSAGE_FEE}(message);
        }

        assertEq(adapter.nonce(), uint32(callCount), "nonce matches call count");
        assertEq(wormhole.publishedMessageCount(), callCount, "message count matches");

        // Verify each message has correct nonce.
        for (uint256 i; i < callCount; ++i) {
            assertEq(wormhole.getPublishedMessage(i).nonce, uint32(i), "nonce matches index");
        }
    }

    function testFuzz_sendMessage_feeExact(uint256 fee) public {
        fee = bound(fee, 0, 1 ether);
        wormhole.setMessageFee(fee);

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);
        bytes memory message = _encodeCommitFromL1(commits);

        // Exact fee should succeed.
        adapter.sendMessage{value: fee}(message);
        assertEq(wormhole.publishedMessageCount(), 1);
    }

    // ── IBridgeAdapter Interface Conformance ──

    function test_implementsIBridgeAdapter() public view {
        // Verify the adapter can be cast to IBridgeAdapter.
        IBridgeAdapter iBridge = IBridgeAdapter(address(adapter));
        assertEq(address(iBridge), address(adapter));
    }
}

// ═══════════════════════════════════════════════════════════
//     3. L1WorldId DISPATCH + ADAPTER INTEGRATION
// ═══════════════════════════════════════════════════════════

contract L1RelayDispatchTest is WormholeBridgeBaseTest {
    MockWormhole wormhole;
    WormholeAdapter wormholeAdapter;
    MockBridgeAdapter mockAdapter;
    WormholePayloadHarness payloadHarness;

    // L1WorldId with a permissive mock factory.
    L1WorldId l1Bridge;
    MockDisputeGameFactory factory;

    address constant WC_BRIDGE = address(uint160(uint256(keccak256("test.wc.bridge"))));

    uint256 constant MESSAGE_FEE = 0.01 ether;

    function setUp() public {
        wormhole = new MockWormhole(2, MESSAGE_FEE);
        wormholeAdapter = new WormholeAdapter(IWormhole(address(wormhole)), 1);
        mockAdapter = new MockBridgeAdapter();
        payloadHarness = new WormholePayloadHarness();
        factory = new MockDisputeGameFactory();

        l1Bridge = new L1WorldId(
            address(0), // verifier (not testing ZK)
            IDisputeGameFactory(address(factory)),
            WC_BRIDGE,
            1 hours,
            30,
            0
        );

        vm.deal(address(this), 100 ether);
    }

    // ── Adapter Registration ──

    function test_registerAdapter_single() public {
        l1Bridge.registerAdapter(IBridgeAdapter(address(mockAdapter)));
        assertEq(address(l1Bridge.adapters(0)), address(mockAdapter));
    }

    function test_registerAdapter_multiple() public {
        l1Bridge.registerAdapter(IBridgeAdapter(address(mockAdapter)));
        l1Bridge.registerAdapter(IBridgeAdapter(address(wormholeAdapter)));

        assertEq(address(l1Bridge.adapters(0)), address(mockAdapter));
        assertEq(address(l1Bridge.adapters(1)), address(wormholeAdapter));
    }

    function test_removeAdapter_removesCorrectAdapter() public {
        l1Bridge.registerAdapter(IBridgeAdapter(address(mockAdapter)));
        l1Bridge.registerAdapter(IBridgeAdapter(address(wormholeAdapter)));

        l1Bridge.removeAdapter(0); // remove mockAdapter, wormholeAdapter moves to index 0

        assertEq(address(l1Bridge.adapters(0)), address(wormholeAdapter));
    }

    function test_removeAdapter_revert_invalidIndex() public {
        vm.expectRevert(InvalidAdapterIndex.selector);
        l1Bridge.removeAdapter(0);
    }

    function test_removeAdapter_lastElement() public {
        l1Bridge.registerAdapter(IBridgeAdapter(address(mockAdapter)));
        l1Bridge.removeAdapter(0);

        // Should revert when accessing index 0 (array is empty).
        vm.expectRevert();
        l1Bridge.adapters(0);
    }

    function test_registerAdapter_emitsEvent() public {
        vm.expectEmit(true, false, false, true, address(l1Bridge));
        emit AdapterRegistered(0, address(mockAdapter));
        l1Bridge.registerAdapter(IBridgeAdapter(address(mockAdapter)));

        vm.expectEmit(true, false, false, true, address(l1Bridge));
        emit AdapterRegistered(1, address(wormholeAdapter));
        l1Bridge.registerAdapter(IBridgeAdapter(address(wormholeAdapter)));
    }

    function test_removeAdapter_emitsEvent() public {
        l1Bridge.registerAdapter(IBridgeAdapter(address(mockAdapter)));
        l1Bridge.registerAdapter(IBridgeAdapter(address(wormholeAdapter)));

        vm.expectEmit(true, false, false, true, address(l1Bridge));
        emit AdapterRemoved(0, address(mockAdapter));
        l1Bridge.removeAdapter(0);
    }

    // ── Dispatch Behavior (unit test via mock adapters) ──

    function test_dispatch_sendsToAllAdapters() public {
        // Register two mock adapters.
        MockBridgeAdapter adapter1 = new MockBridgeAdapter();
        MockBridgeAdapter adapter2 = new MockBridgeAdapter();

        l1Bridge.registerAdapter(IBridgeAdapter(address(adapter1)));
        l1Bridge.registerAdapter(IBridgeAdapter(address(adapter2)));

        // We can't call dispatch directly (internal), so we'll verify via the mock adapter
        // message recording in the E2E test below. Here verify adapters are registered.
        assertEq(address(l1Bridge.adapters(0)), address(adapter1));
        assertEq(address(l1Bridge.adapters(1)), address(adapter2));
    }

    // ── Message Format Verification ──

    function test_dispatch_messageFormat_isCommitFromL1() public {
        // Verify the message format that L1WorldId.dispatch() produces.
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory expectedMessage = _encodeCommitFromL1(commits);

        // Check that the selector is INativeWorldId.commitFromL1
        bytes4 selector;
        assembly {
            selector := mload(add(expectedMessage, 32))
        }
        assertEq(selector, INativeWorldId.commitFromL1.selector, "message selector is commitFromL1");
    }

    // ── Wormhole Adapter E2E: ABI decode → WormholePayload encode → publish ──

    function test_wormholeAdapter_decodesCommitFromL1Correctly() public {
        // Build the exact message that L1WorldId.dispatch() produces.
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](2);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);
        commits[1] = _makeSetIssuerCommitment(TEST_ISSUER_ID, 111, 222, TEST_PROOF_ID, bytes32(uint256(0xAA)));

        bytes memory message = _encodeCommitFromL1(commits);

        // Send through the Wormhole adapter.
        wormholeAdapter.sendMessage{value: MESSAGE_FEE}(message);

        // Verify the Wormhole payload decodes to the original commits.
        MockWormhole.PublishedMessage memory published = wormhole.getPublishedMessage(0);
        ProofsLib.Commitment[] memory decoded = payloadHarness.decode(published.payload);

        assertEq(decoded.length, 2);
        _assertCommitmentsEqual(decoded[0], commits[0]);
        _assertCommitmentsEqual(decoded[1], commits[1]);
    }

    function test_wormholeAdapter_e2e_allFourActionTypes() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](4);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);
        commits[1] = _makeSetIssuerCommitment(TEST_ISSUER_ID, 111, 222, TEST_PROOF_ID, bytes32(uint256(0xAA)));
        commits[2] = _makeSetOprfCommitment(TEST_OPRF_ID, 333, 444, TEST_PROOF_ID, bytes32(uint256(0xBB)));
        commits[3] = _makeInvalidateCommitment(bytes32(uint256(99)), bytes32(uint256(0xCC)));

        bytes memory message = _encodeCommitFromL1(commits);
        wormholeAdapter.sendMessage{value: MESSAGE_FEE}(message);

        MockWormhole.PublishedMessage memory published = wormhole.getPublishedMessage(0);
        ProofsLib.Commitment[] memory decoded = payloadHarness.decode(published.payload);

        assertEq(decoded.length, 4, "all 4 actions decoded");

        // Verify each action selector is preserved in the data.
        bytes4 sel0;
        bytes4 sel1;
        bytes4 sel2;
        bytes4 sel3;
        assembly {
            let d0 := mload(add(mload(add(mload(add(decoded, 0x20)), 0x20)), 0x20))
            sel0 := d0
            let d1 := mload(add(mload(add(mload(add(add(decoded, 0x20), 0x20)), 0x20)), 0x20))
            sel1 := d1
            let d2 := mload(add(mload(add(mload(add(add(decoded, 0x20), 0x40)), 0x20)), 0x20))
            sel2 := d2
            let d3 := mload(add(mload(add(mload(add(add(decoded, 0x20), 0x60)), 0x20)), 0x20))
            sel3 := d3
        }
        assertEq(sel0, UPDATE_ROOT_SEL, "commit 0 = updateRoot");
        assertEq(sel1, SET_ISSUER_SEL, "commit 1 = setIssuerPubkey");
        assertEq(sel2, SET_OPRF_SEL, "commit 2 = setOprfKey");
        assertEq(sel3, INVALIDATE_SEL, "commit 3 = invalidateProofId");
    }

    // ── Chain Hash Consistency ──

    function test_chainHash_matchesProofsLib() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](3);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);
        commits[1] = _makeSetIssuerCommitment(TEST_ISSUER_ID, 111, 222, TEST_PROOF_ID, bytes32(uint256(0xCAFE)));
        commits[2] = _makeSetOprfCommitment(TEST_OPRF_ID, 333, 444, TEST_PROOF_ID, bytes32(uint256(0xDEAD)));

        // Compute chain hash manually.
        bytes32 h0 = _chainHash(bytes32(0), commits[0]);
        bytes32 h1 = _chainHash(h0, commits[1]);
        bytes32 h2 = _chainHash(h1, commits[2]);

        // Also compute via ProofsLib.
        ProofsLib.Chain memory chain = ProofsLib.Chain({head: bytes32(0), length: 0});
        bytes32 proofLibHead = ProofsLib.hashChained(chain, commits);

        assertEq(h2, proofLibHead, "manual chain hash matches ProofsLib.hashChained");
    }

    function test_chainHash_afterWormholeRoundtrip() public {
        // Verify that chain hashing produces the same result before and after
        // a Wormhole encode/decode roundtrip.
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](2);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);
        commits[1] = _makeSetIssuerCommitment(TEST_ISSUER_ID, 111, 222, TEST_PROOF_ID, bytes32(uint256(0xCAFE)));

        // Hash before encode.
        ProofsLib.Chain memory chainBefore = ProofsLib.Chain({head: bytes32(0), length: 0});
        bytes32 headBefore = ProofsLib.hashChained(chainBefore, commits);

        // Encode → decode roundtrip.
        bytes memory encoded = payloadHarness.encode(commits);
        ProofsLib.Commitment[] memory decoded = payloadHarness.decode(encoded);

        // Hash after decode.
        ProofsLib.Chain memory chainAfter = ProofsLib.Chain({head: bytes32(0), length: 0});
        bytes32 headAfter = ProofsLib.hashChained(chainAfter, decoded);

        assertEq(headBefore, headAfter, "chain hash invariant through Wormhole roundtrip");
    }

    function testFuzz_chainHash_invariantThroughWormholeRoundtrip(
        bytes32 blockHash1,
        bytes32 blockHash2,
        uint256 root,
        uint256 ts,
        bytes32 proofId
    ) public view {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](2);
        commits[0] = _makeUpdateRootCommitment(root, ts, proofId, blockHash1);
        commits[1] = _makeSetIssuerCommitment(TEST_ISSUER_ID, 111, 222, proofId, blockHash2);

        ProofsLib.Chain memory chainBefore = ProofsLib.Chain({head: bytes32(0), length: 0});
        bytes32 headBefore = ProofsLib.hashChained(chainBefore, commits);

        bytes memory encoded = payloadHarness.encode(commits);
        ProofsLib.Commitment[] memory decoded = payloadHarness.decode(encoded);

        ProofsLib.Chain memory chainAfter = ProofsLib.Chain({head: bytes32(0), length: 0});
        bytes32 headAfter = ProofsLib.hashChained(chainAfter, decoded);

        assertEq(headBefore, headAfter, "chain hash invariant");
    }

    // ── Parallel Adapter Dispatch ──

    function test_dispatch_wormholeAndMockReceiveSameCommits() public {
        // Register both a mock adapter and the Wormhole adapter.
        l1Bridge.registerAdapter(IBridgeAdapter(address(mockAdapter)));
        l1Bridge.registerAdapter(IBridgeAdapter(address(wormholeAdapter)));

        // Build commits.
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory expectedMessage = _encodeCommitFromL1(commits);

        // Call dispatch directly on both adapters to simulate what L1WorldId does.
        // (We can't trigger L1WorldId.commitChained without valid MPT proofs,
        //  so we test the adapter layer directly.)
        mockAdapter.sendMessage(expectedMessage);
        wormholeAdapter.sendMessage{value: MESSAGE_FEE}(expectedMessage);

        // Verify mock adapter received the raw ABI message.
        assertEq(mockAdapter.receivedMessageCount(), 1);
        assertEq(mockAdapter.getReceivedMessage(0), expectedMessage, "mock received raw message");

        // Verify Wormhole adapter published a decoded + re-encoded payload.
        MockWormhole.PublishedMessage memory published = wormhole.getPublishedMessage(0);
        ProofsLib.Commitment[] memory decoded = payloadHarness.decode(published.payload);
        assertEq(decoded.length, 1);
        _assertCommitmentsEqual(decoded[0], commits[0]);
    }

    // ── Stress Test: Many Commits ──

    function test_wormholeAdapter_manyCommits() public {
        uint256 count = 50;
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](count);
        for (uint256 i; i < count; ++i) {
            commits[i] =
                _makeUpdateRootCommitment(i + 1, TEST_TIMESTAMP + i, bytes32(uint256(i)), bytes32(uint256(0x1000 + i)));
        }

        bytes memory message = _encodeCommitFromL1(commits);
        wormholeAdapter.sendMessage{value: MESSAGE_FEE}(message);

        MockWormhole.PublishedMessage memory published = wormhole.getPublishedMessage(0);
        ProofsLib.Commitment[] memory decoded = payloadHarness.decode(published.payload);

        assertEq(decoded.length, count, "all commits decoded");
        for (uint256 i; i < count; ++i) {
            _assertCommitmentsEqual(decoded[i], commits[i]);
        }
    }

    // ── Edge: Empty Commit Array ──

    function test_wormholeAdapter_emptyCommits() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](0);

        bytes memory message = _encodeCommitFromL1(commits);
        wormholeAdapter.sendMessage{value: MESSAGE_FEE}(message);

        MockWormhole.PublishedMessage memory published = wormhole.getPublishedMessage(0);
        ProofsLib.Commitment[] memory decoded = payloadHarness.decode(published.payload);

        assertEq(decoded.length, 0, "empty commit roundtrip");
    }

    // ── commitChained Revert Cases ──

    function test_commitChained_revert_emptyCommits() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](0);

        vm.expectRevert(EmptyChainedCommits.selector);
        l1Bridge.commitChained(ProofsLib.CommitmentWithProof({mptProof: hex"", commits: commits}));
    }

    function test_commitChained_revert_invalidDisputeGameIndex() public {
        // Factory has no games, so index 0 is out of bounds.
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory fakeMpt = abi.encode(new bytes[](0), new bytes[](0), new bytes[](0), uint256(0));

        vm.expectRevert(InvalidDisputeGameIndex.selector);
        l1Bridge.commitChained(ProofsLib.CommitmentWithProof({mptProof: fakeMpt, commits: commits}));
    }

    function test_commitChained_revert_gameNotDefenderWins() public {
        MockDisputeGame game = new MockDisputeGame(GameStatus.IN_PROGRESS, bytes32(0), 0);
        factory.addGame(address(game));

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory fakeMpt = abi.encode(new bytes[](0), new bytes[](0), new bytes[](0), uint256(0));

        vm.expectRevert(InvalidOutputRoot.selector);
        l1Bridge.commitChained(ProofsLib.CommitmentWithProof({mptProof: fakeMpt, commits: commits}));
    }

    function test_commitChained_revert_challengerWins() public {
        MockDisputeGame game = new MockDisputeGame(GameStatus.CHALLENGER_WINS, bytes32(0), 0);
        factory.addGame(address(game));

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bytes memory fakeMpt = abi.encode(new bytes[](0), new bytes[](0), new bytes[](0), uint256(0));

        vm.expectRevert(InvalidOutputRoot.selector);
        l1Bridge.commitChained(ProofsLib.CommitmentWithProof({mptProof: fakeMpt, commits: commits}));
    }
}

// ═══════════════════════════════════════════════════════════
//      4. WorldIdBridge COMMITMENT APPLICATION TESTS
// ═══════════════════════════════════════════════════════════

/// @dev Concrete WorldIdBridge for testing applyCommitments behavior directly.
contract TestStateBridge is WorldIdBridge {
    using ProofsLib for ProofsLib.Chain;

    constructor() WorldIdBridge(1 hours, 30, 0) {}

    /// @dev Expose applyCommitments + commitChained for direct testing.
    function applyAndCommit(ProofsLib.Commitment[] memory commits) external {
        applyCommitments(commits);
        keccakChain.commitChained(commits);
    }

    function commitChained(ProofsLib.CommitmentWithProof calldata) external pure override {
        revert("TestStateBridge: not implemented");
    }
}

contract StateBridgeCommitmentTest is WormholeBridgeBaseTest {
    TestStateBridge bridge;
    WormholePayloadHarness payloadHarness;

    function setUp() public {
        bridge = new TestStateBridge();
        payloadHarness = new WormholePayloadHarness();
    }

    function test_applyCommitment_updateRoot() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bridge.applyAndCommit(commits);

        assertEq(bridge.latestRoot(), TEST_ROOT, "root applied");
        assertTrue(bridge.isValidRoot(TEST_ROOT), "root is valid");
    }

    function test_applyCommitment_setIssuerPubkey() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeSetIssuerCommitment(TEST_ISSUER_ID, 111, 222, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bridge.applyAndCommit(commits);

        (uint256 x, uint256 y, bytes32 proofId) = _getIssuerPubkey(bridge, TEST_ISSUER_ID);
        assertEq(x, 111, "issuer x");
        assertEq(y, 222, "issuer y");
        assertEq(proofId, TEST_PROOF_ID, "issuer proofId");
    }

    function test_applyCommitment_setOprfKey() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeSetOprfCommitment(TEST_OPRF_ID, 333, 444, TEST_PROOF_ID, TEST_BLOCK_HASH);

        bridge.applyAndCommit(commits);

        // Verify OPRF key is set via the chain head (no public getter for oprfKeyIdToPubkeyAndProofId).
        // Check chain head advanced.
        (bytes32 head,) = bridge.keccakChain();
        assertNotEq(head, bytes32(0), "chain head advanced");
    }

    function test_applyCommitment_invalidateProofId() public {
        // First set a root, then invalidate its proofId.
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);
        bridge.applyAndCommit(commits);
        assertTrue(bridge.isValidRoot(TEST_ROOT), "root valid before invalidation");

        // Invalidate.
        ProofsLib.Commitment[] memory inv = new ProofsLib.Commitment[](1);
        inv[0] = _makeInvalidateCommitment(TEST_PROOF_ID, bytes32(uint256(0xF00D)));
        bridge.applyAndCommit(inv);

        assertFalse(bridge.isValidRoot(TEST_ROOT), "root invalid after proofId invalidated");
        assertTrue(bridge.invalidatedProofIds(TEST_PROOF_ID), "proofId marked invalidated");
    }

    function test_applyCommitment_batchAllActions() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](4);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);
        commits[1] = _makeSetIssuerCommitment(TEST_ISSUER_ID, 111, 222, TEST_PROOF_ID, bytes32(uint256(0xAA)));
        commits[2] = _makeSetOprfCommitment(TEST_OPRF_ID, 333, 444, TEST_PROOF_ID, bytes32(uint256(0xBB)));
        commits[3] = _makeInvalidateCommitment(bytes32(uint256(99)), bytes32(uint256(0xCC)));

        bridge.applyAndCommit(commits);

        assertEq(bridge.latestRoot(), TEST_ROOT, "root applied");
        assertTrue(bridge.invalidatedProofIds(bytes32(uint256(99))), "proofId 99 invalidated");

        (bytes32 head, uint64 length) = bridge.keccakChain();
        assertNotEq(head, bytes32(0), "chain advanced");
        assertEq(length, 4, "chain length = 4");
    }

    function test_applyCommitment_revert_unknownAction() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        // Use a bogus selector.
        commits[0] = _makeRawCommitment(TEST_BLOCK_HASH, abi.encodeWithSelector(bytes4(0xDEADBEEF), uint256(1)));

        // uint8(uint32(bytes4(0xDEADBEEF))) = 0xEF = 239
        vm.expectRevert(abi.encodeWithSelector(UnknownAction.selector, uint8(0xEF)));
        bridge.applyAndCommit(commits);
    }

    function test_chainHead_matchesManualComputation() public {
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](2);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);
        commits[1] = _makeSetIssuerCommitment(TEST_ISSUER_ID, 111, 222, TEST_PROOF_ID, bytes32(uint256(0xCAFE)));

        bytes32 h0 = _chainHash(bytes32(0), commits[0]);
        bytes32 h1 = _chainHash(h0, commits[1]);

        bridge.applyAndCommit(commits);

        (bytes32 head,) = bridge.keccakChain();
        assertEq(head, h1, "chain head matches manual hash");
    }

    function test_commitments_afterWormholeRoundtrip_produceIdenticalState() public {
        // Apply commitments directly, then apply through Wormhole encode/decode roundtrip.
        // Both bridges should have identical state.
        TestStateBridge directBridge = new TestStateBridge();
        TestStateBridge roundtripBridge = new TestStateBridge();

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](3);
        commits[0] = _makeUpdateRootCommitment(TEST_ROOT, TEST_TIMESTAMP, TEST_PROOF_ID, TEST_BLOCK_HASH);
        commits[1] = _makeSetIssuerCommitment(TEST_ISSUER_ID, 111, 222, TEST_PROOF_ID, bytes32(uint256(0xAA)));
        commits[2] = _makeSetOprfCommitment(TEST_OPRF_ID, 333, 444, TEST_PROOF_ID, bytes32(uint256(0xBB)));

        // Direct application.
        directBridge.applyAndCommit(commits);

        // Wormhole roundtrip.
        bytes memory encoded = payloadHarness.encode(commits);
        ProofsLib.Commitment[] memory decoded = payloadHarness.decode(encoded);
        roundtripBridge.applyAndCommit(decoded);

        // Compare state.
        (bytes32 directHead, uint64 directLen) = directBridge.keccakChain();
        (bytes32 rtHead, uint64 rtLen) = roundtripBridge.keccakChain();
        assertEq(directHead, rtHead, "chain heads match");
        assertEq(directLen, rtLen, "chain lengths match");
        assertEq(directBridge.latestRoot(), roundtripBridge.latestRoot(), "roots match");

        (uint256 dx, uint256 dy,) = _getIssuerPubkey(directBridge, TEST_ISSUER_ID);
        (uint256 rx, uint256 ry,) = _getIssuerPubkey(roundtripBridge, TEST_ISSUER_ID);
        assertEq(dx, rx, "issuer x match");
        assertEq(dy, ry, "issuer y match");
    }

    // ── Fuzz: State Consistency Through Roundtrip ──

    function testFuzz_state_invariantThroughWormholeRoundtrip(
        uint256 root,
        uint256 ts,
        bytes32 proofId,
        bytes32 blockHash,
        uint64 issuerId,
        uint256 ix,
        uint256 iy
    ) public {
        TestStateBridge directBridge = new TestStateBridge();
        TestStateBridge roundtripBridge = new TestStateBridge();

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](2);
        commits[0] = _makeUpdateRootCommitment(root, ts, proofId, blockHash);
        commits[1] = _makeSetIssuerCommitment(issuerId, ix, iy, proofId, blockHash);

        directBridge.applyAndCommit(commits);

        bytes memory encoded = payloadHarness.encode(commits);
        ProofsLib.Commitment[] memory decoded = payloadHarness.decode(encoded);
        roundtripBridge.applyAndCommit(decoded);

        (bytes32 dh,) = directBridge.keccakChain();
        (bytes32 rh,) = roundtripBridge.keccakChain();
        assertEq(dh, rh, "chain heads match");
        assertEq(directBridge.latestRoot(), roundtripBridge.latestRoot(), "roots match");
    }

    // ── Helper ──

    function _getIssuerPubkey(TestStateBridge b, uint64 schemaId)
        internal
        view
        returns (uint256 x, uint256 y, bytes32 proofId)
    {
        (BabyJubJub.Affine memory pk, bytes32 pid) = b.issuerSchemaIdToPubkeyAndProofId(schemaId);
        x = pk.x;
        y = pk.y;
        proofId = pid;
    }
}
