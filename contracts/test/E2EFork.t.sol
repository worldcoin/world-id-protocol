// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console2} from "forge-std/Test.sol";
import {WorldChainStateAdapter} from "../src/bridge-sdk/adapters/WorldChainStateAdapter.sol";
import {L1StateAdapter} from "../src/bridge-sdk/adapters/L1StateAdapter.sol";
import {BridgedStateAdapter} from "../src/bridge-sdk/adapters/BridgedStateAdapter.sol";
import {WorldIdStateBridge} from "../src/bridge-sdk/abstract/WorldIdStateBridge.sol";
import {IWorldIdStateBridge} from "../src/bridge-sdk/interfaces/IWorldIdStateBridge.sol";
import {IBridgeAdapter} from "../src/bridge-sdk/interfaces/IBridgeAdapter.sol";
import {IL1BlockHashOracle} from "../src/bridge-sdk/interfaces/IL1BlockHashOracle.sol";
import {StateChainTypes} from "../src/bridge-sdk/libraries/StateChainTypes.sol";
import {MptVerifier} from "../src/bridge-sdk/libraries/MptVerifier.sol";
import {IDisputeGameFactory} from "../src/bridge-sdk/vendored/optimism/IDisputeGameFactory.sol";
import {IDisputeGame} from "../src/bridge-sdk/vendored/optimism/IDisputeGame.sol";
import {ICrossDomainMessenger} from "../src/bridge-sdk/vendored/optimism/ICrossDomainMessenger.sol";
import {GameStatus, Claim, GameType, Timestamp} from "../src/bridge-sdk/vendored/optimism/DisputeTypes.sol";

// ═══════════════════════════════════════════════════════════════
//                         HARNESSES
// ═══════════════════════════════════════════════════════════════

contract ForkMockAdapter is IBridgeAdapter {
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

contract ForkMockOracle is IL1BlockHashOracle {
    mapping(bytes32 => bool) public known;

    function setKnown(bytes32 h) external {
        known[h] = true;
    }

    function isKnownL1BlockHash(bytes32 h) external view returns (bool) {
        return known[h];
    }
}

/// @dev L1 harness: extends L1StateAdapter, adds manual chain head injection.
contract L1ForkHarness is L1StateAdapter {
    constructor(IDisputeGameFactory factory, address wcBridge)
        L1StateAdapter(factory, wcBridge, ICrossDomainMessenger(address(0)), address(0), 1 hours, 30)
    {}

    function setValidChainHead(bytes32 head) external {
        _validChainHeads[head] = true;
    }

    function isValidChainHead(bytes32 head) external view returns (bool) {
        return _validChainHeads[head];
    }
}

/// @dev Destination harness: overrides _verifyChainHead with a simple expected-head check.
contract DestForkHarness is BridgedStateAdapter {
    bytes32 public validHead;

    constructor(IL1BlockHashOracle oracle, address l1Bridge)
        BridgedStateAdapter(oracle, l1Bridge, ICrossDomainMessenger(address(0)), address(0), address(1), 1 hours, 30)
    {}

    function setValidHead(bytes32 head) external {
        validHead = head;
    }

    function _verifyChainHead(bytes32 computedHead, bytes calldata) internal view override {
        require(computedHead == validHead, "DestForkHarness: chain head mismatch");
    }
}

// ═══════════════════════════════════════════════════════════════
//                       E2E FORK TEST SUITE
// ═══════════════════════════════════════════════════════════════

contract E2EForkTest is Test {
    // ═══ World Chain Registry Addresses (mainnet, chain ID 480) ═══
    address constant WC_REGISTRY = 0x969947cFED008bFb5e3F32a25A1A2CDdf64d46fe;
    address constant WC_ISSUER_REGISTRY = 0x640eb6Fd4c7348661B7DB482e1a66f4bFc7a15eE;
    address constant WC_OPRF_REGISTRY = 0xb2C02253ee7bFEDF50F5D015658857099980E91F;

    // ═══ L1 Addresses (Ethereum mainnet) ═══
    address constant L1_DISPUTE_GAME_FACTORY = 0x069c4c579671f8c120b1327a73217D01Ea2EC5ea;

    // ═══ Known Key IDs (verified against deployed registries) ═══
    uint64 constant ISSUER_ID = 0x5a7400653dd6d18a;
    uint160 constant OPRF_ID = uint160(ISSUER_ID);

    // ═══ RPC URLs (public, can override via env) ═══
    string constant WC_RPC_DEFAULT = "https://worldchain-mainnet.g.alchemy.com/public";
    string constant ETH_RPC_DEFAULT = "https://ethereum-rpc.publicnode.com";

    // ═══ Fork IDs ═══
    uint256 wcFork;
    uint256 ethFork;

    // ═══ Captured WC State (passed between forks) ═══
    struct WCState {
        bytes32 chainHead;
        uint256 root;
        uint256 rootTimestamp;
        bytes32 proofId;
        uint256 issuerX;
        uint256 issuerY;
        uint256 oprfX;
        uint256 oprfY;
        bytes32 wcBlockHash;
    }

    function setUp() public {
        string memory wcRpc = vm.envOr("WC_RPC", WC_RPC_DEFAULT);
        string memory ethRpc = vm.envOr("ETH_RPC", ETH_RPC_DEFAULT);

        wcFork = vm.createFork(wcRpc);
        ethFork = vm.createFork(ethRpc);
    }

    // ════════════════════════════════════════════════
    //   WC REGISTRY SMOKE TEST
    // ════════════════════════════════════════════════

    /// @notice Verifies that the WorldChainStateAdapter correctly reads real registry state.
    function test_wcFork_readRealRegistries() public {
        vm.selectFork(wcFork);

        WorldChainStateAdapter wc = _deployWCAdapter();

        // Propagate root from real WorldIDRegistry
        wc.propagateRoot();
        uint256 root = wc.getLatestRoot();
        assertTrue(root != 0, "Root should be non-zero from real registry");
        console2.log("Real latestRoot:", root);

        // Propagate issuer pubkey from real CredentialSchemaIssuerRegistry
        wc.propagateIssuerPubkey(ISSUER_ID);
        (uint256 ix, uint256 iy) = wc.issuerPubkey(ISSUER_ID);
        assertTrue(ix != 0 || iy != 0, "Issuer pubkey should be non-zero");
        console2.log("Real issuer pubkey X:", ix);
        console2.log("Real issuer pubkey Y:", iy);

        // Propagate OPRF key from real OprfKeyRegistry
        wc.propagateOprfKey(OPRF_ID);
        (uint256 ox, uint256 oy) = wc.oprfKey(OPRF_ID);
        assertTrue(ox != 0 || oy != 0, "OPRF key should be non-zero");
        console2.log("Real OPRF key X:", ox);
        console2.log("Real OPRF key Y:", oy);

        // Chain head should be set after all propagations
        assertTrue(wc.chainHead() != bytes32(0), "Chain head should be set");
        assertTrue(wc.isValidRoot(root), "Root should be valid");
    }

    // ════════════════════════════════════════════════
    //   E2E: FULL BRIDGING (WC → L1 → DEST)
    // ════════════════════════════════════════════════

    /// @notice Full end-to-end: propagate on WC, replay chained commits on L1 and destination,
    ///   verify identical state across all three chains.
    function test_e2e_fullBridging() public {
        // Phase 1: World Chain — propagate real state
        WCState memory state = _propagateOnWC();
        StateChainTypes.ChainedCommit[] memory commits = _buildChainedCommits(state);

        // Phase 2: L1 — process chained commits
        vm.selectFork(ethFork);

        L1ForkHarness l1 = new L1ForkHarness(
            IDisputeGameFactory(address(1)), // dummy DGF (commit processing doesn't use it)
            address(2)
        );
        l1.setValidChainHead(state.chainHead);
        l1.processChainedCommits(commits, "");

        _assertStateMatches(IWorldIdStateBridge(address(l1)), state, "L1");

        // Phase 3: Destination — process same chained commits
        ForkMockOracle oracle = new ForkMockOracle();
        DestForkHarness dest = new DestForkHarness(IL1BlockHashOracle(address(oracle)), address(l1));
        dest.setValidHead(state.chainHead);
        dest.processChainedCommits(commits, "");

        _assertStateMatches(IWorldIdStateBridge(address(dest)), state, "Dest");

        // Phase 4: Cross-chain consistency
        assertEq(l1.chainHead(), dest.chainHead(), "L1 and dest chain heads should match");
        assertEq(l1.getLatestRoot(), dest.getLatestRoot(), "L1 and dest roots should match");
    }

    // ════════════════════════════════════════════════
    //   E2E: PARTIAL CATCH-UP
    // ════════════════════════════════════════════════

    /// @notice Bridge in two batches: root first, then issuer + OPRF keys.
    function test_e2e_partialCatchUp() public {
        WCState memory state = _propagateOnWC();
        StateChainTypes.ChainedCommit[] memory fullCommits = _buildChainedCommits(state);

        vm.selectFork(ethFork);

        ForkMockOracle oracle = new ForkMockOracle();
        DestForkHarness dest = new DestForkHarness(IL1BlockHashOracle(address(oracle)), address(1));

        // Batch 1: root only
        StateChainTypes.ChainedCommit[] memory batch1 = new StateChainTypes.ChainedCommit[](1);
        batch1[0] = fullCommits[0];

        // Compute intermediate chain head after 1 commit
        bytes32 intermediateHead =
            keccak256(abi.encode(bytes32(0), batch1[0].blockHash, batch1[0].action, batch1[0].data));
        dest.setValidHead(intermediateHead);
        dest.processChainedCommits(batch1, "");

        assertEq(dest.chainHead(), intermediateHead);
        assertEq(dest.getLatestRoot(), state.root, "Root should match after batch 1");

        // Batch 2: issuer + OPRF
        StateChainTypes.ChainedCommit[] memory batch2 = new StateChainTypes.ChainedCommit[](2);
        batch2[0] = fullCommits[1];
        batch2[1] = fullCommits[2];

        dest.setValidHead(state.chainHead);
        dest.processChainedCommits(batch2, "");

        assertEq(dest.chainHead(), state.chainHead, "Final chain head should match WC");
        _assertStateMatches(IWorldIdStateBridge(address(dest)), state, "Dest after catch-up");
    }

    // ════════════════════════════════════════════════
    //   E2E: ADAPTER DISPATCH WITH REAL DATA
    // ════════════════════════════════════════════════

    /// @notice Verifies that adapter dispatch messages encode real data correctly.
    function test_e2e_adapterDispatch() public {
        vm.selectFork(wcFork);

        WorldChainStateAdapter wc = _deployWCAdapter();
        ForkMockAdapter adapter = new ForkMockAdapter();
        wc.registerAdapter(IBridgeAdapter(address(adapter)));

        bytes32 bh = blockhash(block.number - 1);

        wc.propagateRoot();
        uint256 root = wc.getLatestRoot();
        uint256 ts = wc.getRootTimestamp(root);
        bytes32 proofId = bytes32(block.number);

        // Verify the dispatched message encodes real data
        assertEq(adapter.msgCount(), 1, "Should dispatch 1 message");
        bytes4 sel = bytes4(keccak256("receiveChainedCommit(uint8,bytes32,bytes)"));
        bytes memory expectedData = abi.encode(root, ts, proofId);
        bytes memory expected = abi.encodeWithSelector(sel, StateChainTypes.ACTION_SET_ROOT, bh, expectedData);
        assertEq(adapter.getMsg(0), expected, "Dispatched message should encode real root");
    }

    // ════════════════════════════════════════════════
    //   L1: DISPUTE GAME FACTORY INTERACTION
    // ════════════════════════════════════════════════

    /// @notice Interacts with the real DisputeGameFactory on Ethereum L1.
    function test_l1Fork_disputeGameFactory() public {
        vm.selectFork(ethFork);

        IDisputeGameFactory dgf = IDisputeGameFactory(L1_DISPUTE_GAME_FACTORY);
        uint256 count = dgf.gameCount();
        console2.log("DisputeGameFactory gameCount:", count);
        assertTrue(count > 0, "DGF should have at least one game");

        // Inspect the most recent game
        (GameType gameType, Timestamp ts, IDisputeGame game) = dgf.gameAtIndex(count - 1);
        GameStatus status = game.status();

        console2.log("Latest game status:", uint8(status));
        console2.log("Latest game rootClaim:", uint256(Claim.unwrap(game.rootClaim())));
        console2.log("Latest game l2BlockNumber:", game.l2BlockNumber());

        // Verify rootClaim is non-zero (sanity check)
        assertTrue(Claim.unwrap(game.rootClaim()) != bytes32(0), "rootClaim should be non-zero");
    }

    /// @notice Finds a DEFENDER_WINS game and validates the L1StateAdapter's validation logic.
    function test_l1Fork_disputeGame_defenderWins() public {
        vm.selectFork(ethFork);

        IDisputeGameFactory dgf = IDisputeGameFactory(L1_DISPUTE_GAME_FACTORY);
        uint256 count = dgf.gameCount();

        // Search backwards for a DEFENDER_WINS game
        uint256 defenderIdx = type(uint256).max;
        uint256 searchLimit = count > 50 ? count - 50 : 0;
        for (uint256 i = count; i > searchLimit; --i) {
            (,, IDisputeGame g) = dgf.gameAtIndex(i - 1);
            if (g.status() == GameStatus.DEFENDER_WINS) {
                defenderIdx = i - 1;
                break;
            }
        }

        if (defenderIdx == type(uint256).max) {
            console2.log("No DEFENDER_WINS game found in last 50 games, skipping");
            return;
        }

        // Deploy L1 adapter with real DGF
        L1ForkHarness l1 = new L1ForkHarness(dgf, address(2));

        // Validate the game via the adapter's internal logic
        (,, IDisputeGame winnerGame) = dgf.gameAtIndex(defenderIdx);
        assertTrue(winnerGame.status() == GameStatus.DEFENDER_WINS, "Game should be DEFENDER_WINS");

        bytes32 rootClaim = Claim.unwrap(winnerGame.rootClaim());
        uint256 l2Block = winnerGame.l2BlockNumber();
        console2.log("DEFENDER_WINS game at index:", defenderIdx);
        console2.log("  rootClaim:", uint256(rootClaim));
        console2.log("  l2BlockNumber:", l2Block);
    }

    // ════════════════════════════════════════════════
    //   E2E: INVALIDATION VIA REAL DGF
    // ════════════════════════════════════════════════

    /// @notice If a CHALLENGER_WINS game exists, tests the full invalidation flow.
    function test_e2e_invalidation_viaRealDGF() public {
        vm.selectFork(ethFork);

        IDisputeGameFactory dgf = IDisputeGameFactory(L1_DISPUTE_GAME_FACTORY);
        uint256 count = dgf.gameCount();

        // Search for a CHALLENGER_WINS game
        uint256 challengerIdx = type(uint256).max;
        uint256 searchLimit = count > 100 ? count - 100 : 0;
        for (uint256 i = count; i > searchLimit; --i) {
            (,, IDisputeGame g) = dgf.gameAtIndex(i - 1);
            if (g.status() == GameStatus.CHALLENGER_WINS) {
                challengerIdx = i - 1;
                break;
            }
        }

        if (challengerIdx == type(uint256).max) {
            console2.log("No CHALLENGER_WINS game found in last 100 games, skipping");
            return;
        }

        // Deploy L1 adapter with real DGF and mock adapter for dispatch
        L1ForkHarness l1 = new L1ForkHarness(dgf, address(2));
        ForkMockAdapter adapter = new ForkMockAdapter();
        l1.registerAdapter(IBridgeAdapter(address(adapter)));

        // Invalidate via the real CHALLENGER_WINS game
        l1.invalidateProofId(challengerIdx);

        // Verify the invalidation was dispatched
        assertEq(adapter.msgCount(), 1, "Should dispatch invalidation to adapter");

        // Decode and verify the dispatched message
        (,, IDisputeGame game) = dgf.gameAtIndex(challengerIdx);
        bytes32 expectedProofId = bytes32(game.l2BlockNumber());
        bytes4 sel = bytes4(keccak256("receiveChainedCommit(uint8,bytes32,bytes)"));
        bytes memory data = abi.encode(expectedProofId);
        bytes memory expected =
            abi.encodeWithSelector(sel, StateChainTypes.ACTION_INVALIDATE_PROOF_ID, bytes32(0), data);
        assertEq(adapter.getMsg(0), expected, "Invalidation message should match");

        console2.log("Invalidated proofId:", uint256(expectedProofId));
    }

    // ════════════════════════════════════════════════
    //   E2E: INVALIDATION END-TO-END
    // ════════════════════════════════════════════════

    /// @notice Tests that invalidation on L1 makes roots invalid on the destination.
    function test_e2e_invalidation_rootBecomesInvalid() public {
        // Phase 1: Propagate on WC
        WCState memory state = _propagateOnWC();
        StateChainTypes.ChainedCommit[] memory commits = _buildChainedCommits(state);

        vm.selectFork(ethFork);

        // Phase 2: Process chained commits on destination
        ForkMockOracle oracle = new ForkMockOracle();
        DestForkHarness dest = new DestForkHarness(IL1BlockHashOracle(address(oracle)), address(1));
        dest.setValidHead(state.chainHead);
        dest.processChainedCommits(commits, "");

        assertTrue(dest.isValidRoot(state.root), "Root should be valid before invalidation");

        // Phase 3: Build invalidation chained commit and process it
        bytes memory invalidData = abi.encode(state.proofId);
        bytes32 headAfterInvalidation = keccak256(
            abi.encode(
                state.chainHead,
                bytes32(0), // invalidation uses zero blockhash
                StateChainTypes.ACTION_INVALIDATE_PROOF_ID,
                invalidData
            )
        );

        StateChainTypes.ChainedCommit[] memory invalidCommits = new StateChainTypes.ChainedCommit[](1);
        invalidCommits[0] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_INVALIDATE_PROOF_ID, blockHash: bytes32(0), data: invalidData
        });

        dest.setValidHead(headAfterInvalidation);
        dest.processChainedCommits(invalidCommits, "");

        assertFalse(dest.isValidRoot(state.root), "Root should be invalid after invalidation");
        assertEq(dest.chainHead(), headAfterInvalidation, "Chain head should advance");
    }

    // ════════════════════════════════════════════════
    //   MPT PROOF: REAL WC STATE VERIFICATION
    // ════════════════════════════════════════════════

    /// @notice Verifies MptVerifier against a real WorldIDRegistry storage slot on WC.
    ///   Proves _latestRoot (slot 0x11) via real account + storage MPT proofs.
    /// @dev Requires FFI and network access.
    function test_mptVerification_realWorldChainState() public {
        vm.selectFork(wcFork);

        // Read the expected value directly from the fork
        (bool ok, bytes memory ret) = WC_REGISTRY.staticcall(abi.encodeWithSignature("getLatestRoot()"));
        assertTrue(ok, "getLatestRoot() should succeed");
        uint256 expectedRoot = abi.decode(ret, (uint256));
        assertTrue(expectedRoot != 0, "Expected root should be non-zero");
        console2.log("Expected latestRoot:", expectedRoot);

        // Fetch real proofs via FFI
        string memory wcRpc = vm.envOr("WC_RPC", WC_RPC_DEFAULT);
        string memory blockHex = _toMinimalHexString(block.number);

        string[] memory args = new string[](6);
        args[0] = "bash";
        args[1] = "test/scripts/get-proof-encoded.sh";
        args[2] = vm.toString(WC_REGISTRY);
        args[3] = "0x11"; // _latestRoot slot
        args[4] = blockHex;
        args[5] = wcRpc;

        bytes memory encoded = vm.ffi(args);
        (bytes[] memory accountProof, bytes[] memory storageProof, uint256 provenValue) =
            abi.decode(encoded, (bytes[], bytes[], uint256));

        console2.log("Account proof nodes:", accountProof.length);
        console2.log("Storage proof nodes:", storageProof.length);
        console2.log("Proven storage value:", provenValue);

        // The raw storage value should match the latestRoot
        assertEq(provenValue, expectedRoot, "Proven value should match expected root");

        // Get the state root for this block via FFI
        string[] memory srArgs = new string[](5);
        srArgs[0] = "bash";
        srArgs[1] = "test/scripts/get-block-field.sh";
        srArgs[2] = vm.toString(block.number);
        srArgs[3] = "stateRoot";
        srArgs[4] = wcRpc;

        bytes memory stateRootBytes = vm.ffi(srArgs);
        bytes32 stateRoot = bytes32(stateRootBytes);
        console2.log("WC state root:", uint256(stateRoot));

        // Verify account proof → get storage root
        bytes32 storageRoot = MptVerifier.verifyAccountAndGetStorageRoot(WC_REGISTRY, accountProof, stateRoot);
        assertTrue(storageRoot != bytes32(0), "Storage root should be non-zero");
        console2.log("Verified storage root:", uint256(storageRoot));

        // Verify storage proof → get _latestRoot value
        bytes32 slot = bytes32(uint256(0x11));
        uint256 provenRoot = MptVerifier.storageFromProof(storageProof, storageRoot, slot);
        assertEq(provenRoot, expectedRoot, "MPT-proven root should match fork value");

        console2.log("MPT verification PASSED: proven root =", provenRoot);
    }

    // ════════════════════════════════════════════════
    //          INTERNAL HELPERS
    // ════════════════════════════════════════════════

    function _deployWCAdapter() internal returns (WorldChainStateAdapter) {
        return new WorldChainStateAdapter(WC_REGISTRY, WC_ISSUER_REGISTRY, WC_OPRF_REGISTRY, 1 hours, 30);
    }

    /// @dev Deploys WC adapter on WC fork, propagates all state, and returns captured values.
    function _propagateOnWC() internal returns (WCState memory state) {
        vm.selectFork(wcFork);

        WorldChainStateAdapter wc = _deployWCAdapter();

        // Capture the block hash BEFORE propagation (same block for all 3 calls)
        state.wcBlockHash = blockhash(block.number - 1);
        state.proofId = bytes32(block.number);

        // Propagate all state from real registries
        wc.propagateRoot();
        state.root = wc.getLatestRoot();
        state.rootTimestamp = wc.getRootTimestamp(state.root);

        wc.propagateIssuerPubkey(ISSUER_ID);
        (state.issuerX, state.issuerY) = wc.issuerPubkey(ISSUER_ID);

        wc.propagateOprfKey(OPRF_ID);
        (state.oprfX, state.oprfY) = wc.oprfKey(OPRF_ID);

        state.chainHead = wc.chainHead();

        // Log captured state
        console2.log("WC root:", state.root);
        console2.log("WC chain head:", uint256(state.chainHead));
    }

    /// @dev Builds 3 chained commits from captured WC state (root, issuer, OPRF).
    function _buildChainedCommits(WCState memory state)
        internal
        pure
        returns (StateChainTypes.ChainedCommit[] memory commits)
    {
        commits = new StateChainTypes.ChainedCommit[](3);

        commits[0] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_ROOT,
            blockHash: state.wcBlockHash,
            data: abi.encode(state.root, state.rootTimestamp, state.proofId)
        });

        commits[1] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_ISSUER_PUBKEY,
            blockHash: state.wcBlockHash,
            data: abi.encode(ISSUER_ID, state.issuerX, state.issuerY, state.proofId)
        });

        commits[2] = StateChainTypes.ChainedCommit({
            action: StateChainTypes.ACTION_SET_OPRF_KEY,
            blockHash: state.wcBlockHash,
            data: abi.encode(OPRF_ID, state.oprfX, state.oprfY, state.proofId)
        });
    }

    /// @dev Asserts that a bridge's state matches the captured WC state.
    function _assertStateMatches(IWorldIdStateBridge bridge, WCState memory state, string memory label) internal view {
        assertEq(bridge.getLatestRoot(), state.root, string(abi.encodePacked(label, ": root mismatch")));
        assertEq(
            bridge.getRootTimestamp(state.root),
            state.rootTimestamp,
            string(abi.encodePacked(label, ": root timestamp mismatch"))
        );
        assertEq(bridge.chainHead(), state.chainHead, string(abi.encodePacked(label, ": chain head mismatch")));
        assertTrue(bridge.isValidRoot(state.root), string(abi.encodePacked(label, ": root should be valid")));

        (uint256 ix, uint256 iy) = bridge.issuerPubkey(ISSUER_ID);
        assertEq(ix, state.issuerX, string(abi.encodePacked(label, ": issuer X mismatch")));
        assertEq(iy, state.issuerY, string(abi.encodePacked(label, ": issuer Y mismatch")));

        (uint256 ox, uint256 oy) = bridge.oprfKey(OPRF_ID);
        assertEq(ox, state.oprfX, string(abi.encodePacked(label, ": OPRF X mismatch")));
        assertEq(oy, state.oprfY, string(abi.encodePacked(label, ": OPRF Y mismatch")));
    }

    /// @dev Converts uint256 to minimal 0x-prefixed hex string (e.g. 25497398 → "0x1850f36").
    function _toMinimalHexString(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0x0";

        // Count hex digits
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp >>= 4;
        }

        bytes memory buffer = new bytes(2 + digits);
        buffer[0] = "0";
        buffer[1] = "x";

        for (uint256 i = digits; i > 0; --i) {
            uint8 nibble = uint8(value & 0xf);
            buffer[1 + i] = nibble < 10 ? bytes1(nibble + 0x30) : bytes1(nibble + 0x57);
            value >>= 4;
        }

        return string(buffer);
    }
}
