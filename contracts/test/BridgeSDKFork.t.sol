// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console2} from "forge-std/Test.sol";
import {WorldChainStateAdapter, IOprfKeyRegistry} from "../src/bridge-sdk/adapters/WorldChainStateAdapter.sol";
import {L1StateAdapter} from "../src/bridge-sdk/adapters/L1StateAdapter.sol";
import {OpStackBridgeAdapter} from "../src/bridge-sdk/adapters/op/OpStackBridgeAdapter.sol";
import {WorldIdStateBridge} from "../src/bridge-sdk/abstract/WorldIdStateBridge.sol";
import {IWorldIdStateBridge} from "../src/bridge-sdk/interfaces/IWorldIdStateBridge.sol";
import {IBridgeAdapter} from "../src/bridge-sdk/interfaces/IBridgeAdapter.sol";
import {IL1Block} from "../src/bridge-sdk/vendored/optimism/IL1Block.sol";
import {MptVerifier} from "../src/bridge-sdk/libraries/MptVerifier.sol";
import {IDisputeGameFactory} from "../src/bridge-sdk/vendored/optimism/IDisputeGameFactory.sol";
import {IDisputeGame} from "../src/bridge-sdk/vendored/optimism/IDisputeGame.sol";
import {ICrossDomainMessenger} from "../src/bridge-sdk/vendored/optimism/ICrossDomainMessenger.sol";
import {GameStatus, Claim, GameType, Timestamp} from "../src/bridge-sdk/vendored/optimism/DisputeTypes.sol";
import {BabyJubJub} from "lib/oprf-key-registry/src/BabyJubJub.sol";

// ═══════════════════════════════════════════════════════════════
//                      MINIMAL HARNESS
// ═══════════════════════════════════════════════════════════════

/// @dev Exposes internal OPRF key mapping for assertions.
contract WCHarness is WorldChainStateAdapter {
    constructor(address registry, address issuerRegistry, address oprfRegistry, address l1BlockOracle)
        WorldChainStateAdapter(registry, issuerRegistry, oprfRegistry, 1 hours, 30, 0, address(1), l1BlockOracle)
    {}

    function getOprfKey(uint160 oprfKeyId) external view returns (uint256 x, uint256 y, bytes32 proofId) {
        ProvenPubKeyInfo memory info = _oprfKeyIdToPubkeyAndProofId[oprfKeyId];
        return (info.pubKey.x, info.pubKey.y, info.proofId);
    }
}

// ═══════════════════════════════════════════════════════════════
//                  WORLD CHAIN FORK TESTS
// ═══════════════════════════════════════════════════════════════

/// @notice Tests WorldChainStateAdapter against real WC mainnet registries.
contract WorldChainForkTest is Test {
    // ═══ World Chain Mainnet Addresses ═══
    address constant WC_REGISTRY = 0x969947cFED008bFb5e3F32a25A1A2CDdf64d46fe;
    address constant WC_ISSUER_REGISTRY = 0x640eb6Fd4c7348661B7DB482e1a66f4bFc7a15eE;
    address constant WC_OPRF_REGISTRY = 0xb2C02253ee7bFEDF50F5D015658857099980E91F;
    address constant L1_BLOCK_PREDEPLOY = 0x4200000000000000000000000000000000000015;

    uint64 constant ISSUER_ID = 0x5a7400653dd6d18a;
    uint160 constant OPRF_ID = uint160(ISSUER_ID);

    uint256 wcFork;
    WCHarness wc;

    function setUp() public {
        wcFork = vm.createFork(vm.envString("WORLDCHAIN_PROVIDER"));
        vm.selectFork(wcFork);
        wc = new WCHarness(WC_REGISTRY, WC_ISSUER_REGISTRY, WC_OPRF_REGISTRY, L1_BLOCK_PREDEPLOY);
    }

    function test_propagateRoot_readsRealRegistry() public {
        wc.propagateRoot();

        uint256 root = wc.latestRoot();
        assertTrue(root != 0, "Root should be non-zero from real registry");
        assertTrue(wc.isValidRoot(root), "Propagated root should be valid");
        assertTrue(wc.keccakChain() != bytes32(0), "Chain head should advance");
    }

    function test_propagateRoot_duplicateReverts() public {
        wc.propagateRoot();
        vm.expectRevert(IWorldIdStateBridge.RootNotChanged.selector);
        wc.propagateRoot();
    }

    function test_propagateIssuerPubkey_readsRealRegistry() public {
        wc.propagateIssuerPubkey(ISSUER_ID);

        (BabyJubJub.Affine memory pk,) = wc._issuerSchemaIdToPubkeyAndProofId(ISSUER_ID);
        assertTrue(pk.x != 0 || pk.y != 0, "Issuer pubkey should be non-zero");
    }

    function test_propagateIssuerPubkey_duplicateReverts() public {
        wc.propagateIssuerPubkey(ISSUER_ID);
        vm.expectRevert(IWorldIdStateBridge.IssuerPubkeyNotChanged.selector);
        wc.propagateIssuerPubkey(ISSUER_ID);
    }

    function test_propagateOprfKey_readsRealRegistry() public {
        wc.propagateOprfKey(OPRF_ID);

        (uint256 ox, uint256 oy,) = wc.getOprfKey(OPRF_ID);
        assertTrue(ox != 0 || oy != 0, "OPRF key should be non-zero");
    }

    function test_propagateOprfKey_duplicateReverts() public {
        wc.propagateOprfKey(OPRF_ID);
        vm.expectRevert(IWorldIdStateBridge.OprfKeyNotChanged.selector);
        wc.propagateOprfKey(OPRF_ID);
    }

    function test_chainExtension_eachPropagationAdvancesChain() public {
        wc.propagateRoot();
        bytes32 head1 = wc.keccakChain();

        wc.propagateIssuerPubkey(ISSUER_ID);
        bytes32 head2 = wc.keccakChain();

        wc.propagateOprfKey(OPRF_ID);
        bytes32 head3 = wc.keccakChain();

        assertTrue(head1 != head2, "Head should change after issuer propagation");
        assertTrue(head2 != head3, "Head should change after OPRF propagation");
        assertTrue(head1 != head3, "All heads should be distinct");
    }

    function test_chainExtension_deterministicHash() public {
        bytes32 l1Hash = IL1Block(L1_BLOCK_PREDEPLOY).hash();
        bytes4 sel = bytes4(keccak256("updateRoot(uint256,uint256,bytes32)"));

        (bool ok, bytes memory ret) = WC_REGISTRY.staticcall(abi.encodeWithSignature("getLatestRoot()"));
        assertTrue(ok);
        uint256 realRoot = abi.decode(ret, (uint256));

        bytes memory data = abi.encodeWithSelector(sel, realRoot, block.timestamp, bytes32(block.number));
        bytes32 expected = keccak256(abi.encodePacked(bytes32(0), l1Hash, data));

        wc.propagateRoot();
        assertEq(wc.keccakChain(), expected, "Chain head should match deterministic computation");
    }
}

// ═══════════════════════════════════════════════════════════════
//                  MPT VERIFICATION FORK TESTS
// ═══════════════════════════════════════════════════════════════

/// @notice Verifies MptVerifier against real WC storage proofs fetched via FFI.
contract MptVerificationForkTest is Test {
    address constant WC_REGISTRY = 0x969947cFED008bFb5e3F32a25A1A2CDdf64d46fe;

    uint256 wcFork;

    function setUp() public {
        wcFork = vm.createFork(vm.envString("WORLDCHAIN_PROVIDER"));
        vm.selectFork(wcFork);
    }

    function test_proveLatestRoot_viaMptVerifier() public {
        // Read expected root from real registry
        (bool ok, bytes memory ret) = WC_REGISTRY.staticcall(abi.encodeWithSignature("getLatestRoot()"));
        assertTrue(ok, "getLatestRoot() should succeed");
        uint256 expectedRoot = abi.decode(ret, (uint256));
        assertTrue(expectedRoot != 0, "Expected root should be non-zero");

        // Fetch real proofs via FFI
        string memory wcRpc = vm.envString("WORLDCHAIN_PROVIDER");
        string memory blockHex = _toMinimalHexString(block.number);

        bytes memory encoded = _fetchProof(WC_REGISTRY, bytes32(uint256(0x11)), blockHex, wcRpc);
        (bytes[] memory accountProof, bytes[] memory storageProof, uint256 provenValue) =
            abi.decode(encoded, (bytes[], bytes[], uint256));

        assertEq(provenValue, expectedRoot, "FFI-returned value should match registry");

        // Get state root via FFI
        bytes32 stateRoot = _fetchStateRoot(block.number, wcRpc);

        // Verify account proof
        bytes32 storageRoot = MptVerifier.verifyAccountAndGetStorageRoot(WC_REGISTRY, accountProof, stateRoot);
        assertTrue(storageRoot != bytes32(0), "Storage root should be non-zero");

        // Verify storage proof
        uint256 provenRoot = MptVerifier.storageFromProof(storageProof, storageRoot, bytes32(uint256(0x11)));
        assertEq(provenRoot, expectedRoot, "MPT-proven root should match fork value");
    }

    function test_proveIssuerPubkey_viaMptVerifier() public {
        uint64 issuerId = 0x5a7400653dd6d18a;
        // Slot 0x03 is _idToPubkey mapping in CredentialSchemaIssuerRegistry
        address issuerRegistry = 0x640eb6Fd4c7348661B7DB482e1a66f4bFc7a15eE;

        // Compute the mapping slot: keccak256(abi.encode(key, baseSlot))
        bytes32 mappingSlot;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, issuerId)
            mstore(add(ptr, 0x20), 0x03)
            mappingSlot := keccak256(ptr, 0x40)
        }

        string memory wcRpc = vm.envString("WORLDCHAIN_PROVIDER");
        string memory blockHex = _toMinimalHexString(block.number);

        bytes memory encoded = _fetchProof(issuerRegistry, mappingSlot, blockHex, wcRpc);
        (bytes[] memory accountProof, bytes[] memory storageProof, uint256 provenX) =
            abi.decode(encoded, (bytes[], bytes[], uint256));

        bytes32 stateRoot = _fetchStateRoot(block.number, wcRpc);
        bytes32 storageRoot = MptVerifier.verifyAccountAndGetStorageRoot(issuerRegistry, accountProof, stateRoot);

        uint256 verifiedX = MptVerifier.storageFromProof(storageProof, storageRoot, mappingSlot);
        assertEq(verifiedX, provenX, "MPT-proven issuer X should match FFI value");
        assertTrue(verifiedX != 0, "Issuer pubkey X should be non-zero");
    }

    // ═══════ Helpers ═══════

    function _fetchProof(address account, bytes32 slot, string memory blockHex, string memory rpc)
        internal
        returns (bytes memory)
    {
        string[] memory args = new string[](6);
        args[0] = "bash";
        args[1] = "test/scripts/get-proof-encoded.sh";
        args[2] = vm.toString(account);
        args[3] = vm.toString(slot);
        args[4] = blockHex;
        args[5] = rpc;
        return vm.ffi(args);
    }

    function _fetchStateRoot(uint256 blockNum, string memory rpc) internal returns (bytes32) {
        string[] memory args = new string[](5);
        args[0] = "bash";
        args[1] = "test/scripts/get-block-field.sh";
        args[2] = vm.toString(blockNum);
        args[3] = "stateRoot";
        args[4] = rpc;
        bytes memory result = vm.ffi(args);
        return bytes32(result);
    }

    function _toMinimalHexString(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0x0";
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

// ═══════════════════════════════════════════════════════════════
//                  L1 DISPUTE GAME FORK TESTS
// ═══════════════════════════════════════════════════════════════

/// @notice Tests L1StateAdapter against real DisputeGameFactory on Ethereum mainnet.
contract L1DisputeGameForkTest is Test {
    address constant L1_DISPUTE_GAME_FACTORY = 0x069c4c579671f8c120b1327a73217D01Ea2EC5ea;

    uint256 ethFork;
    IDisputeGameFactory dgf;

    function setUp() public {
        ethFork = vm.createFork(vm.envString("ETHEREUM_PROVIDER"));
        vm.selectFork(ethFork);
        dgf = IDisputeGameFactory(L1_DISPUTE_GAME_FACTORY);
    }

    function test_disputeGameFactory_hasGames() public view {
        uint256 count = dgf.gameCount();
        assertTrue(count > 0, "DGF should have at least one game");
    }

    function test_latestGame_hasValidRootClaim() public view {
        uint256 count = dgf.gameCount();
        (,, IDisputeGame game) = dgf.gameAtIndex(count - 1);
        assertTrue(Claim.unwrap(game.rootClaim()) != bytes32(0), "rootClaim should be non-zero");
    }

    function test_invalidateProofId_withRealChallengerWinsGame() public {
        uint256 challengerIdx = _findGameWithStatus(GameStatus.CHALLENGER_WINS, 100);
        if (challengerIdx == type(uint256).max) {
            console2.log("No CHALLENGER_WINS game found in last 100 games, skipping");
            return;
        }

        L1StateAdapter l1 = new L1StateAdapter(dgf, 1 hours, 30, 0, address(2), address(0), IL1Block(address(0)));

        l1.invalidateProofId(challengerIdx);
        assertTrue(l1.keccakChain() != bytes32(0), "Chain should advance after invalidation");

        (,, IDisputeGame game) = dgf.gameAtIndex(challengerIdx);
        console2.log("Invalidated proofId (l2BlockNumber):", game.l2BlockNumber());
    }

    function test_invalidateProofId_defenderWinsReverts() public {
        uint256 defenderIdx = _findGameWithStatus(GameStatus.DEFENDER_WINS, 50);
        if (defenderIdx == type(uint256).max) {
            console2.log("No DEFENDER_WINS game found in last 50 games, skipping");
            return;
        }

        L1StateAdapter l1 = new L1StateAdapter(dgf, 1 hours, 30, 0, address(2), address(0), IL1Block(address(0)));

        vm.expectRevert(IWorldIdStateBridge.GameNotChallengerWins.selector);
        l1.invalidateProofId(defenderIdx);
    }

    function test_invalidateProofId_invalidIndexReverts() public {
        uint256 count = dgf.gameCount();

        L1StateAdapter l1 = new L1StateAdapter(dgf, 1 hours, 30, 0, address(2), address(0), IL1Block(address(0)));

        vm.expectRevert(IWorldIdStateBridge.InvalidDisputeGameIndex.selector);
        l1.invalidateProofId(count + 999);
    }

    function _findGameWithStatus(GameStatus targetStatus, uint256 searchDepth) internal view returns (uint256) {
        uint256 count = dgf.gameCount();
        uint256 limit = count > searchDepth ? count - searchDepth : 0;
        for (uint256 i = count; i > limit; --i) {
            (,, IDisputeGame g) = dgf.gameAtIndex(i - 1);
            if (g.status() == targetStatus) return i - 1;
        }
        return type(uint256).max;
    }
}

// ═══════════════════════════════════════════════════════════════
//              BRIDGE E2E FORK TESTS (WC → L1)
// ═══════════════════════════════════════════════════════════════

/// @notice End-to-end bridging: propagate on WC fork, replay commits on L1 fork,
///   verify keccak chain heads match.
contract BridgeE2EForkTest is Test {
    address constant WC_REGISTRY = 0x969947cFED008bFb5e3F32a25A1A2CDdf64d46fe;
    address constant WC_ISSUER_REGISTRY = 0x640eb6Fd4c7348661B7DB482e1a66f4bFc7a15eE;
    address constant WC_OPRF_REGISTRY = 0xb2C02253ee7bFEDF50F5D015658857099980E91F;
    address constant L1_BLOCK_PREDEPLOY = 0x4200000000000000000000000000000000000015;
    address constant L1_DISPUTE_GAME_FACTORY = 0x069c4c579671f8c120b1327a73217D01Ea2EC5ea;

    uint64 constant ISSUER_ID = 0x5a7400653dd6d18a;
    uint160 constant OPRF_ID = uint160(ISSUER_ID);

    uint256 wcFork;
    uint256 ethFork;

    struct CapturedState {
        bytes32 keccakChain;
        uint256 root;
        uint256 issuerX;
        uint256 issuerY;
        uint256 oprfX;
        uint256 oprfY;
        bytes32 l1BlockHash;
        uint256 blockTimestamp;
        uint256 blockNumber;
    }

    function setUp() public {
        wcFork = vm.createFork(vm.envString("WORLDCHAIN_PROVIDER"));
        ethFork = vm.createFork(vm.envString("ETHEREUM_PROVIDER"));
    }

    function test_e2e_fullBridging_wcToL1() public {
        CapturedState memory state = _propagateOnWC();
        WorldIdStateBridge.Commitment[] memory commits = _buildCommitments(state);

        vm.selectFork(ethFork);
        IDisputeGameFactory dgf = IDisputeGameFactory(L1_DISPUTE_GAME_FACTORY);
        L1StateAdapter l1 = new L1StateAdapter(dgf, 1 hours, 30, 0, address(2), address(0), IL1Block(address(0)));

        WorldIdStateBridge.CommitmentWithProof memory cwp =
            WorldIdStateBridge.CommitmentWithProof({mptProof: "", commits: commits});

        l1.commitChained(cwp);

        assertEq(l1.keccakChain(), state.keccakChain, "Chain heads should match");
        assertEq(l1.latestRoot(), state.root, "Roots should match");
        assertTrue(l1.isValidRoot(state.root), "Root should be valid on L1");

        (BabyJubJub.Affine memory l1Pk,) = l1._issuerSchemaIdToPubkeyAndProofId(ISSUER_ID);
        assertEq(l1Pk.x, state.issuerX, "Issuer X should match");
        assertEq(l1Pk.y, state.issuerY, "Issuer Y should match");
    }

    function test_e2e_partialCatchUp() public {
        CapturedState memory state = _propagateOnWC();
        WorldIdStateBridge.Commitment[] memory fullCommits = _buildCommitments(state);

        vm.selectFork(ethFork);
        IDisputeGameFactory dgf = IDisputeGameFactory(L1_DISPUTE_GAME_FACTORY);
        L1StateAdapter l1 = new L1StateAdapter(dgf, 1 hours, 30, 0, address(2), address(0), IL1Block(address(0)));

        // Batch 1: root only
        WorldIdStateBridge.Commitment[] memory batch1 = new WorldIdStateBridge.Commitment[](1);
        batch1[0] = fullCommits[0];
        l1.commitChained(WorldIdStateBridge.CommitmentWithProof({mptProof: "", commits: batch1}));
        assertEq(l1.latestRoot(), state.root, "Root should match after batch 1");

        // Batch 2: issuer + OPRF
        WorldIdStateBridge.Commitment[] memory batch2 = new WorldIdStateBridge.Commitment[](2);
        batch2[0] = fullCommits[1];
        batch2[1] = fullCommits[2];
        l1.commitChained(WorldIdStateBridge.CommitmentWithProof({mptProof: "", commits: batch2}));
        assertEq(l1.keccakChain(), state.keccakChain, "Final chain head should match WC");
    }

    function test_e2e_tamperDetection() public {
        CapturedState memory state = _propagateOnWC();

        vm.selectFork(ethFork);
        IDisputeGameFactory dgf = IDisputeGameFactory(L1_DISPUTE_GAME_FACTORY);
        L1StateAdapter l1 = new L1StateAdapter(dgf, 1 hours, 30, 0, address(2), address(0), IL1Block(address(0)));

        // Tamper: use wrong root value
        WorldIdStateBridge.Commitment[] memory commits = new WorldIdStateBridge.Commitment[](1);
        commits[0] = WorldIdStateBridge.Commitment({
            blockHash: state.l1BlockHash,
            data: abi.encodeWithSelector(
                bytes4(keccak256("updateRoot(uint256,uint256,bytes32)")),
                state.root + 1,
                state.blockTimestamp,
                bytes32(state.blockNumber)
            )
        });
        l1.commitChained(WorldIdStateBridge.CommitmentWithProof({mptProof: "", commits: commits}));

        assertTrue(l1.keccakChain() != state.keccakChain, "Tampered commit should produce different chain head");
    }

    function test_e2e_invalidation_rootBecomesInvalid() public {
        CapturedState memory state = _propagateOnWC();
        WorldIdStateBridge.Commitment[] memory commits = _buildCommitments(state);

        vm.selectFork(ethFork);
        IDisputeGameFactory dgf = IDisputeGameFactory(L1_DISPUTE_GAME_FACTORY);
        L1StateAdapter l1 = new L1StateAdapter(dgf, 1 hours, 30, 0, address(2), address(0), IL1Block(address(0)));

        l1.commitChained(WorldIdStateBridge.CommitmentWithProof({mptProof: "", commits: commits}));
        assertTrue(l1.isValidRoot(state.root), "Root should be valid before invalidation");

        // Invalidate the proof ID (block number used as proof ID during propagation)
        WorldIdStateBridge.Commitment[] memory invCommits = new WorldIdStateBridge.Commitment[](1);
        invCommits[0] = WorldIdStateBridge.Commitment({
            blockHash: bytes32(0),
            data: abi.encodeWithSelector(bytes4(keccak256("invalidateProofId(bytes32)")), bytes32(state.blockNumber))
        });
        l1.commitChained(WorldIdStateBridge.CommitmentWithProof({mptProof: "", commits: invCommits}));
        assertFalse(l1.isValidRoot(state.root), "Root should be invalid after invalidation");
    }

    function test_e2e_commitChained_emptyReverts() public {
        vm.selectFork(ethFork);
        IDisputeGameFactory dgf = IDisputeGameFactory(L1_DISPUTE_GAME_FACTORY);
        L1StateAdapter l1 = new L1StateAdapter(dgf, 1 hours, 30, 0, address(2), address(0), IL1Block(address(0)));

        WorldIdStateBridge.Commitment[] memory empty = new WorldIdStateBridge.Commitment[](0);
        vm.expectRevert(IWorldIdStateBridge.EmptyChainedCommits.selector);
        l1.commitChained(WorldIdStateBridge.CommitmentWithProof({mptProof: "", commits: empty}));
    }

    function test_e2e_isValidRoot_windowExpiry() public {
        CapturedState memory state = _propagateOnWC();

        vm.selectFork(ethFork);
        IDisputeGameFactory dgf = IDisputeGameFactory(L1_DISPUTE_GAME_FACTORY);
        L1StateAdapter l1 = new L1StateAdapter(dgf, 1 hours, 30, 0, address(2), address(0), IL1Block(address(0)));

        // Commit root 1
        WorldIdStateBridge.Commitment[] memory c1 = new WorldIdStateBridge.Commitment[](1);
        c1[0] = WorldIdStateBridge.Commitment({
            blockHash: state.l1BlockHash,
            data: abi.encodeWithSelector(
                bytes4(keccak256("updateRoot(uint256,uint256,bytes32)")),
                state.root,
                state.blockTimestamp,
                bytes32(state.blockNumber)
            )
        });
        l1.commitChained(WorldIdStateBridge.CommitmentWithProof({mptProof: "", commits: c1}));
        assertTrue(l1.isValidRoot(state.root));

        // Warp past window, commit a new root to replace latestRoot
        vm.warp(block.timestamp + 100);
        uint256 newRoot = state.root + 42;
        WorldIdStateBridge.Commitment[] memory c2 = new WorldIdStateBridge.Commitment[](1);
        c2[0] = WorldIdStateBridge.Commitment({
            blockHash: state.l1BlockHash,
            data: abi.encodeWithSelector(
                bytes4(keccak256("updateRoot(uint256,uint256,bytes32)")),
                newRoot,
                block.timestamp,
                bytes32(block.number)
            )
        });
        l1.commitChained(WorldIdStateBridge.CommitmentWithProof({mptProof: "", commits: c2}));

        // Old root still within window
        assertTrue(l1.isValidRoot(state.root), "Old root still within 1h window");

        // Warp past validity window
        vm.warp(block.timestamp + 1 hours + 1);
        assertFalse(l1.isValidRoot(state.root), "Old root should expire after window");
        assertTrue(l1.isValidRoot(newRoot), "Latest root always valid");
    }

    // ═══════ Internal Helpers ═══════

    function _propagateOnWC() internal returns (CapturedState memory state) {
        vm.selectFork(wcFork);
        WCHarness wc = new WCHarness(WC_REGISTRY, WC_ISSUER_REGISTRY, WC_OPRF_REGISTRY, L1_BLOCK_PREDEPLOY);

        state.l1BlockHash = IL1Block(L1_BLOCK_PREDEPLOY).hash();
        state.blockTimestamp = block.timestamp;
        state.blockNumber = block.number;

        wc.propagateRoot();
        state.root = wc.latestRoot();

        wc.propagateIssuerPubkey(ISSUER_ID);
        {
            (BabyJubJub.Affine memory pk,) = wc._issuerSchemaIdToPubkeyAndProofId(ISSUER_ID);
            state.issuerX = pk.x;
            state.issuerY = pk.y;
        }

        wc.propagateOprfKey(OPRF_ID);
        (state.oprfX, state.oprfY,) = wc.getOprfKey(OPRF_ID);

        state.keccakChain = wc.keccakChain();
    }

    function _buildCommitments(CapturedState memory state)
        internal
        pure
        returns (WorldIdStateBridge.Commitment[] memory commits)
    {
        commits = new WorldIdStateBridge.Commitment[](3);
        commits[0] = WorldIdStateBridge.Commitment({
            blockHash: state.l1BlockHash,
            data: abi.encodeWithSelector(
                bytes4(keccak256("updateRoot(uint256,uint256,bytes32)")),
                state.root,
                state.blockTimestamp,
                bytes32(state.blockNumber)
            )
        });
        commits[1] = WorldIdStateBridge.Commitment({
            blockHash: state.l1BlockHash,
            data: abi.encodeWithSelector(
                bytes4(keccak256("setIssuerPubkey(uint64,uint256,uint256,bytes32)")),
                ISSUER_ID,
                state.issuerX,
                state.issuerY,
                bytes32(state.blockNumber)
            )
        });
        commits[2] = WorldIdStateBridge.Commitment({
            blockHash: state.l1BlockHash,
            data: abi.encodeWithSelector(
                bytes4(keccak256("setOprfKey(uint160,uint256,uint256,bytes32)")),
                OPRF_ID,
                state.oprfX,
                state.oprfY,
                bytes32(state.blockNumber)
            )
        });
    }
}

// ═══════════════════════════════════════════════════════════════
//              OPSTACK BRIDGE ADAPTER TESTS
// ═══════════════════════════════════════════════════════════════

/// @dev Minimal mock — only one needed in the entire test file.
contract MockCrossDomainMessenger {
    address public lastTarget;
    bytes public lastMessage;
    uint32 public lastMinGasLimit;

    function sendMessage(address target, bytes calldata message, uint32 minGasLimit) external payable {
        lastTarget = target;
        lastMessage = message;
        lastMinGasLimit = minGasLimit;
    }
}

contract OpStackBridgeAdapterTest is Test {
    function test_sendMessage_forwardsToMessenger() public {
        MockCrossDomainMessenger messenger = new MockCrossDomainMessenger();
        address target = address(0xBEEF);
        uint32 gasLimit = 200_000;

        OpStackBridgeAdapter adapter =
            new OpStackBridgeAdapter(ICrossDomainMessenger(address(messenger)), target, gasLimit);

        bytes memory message = hex"deadbeef";
        adapter.sendMessage(message);

        assertEq(messenger.lastTarget(), target);
        assertEq(messenger.lastMessage(), message);
        assertEq(messenger.lastMinGasLimit(), gasLimit);
    }

    function test_sendMessage_forwardsValue() public {
        MockCrossDomainMessenger messenger = new MockCrossDomainMessenger();
        OpStackBridgeAdapter adapter =
            new OpStackBridgeAdapter(ICrossDomainMessenger(address(messenger)), address(0xBEEF), 200_000);

        vm.deal(address(this), 1 ether);
        adapter.sendMessage{value: 0.5 ether}(hex"deadbeef");
        assertEq(address(messenger).balance, 0.5 ether);
    }

    function test_getters_returnConstructorValues() public {
        MockCrossDomainMessenger messenger = new MockCrossDomainMessenger();
        address target = address(0xBEEF);
        uint32 gasLimit = 300_000;

        OpStackBridgeAdapter adapter =
            new OpStackBridgeAdapter(ICrossDomainMessenger(address(messenger)), target, gasLimit);

        assertEq(adapter.MESSENGER(), address(messenger));
        assertEq(adapter.GAS_LIMIT(), gasLimit);
        assertEq(adapter.TARGET(), target);
    }
}
