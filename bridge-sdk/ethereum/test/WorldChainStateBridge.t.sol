// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {EthereumWorldIdVerifier} from "../src/core/EthereumWorldIdVerifier.sol";
import {WorldIdBridge} from "../src/core/lib/WorldIdBridge.sol";
import {EmptyChainedCommits, ChainCommitted} from "../src/core/interfaces/IWorldIdBridge.sol";
import {IL1Block} from "../src/vendor/optimism/IL1Block.sol";
import {ProofsLib} from "../src/lib/ProofsLib.sol";
import {IDisputeGameFactory} from "../src/vendor/optimism/IDisputeGameFactory.sol";
import {IDisputeGame} from "../src/vendor/optimism/IDisputeGame.sol";
import {GameStatus, Claim, GameType, Timestamp} from "../src/vendor/optimism/DisputeTypes.sol";
import {BabyJubJub} from "lib/oprf-key-registry/src/BabyJubJub.sol";

/// @dev Mock L1Block oracle that returns a configurable block hash.
contract MockL1BlockHash {
    bytes32 public hash;

    function setHash(bytes32 h) external {
        hash = h;
    }
}

/// @dev Concrete destination bridge that verifies L1 state via MPT proof.
contract DestinationBridge is WorldIdBridge {
    using ProofsLib for ProofsLib.Chain;

    IL1Block public immutable L1_BLOCK_ORACLE;
    address public immutable L1_BRIDGE;

    constructor(IL1Block oracle, address l1Bridge) WorldIdBridge(1 hours, 30, 0) {
        L1_BLOCK_ORACLE = oracle;
        L1_BRIDGE = l1Bridge;
    }

    function commitChained(ProofsLib.CommitmentWithProof calldata commitWithProof) external override {
        if (commitWithProof.commits.length == 0) revert EmptyChainedCommits();

        (bytes memory l1HeaderRlp, bytes[] memory l1AccountProof, bytes[] memory chainHeadValidityProof) =
            abi.decode(commitWithProof.mptProof, (bytes, bytes[], bytes[]));

        bytes32 blockHash = keccak256(l1HeaderRlp);
        require(blockHash == L1_BLOCK_ORACLE.hash(), "Unknown L1 block hash");

        // 1. Compute expected chain head
        ProofsLib.Chain memory chain = keccakChain;
        bytes32 newChainHead = chain.hashChained(commitWithProof.commits);

        // 2. Extract state root from L1 header (hash already verified above)
        bytes32 stateRoot = ProofsLib.extractStateRootFromHeader(l1HeaderRlp);

        // 3. Verify account + storage proof
        ProofsLib.verifyAccountAndChainStorageProof(
            l1AccountProof, chainHeadValidityProof, stateRoot, L1_BRIDGE, newChainHead
        );

        // 4. Apply state changes and extend chain
        applyCommitments(commitWithProof.commits);
        keccakChain.commitChained(commitWithProof.commits);

        emit ChainCommitted(keccakChain.head, block.number, abi.encode(commitWithProof));
    }
}

/// @dev ABI-compatible mock for IDisputeGame. Does NOT implement the interface
///   (pure/view conflict) — cast address to IDisputeGame at call site.
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

contract WorldChainStateBridgeTest is Test {
    /// @dev Deterministic address used as the "L1 bridge" on the anvil fork.
    address constant PLANTED_BRIDGE = address(uint160(uint256(keccak256("test.l1.bridge"))));
    /// @dev Deterministic address used as the "WC bridge" on the anvil fork.
    address constant PLANTED_WC_BRIDGE = address(uint160(uint256(keccak256("test.wc.bridge"))));

    bytes4 constant UPDATE_ROOT_SEL = bytes4(keccak256("updateRoot(uint256,uint256,bytes32)"));
    bytes4 constant SET_ISSUER_SEL = bytes4(keccak256("setIssuerPubkey(uint64,uint256,uint256,bytes32)"));
    bytes4 constant SET_OPRF_SEL = bytes4(keccak256("setOprfKey(uint160,uint256,uint256,bytes32)"));

    function test_commitChained_singleCommit_realL1MptProof() public {
        // 1. Build a single commitment
        uint256 testRoot = 12345;
        uint256 testTimestamp = 1_700_000_000;
        bytes32 testProofId = bytes32(uint256(42));
        bytes32 commitBlockHash = bytes32(uint256(0xBEEF));

        bytes memory commitData = abi.encodeWithSelector(UPDATE_ROOT_SEL, testRoot, testTimestamp, testProofId);

        // 2. Compute expected chain head: keccak256(head || blockHash || data), head starts at 0
        bytes32 expectedHead = keccak256(abi.encodePacked(bytes32(0), commitBlockHash, commitData));

        // 3. Generate real MPT proof via FFI (anvil fork of L1)
        string memory l1Rpc = vm.envString("ETHEREUM_PROVIDER");
        (bytes memory mptProof, bytes32 blockHash) = _generateDestProof(l1Rpc, expectedHead);

        // 4. Deploy mock oracle + destination bridge
        MockL1BlockHash oracle = new MockL1BlockHash();
        oracle.setHash(blockHash);
        DestinationBridge dest = new DestinationBridge(IL1Block(address(oracle)), PLANTED_BRIDGE);

        // 5. Build CommitmentWithProof and call commitChained
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = ProofsLib.Commitment({blockHash: commitBlockHash, data: commitData});

        dest.commitChained(ProofsLib.CommitmentWithProof({mptProof: mptProof, commits: commits}));

        // 6. Assert state was applied via real proof verification
        (bytes32 head,) = dest.keccakChain();
        assertEq(head, expectedHead, "Chain head should match expected");
        assertEq(dest.latestRoot(), testRoot, "Root should be applied");
        assertTrue(dest.isValidRoot(testRoot), "Root should be valid");
    }

    function test_commitChained_multipleCommits_realL1MptProof() public {
        // 1. Build 3 commitments: root + issuer + OPRF
        bytes32 commitBlockHash = bytes32(uint256(0xCAFE));
        uint256 testRoot = 99999;
        uint256 testTimestamp = 1_700_000_000;
        bytes32 proofId = bytes32(uint256(7));
        uint64 issuerId = 0x5a7400653dd6d18a;
        uint160 oprfId = uint160(issuerId);

        bytes memory rootData = abi.encodeWithSelector(UPDATE_ROOT_SEL, testRoot, testTimestamp, proofId);
        bytes memory issuerData = abi.encodeWithSelector(SET_ISSUER_SEL, issuerId, uint256(111), uint256(222), proofId);
        bytes memory oprfData = abi.encodeWithSelector(SET_OPRF_SEL, oprfId, uint256(333), uint256(444), proofId);

        // 2. Compute chained head: h0 -> h1 -> h2
        bytes32 h0 = keccak256(abi.encodePacked(bytes32(0), commitBlockHash, rootData));
        bytes32 h1 = keccak256(abi.encodePacked(h0, commitBlockHash, issuerData));
        bytes32 h2 = keccak256(abi.encodePacked(h1, commitBlockHash, oprfData));

        // 3. Generate proof for the final chain head
        string memory l1Rpc = vm.envString("ETHEREUM_PROVIDER");
        (bytes memory mptProof, bytes32 blockHash) = _generateDestProof(l1Rpc, h2);

        // 4. Deploy destination bridge
        MockL1BlockHash oracle = new MockL1BlockHash();
        oracle.setHash(blockHash);
        DestinationBridge dest = new DestinationBridge(IL1Block(address(oracle)), PLANTED_BRIDGE);

        // 5. Call commitChained with all 3 commits
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](3);
        commits[0] = ProofsLib.Commitment({blockHash: commitBlockHash, data: rootData});
        commits[1] = ProofsLib.Commitment({blockHash: commitBlockHash, data: issuerData});
        commits[2] = ProofsLib.Commitment({blockHash: commitBlockHash, data: oprfData});

        dest.commitChained(ProofsLib.CommitmentWithProof({mptProof: mptProof, commits: commits}));

        // 6. Assert all state was applied
        (bytes32 head,) = dest.keccakChain();
        assertEq(head, h2, "Final chain head should match");
        assertEq(dest.latestRoot(), testRoot, "Root applied");
        assertTrue(dest.isValidRoot(testRoot), "Root valid");

        (BabyJubJub.Affine memory pk,) = dest.issuerSchemaIdToPubkeyAndProofId(issuerId);
        assertEq(pk.x, 111, "Issuer X applied");
        assertEq(pk.y, 222, "Issuer Y applied");
    }

    function test_commitChained_invalidProof_reverts() public {
        // Build a commitment but generate proof for a DIFFERENT chain head
        bytes32 commitBlockHash = bytes32(uint256(0xDEAD));
        bytes memory commitData = abi.encodeWithSelector(UPDATE_ROOT_SEL, uint256(1), uint256(2), bytes32(uint256(3)));

        // Real chain head
        bytes32 realHead = keccak256(abi.encodePacked(bytes32(0), commitBlockHash, commitData));
        // Wrong head — proof proves this, but commits hash to realHead
        bytes32 wrongHead = keccak256(abi.encodePacked(realHead, bytes32(uint256(1))));

        string memory l1Rpc = vm.envString("ETHEREUM_PROVIDER");
        (bytes memory mptProof, bytes32 blockHash) = _generateDestProof(l1Rpc, wrongHead);

        MockL1BlockHash oracle = new MockL1BlockHash();
        oracle.setHash(blockHash);
        DestinationBridge dest = new DestinationBridge(IL1Block(address(oracle)), PLANTED_BRIDGE);

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = ProofsLib.Commitment({blockHash: commitBlockHash, data: commitData});

        vm.expectRevert();
        dest.commitChained(ProofsLib.CommitmentWithProof({mptProof: mptProof, commits: commits}));
    }

    // ═══════ Dest Proof Helper ═══════

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

    function test_commitChained_l1Bridge_singleCommit() public {
        // 1. Build a commitment
        bytes32 commitBlockHash = bytes32(uint256(0xF00D));
        uint256 testRoot = 54321;
        uint256 testTimestamp = 1_700_000_000;
        bytes32 proofId = bytes32(uint256(99));

        bytes memory commitData = abi.encodeWithSelector(UPDATE_ROOT_SEL, testRoot, testTimestamp, proofId);
        bytes32 expectedHead = keccak256(abi.encodePacked(bytes32(0), commitBlockHash, commitData));

        // 2. Generate proof via FFI (anvil fork of WC)
        string memory wcRpc = vm.envString("WORLDCHAIN_PROVIDER");
        (bytes memory wcMptProof, bytes32 rootClaim) = _generateL1Proof(wcRpc, expectedHead);

        // 3. Deploy mock DisputeGame + Factory
        MockDisputeGame game = new MockDisputeGame(GameStatus.DEFENDER_WINS, rootClaim, 12345);
        MockDisputeGameFactory factory = new MockDisputeGameFactory();
        factory.addGame(address(game));

        // 4. Deploy EthereumWorldIdVerifier (verifier = address(0) for test — not testing ZK proofs here)
        EthereumWorldIdVerifier l1Bridge = new EthereumWorldIdVerifier(
            address(0), IDisputeGameFactory(address(factory)), PLANTED_WC_BRIDGE, 1 hours, 30, 0
        );

        // 5. Encode disputeGameIndex into mptProof alongside the WC proof data
        (bytes[] memory outputRootProof, bytes[] memory accountProof, bytes[] memory storageValidityProof) =
            abi.decode(wcMptProof, (bytes[], bytes[], bytes[]));
        bytes memory mptProofWithIndex = abi.encode(outputRootProof, accountProof, storageValidityProof, uint256(0));

        // 6. Build CommitmentWithProof and call commitChained
        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = ProofsLib.Commitment({blockHash: commitBlockHash, data: commitData});

        l1Bridge.commitChained(ProofsLib.CommitmentWithProof({mptProof: mptProofWithIndex, commits: commits}));

        // 7. Assert state was applied
        (bytes32 head,) = l1Bridge.keccakChain();
        assertEq(head, expectedHead, "Chain head should match");
        assertEq(l1Bridge.latestRoot(), testRoot, "Root applied");
        assertTrue(l1Bridge.isValidRoot(testRoot), "Root valid");
    }

    function test_commitChained_l1Bridge_wrongRootClaim_reverts() public {
        bytes32 commitBlockHash = bytes32(uint256(0xF00D));
        bytes memory commitData = abi.encodeWithSelector(UPDATE_ROOT_SEL, uint256(1), uint256(2), bytes32(uint256(3)));
        bytes32 expectedHead = keccak256(abi.encodePacked(bytes32(0), commitBlockHash, commitData));

        string memory wcRpc = vm.envString("WORLDCHAIN_PROVIDER");
        (bytes memory wcMptProof,) = _generateL1Proof(wcRpc, expectedHead);

        // Use a WRONG rootClaim (doesn't match the proof's output root)
        bytes32 wrongClaim = bytes32(uint256(0xBAD));
        MockDisputeGame game = new MockDisputeGame(GameStatus.DEFENDER_WINS, wrongClaim, 12345);
        MockDisputeGameFactory factory = new MockDisputeGameFactory();
        factory.addGame(address(game));

        EthereumWorldIdVerifier l1Bridge = new EthereumWorldIdVerifier(
            address(0), IDisputeGameFactory(address(factory)), PLANTED_WC_BRIDGE, 1 hours, 30, 0
        );

        // Encode disputeGameIndex into mptProof
        (bytes[] memory outputRootProof, bytes[] memory accountProof, bytes[] memory storageValidityProof) =
            abi.decode(wcMptProof, (bytes[], bytes[], bytes[]));
        bytes memory mptProofWithIndex = abi.encode(outputRootProof, accountProof, storageValidityProof, uint256(0));

        ProofsLib.Commitment[] memory commits = new ProofsLib.Commitment[](1);
        commits[0] = ProofsLib.Commitment({blockHash: commitBlockHash, data: commitData});

        vm.expectRevert();
        l1Bridge.commitChained(ProofsLib.CommitmentWithProof({mptProof: mptProofWithIndex, commits: commits}));
    }

    // ═══════ L1 Proof Helper ═══════

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
}
