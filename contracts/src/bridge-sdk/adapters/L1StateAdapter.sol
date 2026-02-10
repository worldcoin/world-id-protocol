// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {WorldIdStateBridge} from "../abstract/WorldIdStateBridge.sol";
import {IDisputeGameFactory} from "../vendored/optimism/IDisputeGameFactory.sol";
import {IDisputeGame} from "../vendored/optimism/IDisputeGame.sol";
import {GameStatus, Claim} from "../vendored/optimism/DisputeTypes.sol";
import {Hashing} from "../vendored/optimism/Hashing.sol";
import {ICrossDomainMessenger} from "../vendored/optimism/ICrossDomainMessenger.sol";
import {MptVerifier} from "../libraries/MptVerifier.sol";
import {IBridgeAdapter} from "../interfaces/IBridgeAdapter.sol";
import {IL1Block} from "../vendored/optimism/IL1Block.sol";
import {IWorldIdStateBridge} from "../interfaces/IWorldIdStateBridge.sol";

/// @title L1StateAdapter
/// @author World Contributors
/// @notice L1 adapter for the World ID state bridge. Proves WC chain heads are valid via
///   DisputeGame + MPT storage proofs, processes chained commits to populate L1 state, and can
///   dispatch invalidation chained commits to destination chains.
/// @dev Inherits WorldIdStateBridge directly. `_validChainHeads` (slot 8) is populated by
///   `proveChainHead` and checked in `_verifyChainHead` for `processChainedCommits`.
contract L1StateAdapter is WorldIdStateBridge {
    /// @dev Mapping of WC chain head (keccak256 of the chain's blocks) to validity. Updated via `proveChainHead`.
    ///   Stored at a known slot (slot 8) for MPT proof verification in `_verifyChainHead`.
    bytes32 internal constant KECCAK_CHAIN_SLOT = bytes32(keccak256("world.id.l1StateAdapter.keccakChain"));

    struct L1CommitmentWithProof {
        CommitmentWithProof commitment;
        uint256 disputeGameIndex;
    }

    ////////////////////////////////////////////////////////////
    //                       IMMUTABLES                       //
    ////////////////////////////////////////////////////////////

    /// @notice The DisputeGameFactory contract on L1.
    IDisputeGameFactory public immutable DISPUTE_GAME_FACTORY;

    /// @notice The WorldChainStateAdapter contract address on World Chain.
    address public immutable WORLD_CHAIN_BRIDGE;

    ////////////////////////////////////////////////////////////
    //                      CONSTRUCTOR                       //
    ////////////////////////////////////////////////////////////

    constructor(
        IDisputeGameFactory disputeGameFactory,
        uint256 rootValidityWindow_,
        uint256 treeDepth_,
        uint64 minExpirationThreshold_,
        address worldChainVerifier_,
        address l1Bridge,
        IL1Block l1BlockHashOracle
    ) WorldIdStateBridge(rootValidityWindow_, treeDepth_, minExpirationThreshold_, l1BlockHashOracle, l1Bridge) {
        DISPUTE_GAME_FACTORY = disputeGameFactory;
        WORLD_CHAIN_BRIDGE = worldChainVerifier_;
    }

    /// @notice Proves that a given WC chain head is valid by referencing a resolved dispute game and providing
    function proveChainedCommitment(L1CommitmentWithProof calldata commitWithProof) external virtual {
        bytes calldata proofData = commitWithProof.commitment.mptProof;

        (bytes[] memory outputRootProof, bytes[] memory accountProof, bytes[] memory chainHeadValidityProof) =
            abi.decode(proofData, (bytes[], bytes[], bytes[]));

        (, bytes32 rootClaim) = _validateDisputeGame(commitWithProof.disputeGameIndex);

        bytes32 stateRoot = _verifyOutputRootPreimage(outputRootProof, rootClaim);

        bytes32 storageRoot = MptVerifier.verifyAccountAndGetStorageRoot(WORLD_CHAIN_BRIDGE, accountProof, stateRoot);

        bytes32 keccakChain = hashChainedCommitment(commitWithProof.commitment.commits, keccakChain);

        bytes32 validitySlot = MptVerifier._computeMappingSlot(MptVerifier.VALID_CHAIN_HEADS_SLOT, keccakChain);

        uint256 isValid = MptVerifier.storageFromProof(chainHeadValidityProof, storageRoot, validitySlot);

        if (isValid != 1) revert InvalidChainHead();

        commitChained(commitWithProof.commitment);

        _dispatch(abi.encode(commitWithProof.commitment));
    }

    /// @notice Invalidates a proofId by proving that a dispute game covering the corresponding
    ///   WC block was resolved as CHALLENGER_WINS. Dispatches the invalidation to destinations.
    /// @dev Permissionless — anyone can call with a valid dispute game index.
    function invalidateProofId(uint256 disputeGameIndex) external {
        uint256 gameCount = DISPUTE_GAME_FACTORY.gameCount();
        if (disputeGameIndex >= gameCount) {
            revert IWorldIdStateBridge.InvalidDisputeGameIndex();
        }

        (,, IDisputeGame game) = DISPUTE_GAME_FACTORY.gameAtIndex(disputeGameIndex);
        if (game.status() != GameStatus.CHALLENGER_WINS) {
            revert IWorldIdStateBridge.GameNotChallengerWins();
        }

        bytes32 proofId = bytes32(game.l2BlockNumber());
        bytes memory data = abi.encodeWithSelector(WorldIdStateBridge.INVALIDATE_PROOF_ID_SELECTOR, proofId);

        keccakChain = commitChain(Commitment({blockHash: blockhash(block.number), data: data}));
    }

    /// @dev Checks that the computed chain head was previously proven via `proveChainHead`.
    function verifyChainTip(bytes32 computedHead, bytes calldata) internal view virtual {
        bytes32 baseSlot = KECCAK_CHAIN_SLOT;
        assembly ("memory-safe") {
            let fmp := mload(0x40)
            mstore(fmp, keccak256(computedHead, baseSlot))

            let valid := sload(mload(fmp))
            if iszero(valid) {
                mstore(0x00, "Invalid chain head")
                revert(0x00, 0x20)
            }
        }
    }

    /// @dev Validates a dispute game by index and returns the game proxy and root claim.
    function _validateDisputeGame(uint256 index) internal view returns (IDisputeGame game, bytes32 rootClaim) {
        uint256 gameCount = DISPUTE_GAME_FACTORY.gameCount();
        if (index >= gameCount) revert InvalidDisputeGameIndex();

        (,, game) = DISPUTE_GAME_FACTORY.gameAtIndex(index);

        if (game.status() != GameStatus.DEFENDER_WINS) {
            revert InvalidOutputRoot();
        }

        rootClaim = Claim.unwrap(game.rootClaim());
    }

    /// @dev Verifies the output root preimage against the root claim and extracts the L2 state root.
    function _verifyOutputRootPreimage(bytes[] memory outputRootProof, bytes32 rootClaim)
        internal
        pure
        virtual
        returns (bytes32 stateRoot)
    {
        bytes32 version = bytes32(outputRootProof[0]);
        stateRoot = bytes32(outputRootProof[1]);
        bytes32 messagePasserStorageRoot = bytes32(outputRootProof[2]);
        bytes32 latestBlockhash = bytes32(outputRootProof[3]);

        bytes32 computedRoot =
            Hashing.hashOutputRootProof(version, stateRoot, messagePasserStorageRoot, latestBlockhash);

        if (computedRoot != rootClaim) revert InvalidOutputRootPreimage();
    }

    /// @dev Propagates commitments to destination chains by dispatching a message with the commit data. Called in `invalidateProofId` to
    function _dispatch(bytes memory data) internal {
        IBridgeAdapter[] memory currentAdapters = _adapters;
        for (uint256 i; i < currentAdapters.length; ++i) {
            IBridgeAdapter adapter = currentAdapters[i];

            address messenger = adapter.MESSENGER();
            uint32 gasLimit = adapter.GAS_LIMIT();

            (bool success,) =
                messenger.call{value: msg.value}(abi.encodeWithSelector(adapter.sendMessage.selector, data, gasLimit));

            require(success, "L1StateAdapter: dispatch failed");
        }
    }
}
