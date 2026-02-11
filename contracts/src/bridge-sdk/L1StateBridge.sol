// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {WorldIdStateBridge} from "./abstract/WorldIdStateBridge.sol";
import {IL1Block} from "./vendored/optimism/IL1Block.sol";
import {IDisputeGameFactory} from "./vendored/optimism/IDisputeGameFactory.sol";
import {IDisputeGame} from "./vendored/optimism/IDisputeGame.sol";
import {GameStatus, Claim} from "./vendored/optimism/DisputeTypes.sol";
import {IBridgeAdapter} from "./interfaces/IBridgeAdapter.sol";
import {IWorldIdStateBridge} from "./interfaces/IWorldIdStateBridge.sol";
import {ProofsLib} from "./libraries/Proofs.sol";
import {MptVerifier} from "./libraries/MptVerifier.sol";

/// @title RelayContext
/// @author World Contributors
/// @notice L1 relay context for the World ID state bridge.
///
///   Verifies proofs against the state root of World Chain stored in the DisputeGameFactory's
///   game contract. Applies proven commitments locally, marks chain heads valid, and dispatches
///   to destination adapters.
contract L1StateBridge is WorldIdStateBridge {
    using ProofsLib for ProofsLib.Chain;

    ////////////////////////////////////////////////////////////
    //                       IMMUTABLES                       //
    ////////////////////////////////////////////////////////////

    /// @notice The DisputeGameFactory contract on L1.
    IDisputeGameFactory public immutable DISPUTE_GAME_FACTORY;

    /// @notice The SourceContext contract address on World Chain.
    address public immutable WC_BRIDGE;

    ////////////////////////////////////////////////////////////
    //                      CONSTRUCTOR                       //
    ////////////////////////////////////////////////////////////

    constructor(
        IDisputeGameFactory disputeGameFactory,
        address worldChainBridge,
        uint256 rootValidityWindow_,
        uint256 treeDepth_,
        uint64 minExpirationThreshold_
    ) WorldIdStateBridge(IL1Block(address(0)), address(0), rootValidityWindow_, treeDepth_, minExpirationThreshold_) {
        DISPUTE_GAME_FACTORY = disputeGameFactory;
        WC_BRIDGE = worldChainBridge;
    }

    ////////////////////////////////////////////////////////////
    //                   PROVE & DISPATCH                     //
    ////////////////////////////////////////////////////////////

    /// @notice Proves that a batch of commitments is valid by verifying against a DisputeGame
    ///   and MPT proof of the World Chain bridge's chain head. Applies the commitments locally,
    ///   marks the new chain head valid, and dispatches to destination adapters.
    /// @param disputeGameIndex The index of the dispute game in the factory.
    /// @param commitWithProof The commitment batch with MPT proof data.
    function proveChainedCommitment(uint256 disputeGameIndex, ProofsLib.CommitmentWithProof calldata commitWithProof)
        external
        virtual
    {
        if (commitWithProof.commits.length == 0) revert EmptyChainedCommits();

        (, bytes32 rootClaim) = _validateDisputeGame(disputeGameIndex);

        ProofsLib.Chain memory chain = keccakChain;
        ProofsLib.verifyL1Proof(chain, commitWithProof, WC_BRIDGE, rootClaim);

        _applyCommitments(commitWithProof.commits);
        keccakChain.commitChained(commitWithProof.commits);
        _validChainHeads[keccakChain.head] = true;

        _dispatch(abi.encode(commitWithProof));

        emit ChainCommitted(keccakChain.head, block.number, abi.encode(commitWithProof));
    }

    /// @notice Invalidates a proofId by proving that a dispute game covering the corresponding
    ///   WC block was resolved as CHALLENGER_WINS. Extends the chain and dispatches to destinations.
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

        ProofsLib.Commitment memory commit = ProofsLib.Commitment({
            blockHash: blockhash(block.number - 1), data: abi.encodeWithSelector(INVALIDATE_PROOF_ID_SELECTOR, proofId)
        });

        applyCommitment(commit);
        keccakChain.commit(commit);

        _validChainHeads[keccakChain.head] = true;

        _dispatch(abi.encode(commit));

        emit ChainCommitted(keccakChain.head, block.number, abi.encode(commit));
    }

    /// @dev L1 does not accept destination-style chained commits.
    function commitChained(ProofsLib.CommitmentWithProof calldata) external pure override {}

    ////////////////////////////////////////////////////////////
    //                       INTERNAL                         //
    ////////////////////////////////////////////////////////////

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

    /// @dev Dispatches encoded commitment data to all registered adapters.
    function _dispatch(bytes memory data) internal {
        for (uint256 i; i < _adapters.length; ++i) {
            _adapters[i].sendMessage(data);
        }
    }
}
