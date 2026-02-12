// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IDisputeGameFactory} from "../vendor/optimism/IDisputeGameFactory.sol";
import {IDisputeGame} from "../vendor/optimism/IDisputeGame.sol";
import {GameStatus, Claim} from "../vendor/optimism/DisputeTypes.sol";
import {ITransport} from "../interfaces/ITransport.sol";
import {INativeReceiver} from "./interfaces/INativeReceiver.sol";
import {ProofsLib} from "../lib/ProofsLib.sol";
import {CrossDomainWorldIdVerifier} from "./lib/CrossDomainWorldIdVerifier.sol";
import {EmptyChainedCommits, InvalidOutputRoot, ChainCommitted} from "./interfaces/IWorldIdBridge.sol";

/// @dev Thrown when the dispute game index is invalid or does not exist.
error InvalidDisputeGameIndex();

/// @dev Thrown when the adapter index is out of bounds.
error InvalidAdapterIndex();

/// @notice Emitted when a new bridge adapter is registered.
event AdapterRegistered(uint256 indexed index, address adapter);

/// @notice Emitted when a bridge adapter is removed.
event AdapterRemoved(uint256 indexed index, address adapter);

/// @title EthereumWorldIdVerifier
/// @author World Contributors
/// @notice Ethereum L1 World ID verifier and relay. Verifies ZK proofs against bridged state
///   proven via OP Stack DisputeGame, applies commitments, and dispatches to destination adapters.
contract EthereumWorldIdVerifier is CrossDomainWorldIdVerifier {
    using ProofsLib for ProofsLib.Chain;

    ////////////////////////////////////////////////////////////
    //                       IMMUTABLES                       //
    ////////////////////////////////////////////////////////////

    /// @notice The DisputeGameFactory contract on L1.
    IDisputeGameFactory public immutable DISPUTE_GAME_FACTORY;

    /// @notice The SourceContext contract address on World Chain.
    address public immutable WC_BRIDGE;

    /// @notice Registered Adapters for dispatching state updates.
    ITransport[] public adapters;

    ////////////////////////////////////////////////////////////
    //                      CONSTRUCTOR                       //
    ////////////////////////////////////////////////////////////

    constructor(
        address verifier,
        IDisputeGameFactory disputeGameFactory,
        address worldChainBridge,
        uint256 rootValidityWindow_,
        uint256 treeDepth_,
        uint64 minExpirationThreshold_
    ) CrossDomainWorldIdVerifier(verifier, rootValidityWindow_, treeDepth_, minExpirationThreshold_) {
        DISPUTE_GAME_FACTORY = disputeGameFactory;
        WC_BRIDGE = worldChainBridge;
    }

    /// @notice Registers a new bridge adapter for state dispatch.
    /// @param adapter The bridge adapter contract to register.
    function registerAdapter(ITransport adapter) external virtual {
        uint256 index = adapters.length;
        adapters.push(adapter);
        emit AdapterRegistered(index, address(adapter));
    }

    /// @notice Removes a bridge adapter by swapping with the last element and popping.
    /// @param index The index of the adapter to remove.
    function removeAdapter(uint64 index) external virtual {
        if (index >= adapters.length) revert InvalidAdapterIndex();
        address removed = address(adapters[index]);
        adapters[index] = adapters[adapters.length - 1];
        adapters.pop();
        emit AdapterRemoved(index, removed);
    }

    /// @notice Verifies and commits a batch of state changes proven against a resolved WC DisputeGame.
    /// @dev The `mptProof` must encode `(bytes[], bytes[], bytes[], uint256)`:
    ///   outputRootProof, accountProof, storageValidityProof, disputeGameIndex.
    /// @param commitWithProof The commitments and associated MPT proof data.
    function commitChained(ProofsLib.CommitmentWithProof calldata commitWithProof) external override {
        if (commitWithProof.commits.length == 0) revert EmptyChainedCommits();

        (
            bytes[] memory outputRootProof,
            bytes[] memory accountProof,
            bytes[] memory storageValidityProof,
            uint256 disputeGameIndex
        ) = abi.decode(commitWithProof.mptProof, (bytes[], bytes[], bytes[], uint256));

        (, bytes32 rootClaim) = _validateDisputeGame(disputeGameIndex);

        // 1. Compute expected chain head from current state + new commits.
        ProofsLib.Chain memory chain = keccakChain;
        bytes32 newChainHead = chain.hashChained(commitWithProof.commits);

        // 2. Verify output root preimage → L2 state root.
        bytes32 stateRoot = ProofsLib.verifyOutputRootPreimage(outputRootProof, rootClaim);

        // 3. Verify account + storage proof: chain head at slot 0 of WC bridge matches.
        ProofsLib.verifyAccountAndChainStorageProof(
            accountProof, storageValidityProof, stateRoot, WC_BRIDGE, newChainHead
        );

        // 4. Apply state changes and extend chain.
        applyCommitments(commitWithProof.commits);
        keccakChain.commitChained(commitWithProof.commits);

        // 5. Dispatch only the commits (not the L1 mptProof) to native transports.
        dispatch(commitWithProof.commits);

        emit ChainCommitted(keccakChain.head, block.number, abi.encode(commitWithProof));
    }

    ////////////////////////////////////////////////////////////
    //                       INTERNAL                         //
    ////////////////////////////////////////////////////////////

    /// @dev Dispatches commitments to all registered adapters via `commitFromL1` ABI encoding.
    /// @param commits The commitments to dispatch.
    function dispatch(ProofsLib.Commitment[] memory commits) internal {
        bytes memory message = abi.encodeCall(INativeReceiver.commitFromL1, (commits));
        for (uint256 i; i < adapters.length; ++i) {
            adapters[i].sendMessage(message);
        }
    }

    /// @dev Validates a dispute game by index and returns the game proxy and root claim.
    ///   Reverts if the game index is out of bounds or the game has not resolved in favor of the defender.
    /// @param index The index of the dispute game in the factory.
    /// @return game The dispute game proxy contract.
    /// @return rootClaim The root claim (output root) of the resolved game.
    function _validateDisputeGame(uint256 index) internal view returns (IDisputeGame game, bytes32 rootClaim) {
        uint256 gameCount = DISPUTE_GAME_FACTORY.gameCount();
        if (index >= gameCount) revert InvalidDisputeGameIndex();

        (,, game) = DISPUTE_GAME_FACTORY.gameAtIndex(index);

        if (game.status() != GameStatus.DEFENDER_WINS) {
            revert InvalidOutputRoot();
        }

        rootClaim = Claim.unwrap(game.rootClaim());
    }
}
