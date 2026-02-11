// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IBridgeAdapter} from "./IBridgeAdapter.sol";
import {ProofsLib} from "../libraries/Proofs.sol";

/// @title IWorldIdStateBridge
/// @author World Contributors
/// @notice Interface for cross-chain World ID state bridges. Defines state getters, chained
///   commit processing, and adapter management shared by all adapter types (WorldChain, L1,
///   and bridged destinations).
interface IWorldIdStateBridge {
    error Unauthorized();
    /// @dev Thrown when the dispute game index is invalid or does not exist.
    error InvalidDisputeGameIndex();

    /// @dev Thrown when the output root fails acceptance criteria.
    error InvalidOutputRoot();

    /// @dev Thrown when the output root preimage does not match the game's `rootClaim()`.
    error InvalidOutputRootPreimage();

    /// @dev Thrown when the dispute game has not been resolved in favor of the challenger.
    error GameNotChallengerWins();

    /// @dev Thrown when propagateRoot is called but the root hasn't changed.
    error RootNotChanged();

    /// @dev Thrown when propagateIssuerPubkey is called but the pubkey hasn't changed.
    error IssuerPubkeyNotChanged();

    /// @dev Thrown when propagateOprfKey is called but the key hasn't changed.
    error OprfKeyNotChanged();

    /// @dev Thrown when the L1 block header hash is not recognized by the oracle.
    error UnknownL1BlockHash();

    /// @dev Thrown when no chained commits are provided.
    error EmptyChainedCommits();

    /// @dev Thrown when a chained commit has an unknown action type.
    error UnknownAction(uint8 action);

    /// @dev Thrown when the computed chain head is not valid.
    error InvalidChainHead();

    /// @dev Thrown when the provided root is not valid.
    error InvalidRoot();

    /// @dev Thrown when a proof ID used by a root or key has been invalidated.
    error InvalidatedProofId();

    /// @notice Emitted when a proof ID is invalidated.
    event ProofIdInvalidated(bytes32 indexed proofId);

    /// @notice Emitted when a new bridge adapter is registered.
    event AdapterRegistered(uint256 indexed index, address adapter);

    /// @notice Emitted when a bridge adapter is removed.
    event AdapterRemoved(uint256 indexed index, address adapter);

    /// @notice Emitted when the native World Chain state is updated and propagated into the bridge.
    event ChainCommitted(bytes32 indexed keccakChain, uint256 indexed blockNumber, bytes commitment);

    /// @notice Checks if a root is currently valid.
    function isValidRoot(uint256 root) external view returns (bool);

    /// @notice Registers a new bridge adapter.
    function registerAdapter(IBridgeAdapter adapter) external;

    /// @notice Removes a bridge adapter at the given index using swap-and-pop.
    function removeAdapter(uint256 index) external;

    /// @notice Commits a sequence of state transitions by verifying them against L1 state
    ///   via MPT proof. The L1 block hash is read from the oracle for trust anchoring.
    /// @param commitWithProof The commitment batch with MPT proof data.
    function commitChained(ProofsLib.CommitmentWithProof calldata commitWithProof) external;
}
