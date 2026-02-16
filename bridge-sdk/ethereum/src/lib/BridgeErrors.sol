// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Custom errors for the World ID state bridge.

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

/// @dev Thrown when propagateState is called but no state has changed.
error NothingChanged();

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

/// @dev Thrown when the MPT account proof returns an empty RLP result.
error EmptyAccountProof();

/// @dev Thrown when the RLP-decoded account does not have exactly 4 fields.
error InvalidAccountFields();

/// @dev Thrown when a decoded storage value exceeds 32 bytes.
error StorageValueTooLarge();

/// @dev Thrown when a block header has fewer fields than required.
error InvalidBlockHeader();

/// @dev Thrown when the number of commitments exceeds uint16 max.
error TooManyCommits();

/// @dev Thrown when a Wormhole payload is shorter than the header size.
error PayloadTooShort();

/// @dev Thrown when a Wormhole payload has an unsupported version byte.
error UnsupportedPayloadVersion();

/// @dev Thrown when a Wormhole payload has an unknown action byte.
error UnknownPayloadAction();

/// @dev Thrown when the adapter index is out of bounds.
error InvalidAdapterIndex();

/// @dev Thrown when an unsupported operation is invoked on a context.
error UnsupportedOperation();

/// @dev Thrown when the keccakChain slot check fails during construction.
error InvalidChainSlot();
