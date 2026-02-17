// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Thrown when no chained commits are provided.
error EmptyChainedCommits();

/// @notice Thrown when a chained commit has an unknown action type.
error UnknownAction(uint8 action);

/// @notice Thrown when the keccakChain slot check fails during construction.
error InvalidChainSlot();

/// @notice Thrown when propagateState is called but no state has changed.
error NothingChanged();

/// @notice Thrown when a zero address is provided where one is not allowed.
error ZeroAddress();

/**
 * @dev Thrown when the credential minimum expiration constraint is too old. A new proof should be requested with a fresher expiration.
 */
error ExpirationTooOld();

/**
 * @dev Thrown when the provided Merkle root is not valid in the `WorldIDRegistry`.
 */
error InvalidMerkleRoot();

/**
 * @dev Thrown when the credential issuer schema ID is not registered in the `CredentialSchemaIssuerRegistry`.
 */
error UnregisteredIssuerSchemaId();

/// @dev Thrown when the OPRF key ID has not been bridged (pubkey is zero).
error UnregisteredOprfKeyId();

/// @dev Thrown when the recipient does not return the expected ERC-7786 magic value.
error InvalidRecipientResponse();

/// @dev Thrown when the recipient address does not match the configured bridge.
error InvalidRecipient();

/// @dev Thrown when no commitments are provided in the payload.
error EmptyPayload();

/// @dev Thrown when ETH is sent to a function that does not accept it.
error UnexpectedETH();

/// @dev Thrown when a required attribute is missing.
error InvalidAttribute();

/// @dev Thrown when an attribute with an unrecognized selector is provided.
error UnsupportedAttribute(bytes4 selector);

/// @dev Thrown when an attribute with an unrecognized selector is provided.
error InvalidAttributes();

/// @dev Thrown when the proof's sync committee root doesn't match the stored root for that period.
error InvalidSyncCommitteeRoot();

/// @dev Thrown when the output root preimage does not match the dispute game's root claim.
error InvalidOutputRoot();

/// @dev Thrown when the dispute game has not resolved in favor of the defender.
error GameNotFinalized();

/// @dev Thrown when the proven slot is not newer than the current head.
error SlotBehindHead();

/// @dev Thrown when the proven slot is not a checkpoint slot (multiple of 32).
error NonCheckpointSlot();

/// @dev Thrown when the sync committee hash for the current period is not set.
error SyncCommitteeNotSet();

/// @dev Thrown when the next sync committee hash conflicts with an already-set value.
error NextSyncCommitteeMismatch();

/// @notice Thrown when a commitment's 4-byte action selector does not match any known handler
///   (`updateRoot`, `setIssuerPubkey`, `setOprfKey`).
/// @param selector The unrecognized selector from the commitment data.
error InvalidCommitmentSelector(bytes4 selector);

/// @dev Thrown when an account proof is empty (account does not exist in the state) during MPT verification.
error EmptyAccountProof();

///@dev Thrown when an account proof's RLP fields do not match the expected count during MPT verification.
error InvalidAccountField();

/// @dev Thrown when a storage proof's decoded value exceeds the maximum byte length that can be safely cast to bytes32.
error StorageValueTooLarge();

/// @dev Thrown when the proven chain head does not match the expected keccak chain head.
error InvalidChainHead();

error InvalidContractName();

error InvalidContractVersion();
