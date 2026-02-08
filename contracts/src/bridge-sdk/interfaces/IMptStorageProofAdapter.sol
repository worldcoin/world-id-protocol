// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ICrossDomainRegistryState} from "./ICrossDomainRegistryState.sol";

/// @title IMptStorageProofAdapter
/// @author World Contributors
/// @notice Extends `ICrossDomainRegistryState` for chains that can verify World Chain storage
///   via MPT proofs against the `DisputeGameFactory` (e.g. Ethereum L1).
/// @dev Proves World Chain storage slots by verifying a chain of MPT proofs:
///   1. Look up the dispute game by index from `DisputeGameFactory`.
///   2. Validate that the output root meets acceptance criteria (implementor-defined).
///   3. Verify the output root preimage against the game's `rootClaim()`.
///   4. Verify the MPT account proof: L2 state root -> target contract's storage root.
///   5. Verify storage proofs against the storage root to extract slot values.
///   6. Deliver proven values to the verifier atomically.
///
///   The `proofId` for MPT storage proofs is derived from the dispute game address, enabling
///   retroactive invalidation if the game resolves `CHALLENGER_WINS`.
interface IMptStorageProofAdapter is ICrossDomainRegistryState {
    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    /// @dev Thrown when the dispute game index is invalid or does not exist.
    error InvalidDisputeGameIndex();

    /// @dev Thrown when the output root fails acceptance criteria.
    error InvalidOutputRoot();

    /// @dev Thrown when the output root preimage does not match the game's `rootClaim()`.
    error InvalidOutputRootPreimage();

    /// @dev Thrown when the MPT account proof verification fails.
    error InvalidAccountProof();

    /// @dev Thrown when a storage proof verification fails.
    error InvalidStorageProof();

    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
    ////////////////////////////////////////////////////////////

    /// @notice Emitted when a Merkle root is successfully proven via storage proofs.
    /// @param root The proven Merkle root.
    /// @param timestamp The World Chain timestamp when the root was recorded.
    /// @param treeDepth The depth of the Merkle tree at the time of the proof.
    /// @param proofId The opaque proof identifier derived from the dispute game.
    event RootProven(uint256 indexed root, uint256 timestamp, uint256 treeDepth, bytes32 proofId);

    /// @notice Emitted when an issuer public key is successfully proven via storage proofs.
    /// @param issuerSchemaId The credential schema and issuer pair identifier.
    /// @param x The x-coordinate of the proven public key.
    /// @param y The y-coordinate of the proven public key.
    /// @param proofId The opaque proof identifier derived from the dispute game.
    event IssuerPubkeyProven(uint64 indexed issuerSchemaId, uint256 x, uint256 y, bytes32 proofId);

    /// @notice Emitted when an OPRF key is successfully proven via storage proofs.
    /// @param oprfKeyId The OPRF key identifier.
    /// @param x The x-coordinate of the proven OPRF key.
    /// @param y The y-coordinate of the proven OPRF key.
    /// @param proofId The opaque proof identifier derived from the dispute game.
    event OprfKeyProven(uint160 indexed oprfKeyId, uint256 x, uint256 y, bytes32 proofId);

    ////////////////////////////////////////////////////////////
    //                   PROOF FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /// @notice Proves the latest Merkle root, its timestamp, and tree depth from World Chain
    ///   storage via MPT proofs against a dispute game output root.
    /// @dev Verifies the output root preimage, account proof, and three separate storage proofs
    ///   (root timestamp mapping, latest root slot, and tree depth slot), then delivers the
    ///   proven values to the verifier atomically.
    /// @param disputeGameIndex The index of the dispute game in the `DisputeGameFactory`.
    /// @param outputRootProof The RLP-encoded proof components for the output root preimage
    ///   verification against the game's `rootClaim()`.
    /// @param accountProof The MPT account proof verifying the World Chain registry contract's
    ///   storage root against the L2 state root extracted from the output root.
    /// @param rootTimestampProof The MPT storage proof for the root's timestamp in the
    ///   `WorldIDRegistry` `rootTimestamps` mapping.
    /// @param latestRootProof The MPT storage proof for the `latestRoot` storage slot in the
    ///   `WorldIDRegistry`.
    /// @param treeDepthProof The MPT storage proof for the `treeDepth` storage slot in the
    ///   `WorldIDRegistry`.
    function proveRoot(
        uint256 disputeGameIndex,
        bytes[4] calldata outputRootProof,
        bytes[] calldata accountProof,
        bytes[] calldata rootTimestampProof,
        bytes[] calldata latestRootProof,
        bytes[] calldata treeDepthProof
    ) external;

    /// @notice Proves a credential issuer public key from World Chain storage via MPT proofs
    ///   against a dispute game output root.
    /// @dev Verifies the output root preimage, account proof, and two storage proofs (one for
    ///   each coordinate of the public key), then delivers the proven key to the verifier.
    /// @param issuerSchemaId The unique identifier for the credential schema and issuer pair.
    /// @param disputeGameIndex The index of the dispute game in the `DisputeGameFactory`.
    /// @param outputRootProof The RLP-encoded proof components for the output root preimage
    ///   verification against the game's `rootClaim()`.
    /// @param accountProof The MPT account proof verifying the
    ///   `CredentialSchemaIssuerRegistry` contract's storage root against the L2 state root.
    /// @param storageProofX The MPT storage proof for the x-coordinate of the issuer public key.
    /// @param storageProofY The MPT storage proof for the y-coordinate of the issuer public key.
    function proveIssuerPubkey(
        uint64 issuerSchemaId,
        uint256 disputeGameIndex,
        bytes[4] calldata outputRootProof,
        bytes[] calldata accountProof,
        bytes[] calldata storageProofX,
        bytes[] calldata storageProofY
    ) external;

    /// @notice Proves an OPRF public key from World Chain storage via MPT proofs against a
    ///   dispute game output root.
    /// @dev Verifies the output root preimage, account proof, and two storage proofs (one for
    ///   each coordinate of the OPRF key), then delivers the proven key to the verifier.
    /// @param oprfKeyId The unique identifier for the OPRF key.
    /// @param disputeGameIndex The index of the dispute game in the `DisputeGameFactory`.
    /// @param outputRootProof The RLP-encoded proof components for the output root preimage
    ///   verification against the game's `rootClaim()`.
    /// @param accountProof The MPT account proof verifying the `OprfKeyRegistry` contract's
    ///   storage root against the L2 state root.
    /// @param storageProofX The MPT storage proof for the x-coordinate of the OPRF key.
    /// @param storageProofY The MPT storage proof for the y-coordinate of the OPRF key.
    function proveOprfKey(
        uint160 oprfKeyId,
        uint256 disputeGameIndex,
        bytes[4] calldata outputRootProof,
        bytes[] calldata accountProof,
        bytes[] calldata storageProofX,
        bytes[] calldata storageProofY
    ) external;
}
