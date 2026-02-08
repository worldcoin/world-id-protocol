// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IMptStorageProofAdapter} from "./IMptStorageProofAdapter.sol";

/// @title IL2StorageProofAdapter
/// @author World Contributors
/// @notice Extends `IMptStorageProofAdapter` for OP Stack L2s that can verify World Chain
///   storage proofs locally using the `L1Block` contract (`0x4200000000000000000000000000000000000015`).
/// @dev Inherits from `IMptStorageProofAdapter` so that the standard dispute-game-level MPT
///   proof verification can be reused. This interface adds an L1 block header verification
///   prefix — anchoring the proof chain to the L1 block hash exposed by the `L1Block` predeploy.
///
///   The full proof chain is two layers deep:
///
///   L1 block hash  (from L1Block contract on L2)
///     -> L1 state root  (RLP-decode L1 block header)
///       -> DisputeGameFactory storage  (L1 account + storage proof)
///         -> output root / rootClaim
///           -> World Chain state root  (output root preimage)
///             -> Registry storage  (L2 account + storage proofs)
///               -> root, timestamp, treeDepth, pubkeys
interface IL2StorageProofAdapter is IMptStorageProofAdapter {
    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    /// @dev Thrown when the provided L1 block header hash does not match the L1 block hash
    ///   from the `L1Block` predeploy.
    error InvalidL1BlockHash();

    /// @dev Thrown when RLP decoding of the L1 block header fails.
    error InvalidL1BlockHeader();

    /// @dev Thrown when the L1 account proof for the `DisputeGameFactory` fails verification.
    error InvalidL1AccountProof();

    /// @dev Thrown when the L1 storage proof for the dispute game entry fails verification.
    error InvalidL1GameStorageProof();

    ////////////////////////////////////////////////////////////
    //                   PROOF FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /// @notice Proves the latest Merkle root, its timestamp, and tree depth from World Chain
    ///   via a two-layer MPT proof anchored to the L1 block hash from the `L1Block` contract.
    /// @dev Verification flow:
    ///   1. Hash `l1BlockHeader` and verify it matches the `L1Block` predeploy's block hash.
    ///   2. RLP-decode the L1 block header to extract the L1 state root.
    ///   3. Verify `l1AccountProof` to obtain the `DisputeGameFactory` storage root on L1.
    ///   4. Verify `l1GameStorageProof` to extract the dispute game's `rootClaim`.
    ///   5. Verify `outputRootPreimage` against the `rootClaim` to extract the L2 state root.
    ///   6. Verify `l2AccountProof` to obtain the `WorldIDRegistry` storage root on L2.
    ///   7. Verify the three L2 storage proofs to extract root timestamp, latest root, and
    ///      tree depth — reusing the inherited `IMptStorageProofAdapter` verification logic.
    /// @param l1BlockHeader The RLP-encoded L1 block header. Its hash must match the L1 block
    ///   hash from the `L1Block` predeploy.
    /// @param l1AccountProof The MPT account proof for the `DisputeGameFactory` on L1, verified
    ///   against the L1 state root.
    /// @param l1GameStorageProof The MPT storage proof for the dispute game entry in the
    ///   `DisputeGameFactory`.
    /// @param outputRootPreimage The preimage components of the output root, verified against
    ///   the game's `rootClaim()`.
    /// @param l2AccountProof The MPT account proof for the `WorldIDRegistry` on World Chain,
    ///   verified against the L2 state root from the output root.
    /// @param rootTimestampProof The MPT storage proof for the root's timestamp in the
    ///   `WorldIDRegistry` `rootTimestamps` mapping.
    /// @param latestRootProof The MPT storage proof for the `latestRoot` storage slot.
    /// @param treeDepthProof The MPT storage proof for the `treeDepth` storage slot.
    function proveRoot(
        bytes calldata l1BlockHeader,
        bytes[] calldata l1AccountProof,
        bytes[] calldata l1GameStorageProof,
        bytes calldata outputRootPreimage,
        bytes[] calldata l2AccountProof,
        bytes[] calldata rootTimestampProof,
        bytes[] calldata latestRootProof,
        bytes[] calldata treeDepthProof
    ) external;

    /// @notice Proves a credential issuer public key from World Chain via a two-layer MPT
    ///   proof anchored to the L1 block hash from the `L1Block` contract.
    /// @dev Follows the same L1 verification prefix as `proveRoot`, then verifies L2 storage
    ///   proofs for the x and y coordinates of the issuer public key — reusing the inherited
    ///   `IMptStorageProofAdapter` verification logic for the sub-layers.
    /// @param issuerSchemaId The unique identifier for the credential schema and issuer pair.
    /// @param l1BlockHeader The RLP-encoded L1 block header.
    /// @param l1AccountProof The MPT account proof for the `DisputeGameFactory` on L1.
    /// @param l1GameStorageProof The MPT storage proof for the dispute game entry.
    /// @param outputRootPreimage The preimage components of the output root.
    /// @param l2AccountProof The MPT account proof for the `CredentialSchemaIssuerRegistry`
    ///   on World Chain.
    /// @param storageProofX The MPT storage proof for the x-coordinate of the issuer public key.
    /// @param storageProofY The MPT storage proof for the y-coordinate of the issuer public key.
    function proveIssuerPubkey(
        uint64 issuerSchemaId,
        bytes calldata l1BlockHeader,
        bytes[] calldata l1AccountProof,
        bytes[] calldata l1GameStorageProof,
        bytes calldata outputRootPreimage,
        bytes[] calldata l2AccountProof,
        bytes[] calldata storageProofX,
        bytes[] calldata storageProofY
    ) external;

    /// @notice Proves an OPRF public key from World Chain via a two-layer MPT proof anchored
    ///   to the L1 block hash from the `L1Block` contract.
    /// @dev Follows the same L1 verification prefix as `proveRoot`, then verifies L2 storage
    ///   proofs for the x and y coordinates of the OPRF key — reusing the inherited
    ///   `IMptStorageProofAdapter` verification logic for the sub-layers.
    /// @param oprfKeyId The unique identifier for the OPRF key.
    /// @param l1BlockHeader The RLP-encoded L1 block header.
    /// @param l1AccountProof The MPT account proof for the `DisputeGameFactory` on L1.
    /// @param l1GameStorageProof The MPT storage proof for the dispute game entry.
    /// @param outputRootPreimage The preimage components of the output root.
    /// @param l2AccountProof The MPT account proof for the `OprfKeyRegistry` on World Chain.
    /// @param storageProofX The MPT storage proof for the x-coordinate of the OPRF key.
    /// @param storageProofY The MPT storage proof for the y-coordinate of the OPRF key.
    function proveOprfKey(
        uint160 oprfKeyId,
        bytes calldata l1BlockHeader,
        bytes[] calldata l1AccountProof,
        bytes[] calldata l1GameStorageProof,
        bytes calldata outputRootPreimage,
        bytes[] calldata l2AccountProof,
        bytes[] calldata storageProofX,
        bytes[] calldata storageProofY
    ) external;
}
