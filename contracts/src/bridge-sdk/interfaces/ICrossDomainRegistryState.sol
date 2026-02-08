// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title ICrossDomainRegistryState
/// @author World Contributors
/// @notice Unified read interface over World ID registry state.
/// @dev Every source in the state bridge protocol exposes these five getters — whether it reads
///   from live on-chain registries (World Chain), an MPT-proven cache (Ethereum L1), or bridged
///   state (any destination chain). This is the polymorphic seam that connects the source,
///   dispatch, and digest layers of the protocol.
interface ICrossDomainRegistryState {
    /// @notice Returns the timestamp at which a given Merkle root was recorded in the
    ///   `WorldIDRegistry`.
    /// @param root The Merkle root to query.
    /// @return The Unix timestamp when `root` was recorded. Returns 0 if the root is unknown.
    function getRootTimestamp(uint256 root) external view returns (uint256);

    /// @notice Returns the most recently recorded Merkle root.
    /// @return The latest root from the `WorldIDRegistry`.
    function getLatestRoot() external view returns (uint256);

    /// @notice Returns the credential issuer public key for a given issuer-schema pair.
    /// @dev The public key is an elliptic curve point used to verify credential signatures inside
    ///   World ID zero-knowledge proofs.
    /// @param issuerSchemaId The unique identifier for the credential schema and issuer pair,
    ///   as registered in the `CredentialSchemaIssuerRegistry`.
    /// @return x The x-coordinate of the issuer public key.
    /// @return y The y-coordinate of the issuer public key.
    function issuerPubkey(uint64 issuerSchemaId) external view returns (uint256 x, uint256 y);

    /// @notice Returns the OPRF public key for a given OPRF key identifier.
    /// @dev The OPRF key is used in the oblivious pseudorandom function protocol that preserves
    ///   biometric privacy during World ID proof generation.
    /// @param oprfKeyId The unique identifier for the OPRF key, as registered in the
    ///   `OprfKeyRegistry`.
    /// @return x The x-coordinate of the OPRF public key.
    /// @return y The y-coordinate of the OPRF public key.
    function oprfKey(uint160 oprfKeyId) external view returns (uint256 x, uint256 y);

    /// @notice Returns the time window (in seconds) during which a Merkle root remains valid
    ///   after being recorded.
    /// @return The root validity window in seconds.
    function rootValidityWindow() external view returns (uint256);
}
