//! Solidity contract bindings for the World ID Protocol.
//!
//! This module provides auto-generated Rust bindings for the on-chain World ID
//! contracts via [`alloy::sol!`]. The bindings include full RPC support so
//! callers can interact with deployed contracts directly.
//!
//! # Example
//!
//! ```rust,ignore
//! use world_id_core::contracts::IWorldIDVerifier;
//!
//! // Build a call to the on-chain verifier
//! let contract = IWorldIDVerifier::new(address, provider);
//! let result = contract.verify(nullifier, action, rp_id, nonce, signal_hash,
//!     expires_at_min, issuer_schema_id, credential_genesis_issued_at_min,
//!     zero_knowledge_proof).call().await?;
//! ```

alloy::sol! {
    /// Bindings for the `IWorldIDVerifier` interface.
    ///
    /// See [`contracts/src/core/interfaces/IWorldIDVerifier.sol`](https://github.com/worldcoin/world-id-protocol/blob/main/contracts/src/core/interfaces/IWorldIDVerifier.sol)
    /// for the canonical Solidity source.
    #[sol(rpc)]
    #[derive(Debug)]
    interface IWorldIDVerifier {
        error ExpirationTooOld();
        error InvalidMerkleRoot();
        error UnregisteredIssuerSchemaId();

        event CredentialSchemaIssuerRegistryUpdated(
            address oldCredentialSchemaIssuerRegistry,
            address newCredentialSchemaIssuerRegistry
        );
        event WorldIDRegistryUpdated(address oldWorldIDRegistry, address newWorldIDRegistry);
        event OprfKeyRegistryUpdated(address oldOprfKeyRegistry, address newOprfKeyRegistry);
        event VerifierUpdated(address oldVerifier, address newVerifier);
        event MinExpirationThresholdUpdated(
            uint64 oldMinExpirationThreshold,
            uint64 newMinExpirationThreshold
        );

        function verify(
            uint256 nullifier,
            uint256 action,
            uint64 rpId,
            uint256 nonce,
            uint256 signalHash,
            uint64 expiresAtMin,
            uint64 issuerSchemaId,
            uint256 credentialGenesisIssuedAtMin,
            uint256[5] calldata zeroKnowledgeProof
        ) external view;

        function verifySession(
            uint64 rpId,
            uint256 nonce,
            uint256 signalHash,
            uint64 expiresAtMin,
            uint64 issuerSchemaId,
            uint256 credentialGenesisIssuedAtMin,
            uint256 sessionId,
            uint256[2] calldata sessionNullifier,
            uint256[5] calldata zeroKnowledgeProof
        ) external view;

        function verifyProofAndSignals(
            uint256 nullifier,
            uint256 action,
            uint64 rpId,
            uint256 nonce,
            uint256 signalHash,
            uint64 expiresAtMin,
            uint64 issuerSchemaId,
            uint256 credentialGenesisIssuedAtMin,
            uint256 sessionId,
            uint256[5] calldata zeroKnowledgeProof
        ) external view;

        function updateCredentialSchemaIssuerRegistry(
            address newCredentialSchemaIssuerRegistry
        ) external;
        function updateWorldIDRegistry(address newWorldIDRegistry) external;
        function updateOprfKeyRegistry(address newOprfKeyRegistry) external;
        function updateVerifier(address newVerifier) external;
        function updateMinExpirationThreshold(uint64 newMinExpirationThreshold) external;

        function getCredentialSchemaIssuerRegistry() external view returns (address);
        function getWorldIDRegistry() external view returns (address);
        function getOprfKeyRegistry() external view returns (address);
        function getVerifier() external view returns (address);
        function getMinExpirationThreshold() external view returns (uint256);
        function getTreeDepth() external view returns (uint256);
    }
}
