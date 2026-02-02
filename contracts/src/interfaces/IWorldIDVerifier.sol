// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title IWorldIDVerifier
 * @author World Contributors
 * @notice Interface for verifying World ID proofs (Uniqueness and Session proofs).
 * @dev In addition to verifying the Groth16 Proof, it verifies relevant public inputs to the
 *  circuits through checks with the WorldIDRegistry, CredentialSchemaIssuerRegistry, and OprfKeyRegistry.
 */
interface IWorldIDVerifier {
    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

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

    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Emitted when the credential schema issuer registry is updated.
     * @param oldCredentialSchemaIssuerRegistry The previous registry address.
     * @param newCredentialSchemaIssuerRegistry The new registry address.
     */
    event CredentialSchemaIssuerRegistryUpdated(
        address oldCredentialSchemaIssuerRegistry, address newCredentialSchemaIssuerRegistry
    );

    /**
     * @notice Emitted when the World ID Registry is updated.
     * @param oldWorldIDRegistry The previous registry address.
     * @param newWorldIDRegistry The new registry address.
     */
    event WorldIDRegistryUpdated(address oldWorldIDRegistry, address newWorldIDRegistry);

    /**
     * @notice Emitted when the OPRF key registry is updated.
     * @param oldOprfKeyRegistry The previous registry address.
     * @param newOprfKeyRegistry The new registry address.
     */
    event OprfKeyRegistryUpdated(address oldOprfKeyRegistry, address newOprfKeyRegistry);

    /**
     * @notice Emitted when the verifier is updated.
     * @param oldVerifier The previous verifier address.
     * @param newVerifier The new verifier address.
     */
    event VerifierUpdated(address oldVerifier, address newVerifier);

    /**
     * @notice Emitted when the minimum expiration threshold is updated.
     * @param oldMinExpirationThreshold The previous minimum expiration threshold value.
     * @param newMinExpirationThreshold The new minimum expiration threshold value.
     */
    event MinExpirationThresholdUpdated(uint64 oldMinExpirationThreshold, uint64 newMinExpirationThreshold);

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Verifies a Uniqueness Proof.
     * @dev Validates the World ID registration and inclusion, credential issuer registration,
     *   and delegates to the Groth16 proof verifier for proof verification.
     * @param nullifier <description>
     * @param action Raw field element bound into the proof. When using strings or bytes, hash with keccak256 and reduce to field.
     * @param rpId Registered RP identifier from the RpRegistry.
     * @param nonce Unique nonce for this request provided by the RP.
     * @param signalHash Hash of the optional RP-defined signal bound into the proof.
     * @param expiresAtMin The minimum expiration required for the Credential used in the proof. If the constraint is not required,
     *   it should use the current time as the minimum expiration. The Authenticator will normally expose the effective input used in the proof.
     * @param issuerSchemaId Unique identifier for the credential schema and issuer pair.
     * @param credentialGenesisIssuedAtMin Minimum genesis_issued_at timestamp constraint. Set to 0 to skip.
     * @param zeroKnowledgeProof Encoded proof: first 4 elements are compressed Groth16 proof [a, b, b, c],
     *   last element is the Merkle root from WorldIDRegistry.
     */
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

    /**
     * @notice Verifies a Session Proof.
     * @dev Validates the World ID registration and inclusion, credential issuer registration,
     *   and delegates to the Groth16 proof verifier for proof verification.
     * @param rpId Registered RP identifier.
     * @param nonce Unique nonce for this request.
     * @param signalHash Hash of the optional RP-defined signal bound into the proof.
     * @param expiresAtMin The minimum expiration required for the Credential used in the proof. If the constraint is not required,
     *   it should use the current time as the minimum expiration. The Authenticator will normally expose the effective input used in the proof.
     * @param issuerSchemaId Unique identifier for the credential schema and issuer pair.
     * @param credentialGenesisIssuedAtMin Minimum genesis_issued_at timestamp constraint. Set to 0 to skip.
     * @param sessionId Session identifier that links proofs for the same user/RP pair across requests.
     * @param sessionNullifier Session nullifier: index 0 is the nullifier, index 1 is the randomly generated action.
     * @param zeroKnowledgeProof Encoded proof: first 4 elements are compressed Groth16 proof [a, b, b, c],
     *   last element is the Merkle root from WorldIDRegistry.
     */
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

    /*
    * @notice Verifies a World ID Proof and the relevant public signals. This method can be used
    *   to verify any type of World ID Proof and requires explicit inputs. Using `verify` or `verifySession` is
    *   recommended for most use cases.
    */
    function _verifyProofAndSignals(
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

    ////////////////////////////////////////////////////////////
    //                    OWNER FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Updates the credential schema issuer registry address.
     * @param _credentialSchemaIssuerRegistry The new credential schema issuer registry address.
     */
    function updateCredentialSchemaIssuerRegistry(address _credentialSchemaIssuerRegistry) external;

    /**
     * @notice Updates the World ID registry address.
     * @param _worldIDRegistry The new World ID registry address.
     */
    function updateWorldIDRegistry(address _worldIDRegistry) external;

    /**
     * @notice Updates the OPRF key registry address.
     * @param _oprfKeyRegistry The new OPRF key registry address.
     */
    function updateOprfKeyRegistry(address _oprfKeyRegistry) external;

    /**
     * @notice Updates the Verifier address.
     * @param _verifier The new verifier address.
     */
    function updateVerifier(address _verifier) external;

    /**
     * @notice Updates the proof timestamp delta.
     * @param _proofTimestampDelta The new proof timestamp delta value in seconds.
     */
    function updateProofTimestampDelta(uint256 _proofTimestampDelta) external;

    /**
     * @notice Returns the credential schema issuer registry address.
     * @return The address of the CredentialSchemaIssuerRegistry contract.
     */
    function getCredentialSchemaIssuerRegistry() external view returns (address);

    /**
     * @notice Returns the World ID registry address.
     * @return The address of the WorldIDRegistry contract.
     */
    function getWorldIDRegistry() external view returns (address);

    /**
     * @notice Returns the OPRF key registry address.
     * @return The address of the OprfKeyRegistry contract.
     */
    function getOprfKeyRegistry() external view returns (address);

    /**
     * @notice Returns the verifier contract address.
     * @return The address of the Verifier contract.
     */
    function getVerifier() external view returns (address);

    /**
     * @notice Returns the proof timestamp delta.
     * @return The allowed delta for proof timestamps (seconds).
     */
    function getProofTimestampDelta() external view returns (uint256);

    /**
     * @notice Returns the tree depth.
     * @return The depth of the Merkle tree in WorldIDRegistry.
     */
    function getTreeDepth() external view returns (uint256);
}
