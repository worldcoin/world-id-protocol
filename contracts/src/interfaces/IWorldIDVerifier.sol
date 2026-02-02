// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title IWorldIDVerifier
 * @author World Contributors
 * @notice Interface for verifying nullifier proofs for World ID credentials
 * @dev Coordinates verification between the World ID registry, the credential schema issuer registry, and the OPRF key registry
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
     * @notice Emitted when the proof timestamp delta is updated.
     * @param oldProofTimestampDelta The previous proof timestamp delta value.
     * @param newProofTimestampDelta The new proof timestamp delta value.
     */
    event ProofTimestampDeltaUpdated(uint64 oldProofTimestampDelta, uint64 newProofTimestampDelta);

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Verifies a Uniqueness Proof.
     * @dev Validates the World ID registration and inclusion, credential issuer registration,
     *   and delegates to the Groth16 proof verifier for proof verification.
     * @param nullifier The nullifier hash to verify uniqueness.
     * @param action The action identifier.
     * @param rpId The relying party identifier.
     * @param nonce The nonce used in the proof.
     * @param signalHash The hash of the signal which was committed in the proof.
     * @param expiresAtMin The minimum expiration required for the Credential used in the proof. If the constraint is not required,
     *   it should use the current time as the minimum expiration. The Authenticator will normally expose the effective input used in the proof.
     * @param issuerSchemaId The ID of the credential issuer.
     * @param credentialGenesisIssuedAtMin The minimum timestamp for when the credential was initially issued. Set to 0 to skip.
     * @param zeroKnowledgeProof The encoded Zero Knowledge Proof (first 4 elements represent a compressed Groth16 proof [a, b, b, c]
     *   and the last element the Merkle Root of the tree in WorldIDRegistry.
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
     * @param rpId The relying party identifier.
     * @param nonce The nonce used in the proof.
     * @param signalHash The hash of the signal which was committed in the proof.
     * @param expiresAtMin The minimum expiration required for the Credential used in the proof. If the constraint is not required,
     *   it should use the current time as the minimum expiration. The Authenticator will normally expose the effective input used in the proof.
     * @param issuerSchemaId The ID of the credential issuer.
     * @param credentialGenesisIssuedAtMin The minimum timestamp for when the credential was initially issued. Set to 0 to skip.
     * @param sessionId The ID of the session.
     * @param sessionNullifier The nullifier explicitly encoded for Session Proofs. @dev: This encodes the raw `nullifier` (index 0) and the
     *   randomly generated `action` (index 1).
     * @param zeroKnowledgeProof The encoded Zero Knowledge Proof (first 4 elements represent a compressed Groth16 proof [a, b, b, c]
     *   and the last element the Merkle Root of the tree in WorldIDRegistry.
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
     * @notice Updates the proof timestamp delta
     * @param _proofTimestampDelta The new proof timestamp delta value in seconds.
     */
    function updateProofTimestampDelta(uint64 _proofTimestampDelta) external;
}
