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
     * @dev Thrown when the proof timestamp is too old, exceeding the allowed proof timestamp delta.
     */
    error OutdatedNullifier();

    /**
     * @dev Thrown when the proof timestamp is in the future (greater than the current block timestamp).
     */
    error NullifierFromFuture();

    /**
     * @dev Thrown when the provided authenticator root is not valid in the World ID registry.
     */
    error InvalidMerkleRoot();

    /**
     * @dev Thrown when the credential issuer schema ID is not registered in the credential schema issuer registry.
     */
    error UnregisteredIssuerSchemaId();

    /**
     * @dev Thrown when setting an external contract address to the zero address.
     */
    error ZeroAddress();

    /**
     * @dev Thrown when the implementation has not been initialized via proxy.
     */
    error ImplementationNotInitialized();

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
    event ProofTimestampDeltaUpdated(uint256 oldProofTimestampDelta, uint256 newProofTimestampDelta);

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Verifies a Uniqueness Proof for a specific World ID.
     * @dev Validates the authenticator root, credential issuer registration, and delegates to the nullifier verifier for proof verification.
     * @param nullifier The nullifier hash to verify uniqueness.
     * @param action The action identifier.
     * @param rpId The relying party identifier.
     * @param sessionId The identifier for a specific RP-specific session.
     * @param nonce The nonce used in the proof.
     * @param signalHash The hash of the signal which was committed in the proof.
     * @param authenticatorRoot The merkle root of the authenticator set.
     * @param proofTimestamp The timestamp when the proof was generated.
     * @param credentialIssuerId The ID of the credential issuer.
     * @param credentialGenesisIssuedAtMin The minimum timestamp for when the credential was initially issued. Set to 0 to skip.
     * @param compressedProof The compressed Groth16 proof.
     */
    function verify(
        uint256 nullifier,
        uint256 action,
        uint64 rpId,
        uint256 sessionId,
        uint256 nonce,
        uint256 signalHash,
        uint256 authenticatorRoot,
        uint256 proofTimestamp,
        uint64 credentialIssuerId,
        uint256 credentialGenesisIssuedAtMin,
        uint256[4] calldata compressedProof
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
    function updateProofTimestampDelta(uint256 _proofTimestampDelta) external;
}
