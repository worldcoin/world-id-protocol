// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title ICredentialSchemaIssuerRegistry
 * @author World Contributors
 * @notice Interface for the Credential Schema Issuer Registry contract.
 * @dev An `issuerSchemaId` represents the unique combination of a specific schema (e.g. ICAO 9303 Passport)
 *   from a specific issuer (e.g. TFH). This ID is included in each issued Credential.
 */
interface ICredentialSchemaIssuerRegistry {
    ////////////////////////////////////////////////////////////
    //                        STRUCTS                         //
    ////////////////////////////////////////////////////////////

    struct Pubkey {
        uint256 x;
        uint256 y;
    }

    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Thrown when trying to update the schema URI to the same as the current one.
     */
    error SchemaUriIsTheSameAsCurrentOne();

    /**
     * @dev Thrown when the provided signature is invalid for the operation.
     */
    error InvalidSignature();

    /**
     * @dev Thrown when the provided pubkey is invalid (for example if either coordinate is zero).
     */
    error InvalidPubkey();

    /**
     * @dev Thrown when an invalid signer is provided (e.g. zero address)
     */
    error InvalidSigner();

    /**
     * @dev Thrown when an issuerSchemaId is not registered
     */
    error IdNotRegistered();

    /**
     * @dev Thrown when trying to update signer to the same address that's already assigned
     */
    error SignerAlreadyAssigned();

    /**
     * @dev Thrown when the provided issuerSchemaId is invalid
     */
    error InvalidIssuerSchemaId();

    /**
     * @dev Thrown when the requested id to be registered is already in use. ids must be unique and unique in the OprfKeyRegistry too.
     */
    error IdAlreadyInUse(uint64 id);

    /**
     * @dev Thrown when the passed id is invalid for the operation. Usually this means the `id` used is equal to `0` which is not allowed.
     */
    error InvalidId();

    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Emitted when a new issuer-schema pair is registered.
     * @param issuerSchemaId The unique identifier assigned to the issuer-schema pair.
     * @param pubkey The off-chain public key that will sign credentials.
     * @param signer The on-chain address authorized to perform updates.
     * @param oprfKeyId The OPRF key identifier for the issuer-schema pair.
     */
    event IssuerSchemaRegistered(uint64 indexed issuerSchemaId, Pubkey pubkey, address signer, uint160 oprfKeyId);

    /**
     * @dev Emitted when an issuer-schema pair is removed from the registry.
     * @param issuerSchemaId The unique identifier of the removed issuer-schema pair.
     * @param pubkey The off-chain public key that was associated with the pair.
     * @param signer The on-chain address that was authorized to perform updates.
     */
    event IssuerSchemaRemoved(uint64 indexed issuerSchemaId, Pubkey pubkey, address signer);

    /**
     * @dev Emitted when the off-chain public key for an issuer-schema pair is updated.
     * @param issuerSchemaId The unique identifier of the issuer-schema pair.
     * @param oldPubkey The previous off-chain public key.
     * @param newPubkey The new off-chain public key.
     */
    event IssuerSchemaPubkeyUpdated(uint64 indexed issuerSchemaId, Pubkey oldPubkey, Pubkey newPubkey);

    /**
     * @dev Emitted when the on-chain signer address for an issuer-schema pair is updated.
     * @param issuerSchemaId The unique identifier of the issuer-schema pair.
     * @param oldSigner The previous on-chain signer address.
     * @param newSigner The new on-chain signer address.
     */
    event IssuerSchemaSignerUpdated(uint64 indexed issuerSchemaId, address oldSigner, address newSigner);

    /**
     * @dev Emitted when the schema URI for an issuer-schema pair is updated.
     * @param issuerSchemaId The unique identifier of the issuer-schema pair.
     * @param oldSchemaUri The previous schema URI.
     * @param newSchemaUri The new schema URI.
     */
    event IssuerSchemaUpdated(uint64 indexed issuerSchemaId, string oldSchemaUri, string newSchemaUri);

    /**
     * @notice Emitted when the OPRF key registry is updated.
     * @param oldOprfKeyRegistry The previous registry address.
     * @param newOprfKeyRegistry The new registry address.
     */
    event OprfKeyRegistryUpdated(address oldOprfKeyRegistry, address newOprfKeyRegistry);

    ////////////////////////////////////////////////////////////
    //                   PUBLIC FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Registers a new credential schema issuer pair.
     * @param issuerSchemaId The unique identifier for this issuer-schema pair.
     * @param pubkey The off-chain public key that will sign credentials for this issuer-schema pair.
     * @param signer The on-chain address authorized to perform updates for this issuer-schema pair.
     * @return The unique identifier assigned to this issuer-schema pair.
     */
    function register(uint64 issuerSchemaId, Pubkey memory pubkey, address signer) external returns (uint256);

    /**
     * @dev Removes a registered issuer-schema pair. Must be signed by the authorized signer.
     * @param issuerSchemaId The issuer-schema ID to remove.
     * @param signature The signature authorizing the removal.
     */
    function remove(uint64 issuerSchemaId, bytes calldata signature) external;

    /**
     * @dev Updates the off-chain public key for an issuer-schema pair. Must be signed by the authorized signer.
     * @param issuerSchemaId The issuer-schema ID whose pubkey will be updated.
     * @param newPubkey The new off-chain public key.
     * @param signature The signature authorizing the update.
     */
    function updatePubkey(uint64 issuerSchemaId, Pubkey memory newPubkey, bytes calldata signature) external;

    /**
     * @dev Updates the on-chain signer address for an issuer-schema pair. Must be signed by the current signer.
     * @param issuerSchemaId The issuer-schema ID whose signer will be updated.
     * @param newSigner The new on-chain signer address authorized to perform updates.
     * @param signature The signature from the current signer authorizing the update.
     */
    function updateSigner(uint64 issuerSchemaId, address newSigner, bytes calldata signature) external;

    /**
     * @dev Updates the schema URI for a specific issuer schema ID.
     * @param issuerSchemaId The issuer-schema ID whose schema URI will be updated.
     * @param schemaUri The new schema URI to set.
     * @param signature The signature from the authorized signer authorizing the update.
     */
    function updateIssuerSchemaUri(uint64 issuerSchemaId, string memory schemaUri, bytes calldata signature) external;

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Returns the schema URI for a specific issuerSchemaId.
     * @param issuerSchemaId The issuer+schema ID.
     * @return The schema URI for the issuerSchemaId.
     */
    function getIssuerSchemaUri(uint64 issuerSchemaId) external view returns (string memory);

    /**
     * @dev Returns the off-chain pubkey for a specific issuerSchemaId which signs credentials and whose signature is verified on World ID ZKPs.
     * @param issuerSchemaId The issuer-schema ID whose pubkey will be returned.
     * @return The pubkey for the issuerSchemaId.
     */
    function issuerSchemaIdToPubkey(uint64 issuerSchemaId) external view returns (Pubkey memory);

    /**
     * @dev Returns the on-chain signer address authorized to perform updates on a specific issuerSchemaId.
     * @param issuerSchemaId The issuer-schema ID whose signer will be returned.
     * @return The on-chain signer address for the issuerSchemaId.
     */
    function getSignerForIssuerSchemaId(uint64 issuerSchemaId) external view returns (address);

    /**
     * @dev Returns the current nonce for a specific issuer-schema ID, used for replay protection in signed operations.
     * @param issuerSchemaId The issuer-schema ID to query.
     * @return The current nonce for the issuer-schema ID.
     */
    function nonceOf(uint64 issuerSchemaId) external view returns (uint256);

    /**
     * @dev Returns the OPRF key registry address.
     * @return The address of the OPRF key registry contract.
     */
    function getOprfKeyRegistry() external view returns (address);

    ////////////////////////////////////////////////////////////
    //                    OWNER FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Updates the OPRF key registry address.
     * @param newOprfKeyRegistry The new OPRF key registry address.
     */
    function updateOprfKeyRegistry(address newOprfKeyRegistry) external;
}
