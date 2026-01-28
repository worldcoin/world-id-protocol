// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title ICredentialSchemaIssuerRegistry
 * @author World Contributors
 * @dev Interface for the Credential Schema Issuer Registry contract
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
     * @dev Thrown when the implementation has not been initialized via proxy.
     */
    error ImplementationNotInitialized();

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
     * @dev Thrown when trying to set an address to the zero address.
     */
    error ZeroAddress();

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
     * @dev Emitted when the fee recipient address is updated.
     * @param oldRecipient The previous fee recipient address.
     * @param newRecipient The new fee recipient address.
     */
    event FeeRecipientUpdated(address indexed oldRecipient, address indexed newRecipient);

    /**
     * @dev Emitted when the registration fee amount is updated.
     * @param oldFee The previous registration fee.
     * @param newFee The new registration fee.
     */
    event RegistrationFeeUpdated(uint256 oldFee, uint256 newFee);

    /**
     * @dev Emitted when the fee token address is updated.
     * @param oldToken The previous fee token address.
     * @param newToken The new fee token address.
     */
    event FeeTokenUpdated(address indexed oldToken, address indexed newToken);

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
}
