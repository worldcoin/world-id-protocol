// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title ICredentialSchemaIssuerRegistry
 * @author world
 * @dev Interface for the Credential Schema Issuer Registry contract
 */
interface ICredentialSchemaIssuerRegistry {
    ////////////////////////////////////////////////////////////
    //                         Types                          //
    ////////////////////////////////////////////////////////////

    struct Pubkey {
        uint256 x;
        uint256 y;
    }

    ////////////////////////////////////////////////////////////
    //                        Events                          //
    ////////////////////////////////////////////////////////////

    event IssuerSchemaRegistered(uint256 indexed issuerSchemaId, Pubkey pubkey, address signer);
    event IssuerSchemaRemoved(uint256 indexed issuerSchemaId, Pubkey pubkey, address signer);
    event IssuerSchemaPubkeyUpdated(uint256 indexed issuerSchemaId, Pubkey oldPubkey, Pubkey newPubkey);
    event IssuerSchemaSignerUpdated(uint256 indexed issuerSchemaId, address oldSigner, address newSigner);
    event IssuerSchemaUpdated(uint256 indexed issuerSchemaId, string oldSchemaUri, string newSchemaUri);

    ////////////////////////////////////////////////////////////
    //                        Errors                         //
    ////////////////////////////////////////////////////////////

    error ImplementationNotInitialized();

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

    ////////////////////////////////////////////////////////////
    //                        Functions                       //
    ////////////////////////////////////////////////////////////

    function register(Pubkey memory pubkey, address signer) external returns (uint256);

    function remove(uint256 issuerSchemaId, bytes calldata signature) external;

    function updatePubkey(uint256 issuerSchemaId, Pubkey memory newPubkey, bytes calldata signature) external;

    function updateSigner(uint256 issuerSchemaId, address newSigner, bytes calldata signature) external;

    /**
     * @dev Returns the schema URI for a specific issuerSchemaId.
     * @param issuerSchemaId The issuer+schema ID.
     * @return The schema URI for the issuerSchemaId.
     */
    function getIssuerSchemaUri(uint256 issuerSchemaId) external view returns (string memory);

    /**
     * @dev Updates the schema URI for a specific issuer schema ID.
     */
    function updateIssuerSchemaUri(uint256 issuerSchemaId, string memory schemaUri, bytes calldata signature) external;

    /**
     * @dev Returns the off-chain pubkey for a specific issuerSchemaId which signs credentials and whose signature is verified on World ID ZKPs.
     * @param issuerSchemaId The issuer-schema ID whose pubkey will be returned.
     * @return The pubkey for the issuerSchemaId.
     */
    function issuerSchemaIdToPubkey(uint256 issuerSchemaId) external view returns (Pubkey memory);

    /**
     * @dev Returns the on-chain signer address authorized to perform updates on a specific issuerSchemaId.
     * @param issuerSchemaId The issuer-schema ID whose signer will be returned.
     * @return The on-chain signer address for the issuerSchemaId.
     */
    function getSignerForIssuerSchemaId(uint256 issuerSchemaId) external view returns (address);

    function nextIssuerSchemaId() external view returns (uint256);

    function nonceOf(uint256 issuerSchemaId) external view returns (uint256);
}

