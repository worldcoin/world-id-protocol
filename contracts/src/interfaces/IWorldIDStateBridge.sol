// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title IWorldIDStateBridge
 * @author World Contributors
 * @notice Interface for the World ID State Bridge contract.
 * @dev Bridges World ID state (roots, timestamps, registry pubkeys) from World Chain to other chains
 *   using storage proofs verified against the L2OutputOracle.
 */
interface IWorldIDStateBridge {
    ////////////////////////////////////////////////////////////
    //                        STRUCTS                         //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Public key coordinates for credential issuers and OPRF keys.
     * @param x The x coordinate of the public key.
     * @param y The y coordinate of the public key.
     */
    struct Pubkey {
        uint256 x;
        uint256 y;
    }

    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Thrown when the provided L1 block hash does not match the L1Block predeploy hash.
     */
    error InvalidL1BlockHash();

    /**
     * @dev Thrown when the provided L2 output index is invalid or out of range.
     */
    error InvalidL2OutputIndex();

    /**
     * @dev Thrown when the account proof verification fails.
     */
    error InvalidAccountProof();

    /**
     * @dev Thrown when a storage proof verification fails.
     */
    error InvalidStorageProof();

    /**
     * @dev Thrown when the extracted output root does not match the expected value.
     */
    error InvalidOutputRoot();

    /**
     * @dev Thrown when the block header RLP decoding fails.
     */
    error InvalidBlockHeader();

    /**
     * @dev Thrown when attempting to bridge a root that is older than the latest bridged root.
     */
    error StaleRoot();

    /**
     * @dev Thrown when the root timestamp is zero (uninitialized).
     */
    error RootNotRecorded();

    /**
     * @dev Thrown when the provided issuer schema ID is invalid.
     */
    error InvalidIssuerSchemaId();

    /**
     * @dev Thrown when the provided OPRF key ID is invalid.
     */
    error InvalidOprfKeyId();

    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Emitted when a new World Chain root is bridged.
     * @param root The new Merkle root from World Chain.
     * @param timestamp The timestamp when the root was recorded on World Chain.
     * @param l2OutputIndex The L2OutputOracle output index used for verification.
     */
    event RootBridged(uint256 indexed root, uint256 timestamp, uint256 l2OutputIndex);

    /**
     * @notice Emitted when a credential issuer pubkey is bridged.
     * @param issuerSchemaId The issuer schema ID.
     * @param pubkeyX The x coordinate of the public key.
     * @param pubkeyY The y coordinate of the public key.
     */
    event IssuerPubkeyBridged(uint64 indexed issuerSchemaId, uint256 pubkeyX, uint256 pubkeyY);

    /**
     * @notice Emitted when an OPRF pubkey is bridged.
     * @param oprfKeyId The OPRF key ID.
     * @param pubkeyX The x coordinate of the public key.
     * @param pubkeyY The y coordinate of the public key.
     */
    event OprfPubkeyBridged(uint160 indexed oprfKeyId, uint256 pubkeyX, uint256 pubkeyY);

    /**
     * @notice Emitted when the World Chain WorldIDRegistry address is updated.
     * @param oldAddress The previous address.
     * @param newAddress The new address.
     */
    event WorldChainRegistryAddressUpdated(address oldAddress, address newAddress);

    /**
     * @notice Emitted when the World Chain CredentialSchemaIssuerRegistry address is updated.
     * @param oldAddress The previous address.
     * @param newAddress The new address.
     */
    event WorldChainIssuerRegistryAddressUpdated(address oldAddress, address newAddress);

    /**
     * @notice Emitted when the World Chain OprfKeyRegistry address is updated.
     * @param oldAddress The previous address.
     * @param newAddress The new address.
     */
    event WorldChainOprfRegistryAddressUpdated(address oldAddress, address newAddress);

    /**
     * @notice Emitted when the L2OutputOracle address is updated.
     * @param oldAddress The previous address.
     * @param newAddress The new address.
     */
    event L2OutputOracleUpdated(address oldAddress, address newAddress);

    /**
     * @notice Emitted when the root validity window is updated.
     * @param oldWindow The previous validity window in seconds.
     * @param newWindow The new validity window in seconds.
     */
    event RootValidityWindowUpdated(uint256 oldWindow, uint256 newWindow);

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Returns the latest bridged root.
     * @return The latest Merkle root.
     */
    function getLatestRoot() external view returns (uint256);

    /**
     * @notice Returns the timestamp for a given root.
     * @param root The root to query.
     * @return The timestamp when the root was recorded on World Chain.
     */
    function getRootTimestamp(uint256 root) external view returns (uint256);

    /**
     * @notice Checks if a root is valid (exists and within validity window).
     * @param root The root to check.
     * @return True if the root is valid.
     */
    function isValidRoot(uint256 root) external view returns (bool);

    /**
     * @notice Returns the root validity window in seconds.
     * @return The validity window.
     */
    function getRootValidityWindow() external view returns (uint256);

    /**
     * @notice Returns the tree depth (hardcoded, matches World Chain).
     * @return The tree depth.
     */
    function getTreeDepth() external view returns (uint256);

    /**
     * @notice Returns the bridged credential issuer pubkey for an issuer schema ID.
     * @param issuerSchemaId The issuer schema ID.
     * @return The public key.
     */
    function getIssuerPubkey(uint64 issuerSchemaId) external view returns (Pubkey memory);

    /**
     * @notice Returns the bridged OPRF pubkey for an OPRF key ID.
     * @param oprfKeyId The OPRF key ID.
     * @return The public key.
     */
    function getOprfPubkey(uint160 oprfKeyId) external view returns (Pubkey memory);

    ////////////////////////////////////////////////////////////
    //                    OWNER FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Updates the root validity window.
     * @param newWindow The new validity window in seconds.
     */
    function setRootValidityWindow(uint256 newWindow) external;

    /**
     * @notice Updates the World Chain WorldIDRegistry address.
     * @param newAddress The new address.
     */
    function setWorldChainRegistryAddress(address newAddress) external;

    /**
     * @notice Updates the World Chain CredentialSchemaIssuerRegistry address.
     * @param newAddress The new address.
     */
    function setWorldChainIssuerRegistryAddress(address newAddress) external;

    /**
     * @notice Updates the World Chain OprfKeyRegistry address.
     * @param newAddress The new address.
     */
    function setWorldChainOprfRegistryAddress(address newAddress) external;

    /**
     * @notice Updates the L2OutputOracle address.
     * @param newAddress The new address.
     */
    function setL2OutputOracle(address newAddress) external;
}
