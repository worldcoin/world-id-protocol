// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title IRpRegistry
 * @author World Contributors
 * @dev Interface for the Relying Party Registry contract
 */
interface IRpRegistry {
    // ========================================
    // STRUCTS
    // ========================================

    struct RelyingParty {
        // whether the rpId has ever been initialized.
        bool initialized;
        // whether the RP is active or not. an inactive RP is not able to make requests.
        bool active;
        // the manager authorized to perform registry updates for the RP
        address manager;
        // the signer which is allowed to sign proof requests.
        // while not recommended, it can be the same as the manager.
        address signer;
        // the OPRF key identifier from the OprfKeyRegistry contract.
        // points to the committed public key from OPRF Nodes for the RP.
        uint160 oprfKeyId;
        // the fully qualified domain name (FQDN) where the well-known metadata file for the RP is published.
        // the metadata file must be published in https://<unverifiedWellKnownDomain>/.well-known/world-id.json
        // examples: `world.org`, `example.world.org`
        // note this is unverified and it's every party responsibility to verify the domain through the well-known file.
        string unverifiedWellKnownDomain;
    }

    // ========================================
    // ERRORS
    // ========================================

    /**
     * @dev Thrown when the contract implementation has not been initialized.
     */
    error ImplementationNotInitialized();

    /**
     * @dev Thrown when attempting to register a relying party with an rpId that is already in use.
     * @param rpId The relying party ID that is already in use.
     */
    error RpIdAlreadyInUse(uint64 rpId);

    /**
     * @dev Thrown when attempting to access a relying party that does not exist.
     */
    error RpIdDoesNotExist();

    /**
     * @dev Thrown when attempting to use an inactive relying party.
     */
    error RpIdInactive();

    /**
     * @dev Thrown when attempting to set the manager address to the zero address.
     */
    error ManagerCannotBeZeroAddress();

    /**
     * @dev Thrown when attempting to set the signer address to the zero address.
     */
    error SignerCannotBeZeroAddress();

    /**
     * @dev Thrown when the provided array lengths do not match in batch operations.
     */
    error MismatchingArrayLengths();

    /**
     * @dev Thrown when the provided nonce does not match the expected nonce for a relying party.
     */
    error InvalidNonce();

    /**
     * @dev Thrown when the provided signature is invalid for the operation.
     */
    error InvalidSignature();

    /**
     * @dev Thrown when the sender has insufficient funds to pay the registration fee.
     */
    error InsufficientFunds();

    /**
     * @dev Thrown when a payment transfer fails.
     */
    error PaymentFailure();

    /**
     * @dev Thrown when attempting to set an address parameter to the zero address.
     */
    error ZeroAddress();

    // ========================================
    // EVENTS
    // ========================================

    event RpRegistered(
        uint64 indexed rpId, uint160 indexed oprfKeyId, address manager, string unverifiedWellKnownDomain
    );

    event RpUpdated(
        uint64 indexed rpId,
        uint160 indexed oprfKeyId,
        bool active,
        address manager,
        address signer,
        string unverifiedWellKnownDomain
    );

    event FeeRecipientUpdated(address indexed oldRecipient, address indexed newRecipient);

    event RegistrationFeeUpdated(uint256 oldFee, uint256 newFee);

    event FeeTokenUpdated(address indexed oldToken, address indexed newToken);

    // ========================================
    // PUBLIC FUNCTIONS
    // ========================================

    /**
     * @dev Registers a new relying party.
     */
    function register(uint64 rpId, address manager, address signer, string calldata unverifiedWellKnownDomain) external;

    /**
     * @dev Registers multiple new relying parties at once.
     */
    function registerMany(
        uint64[] calldata rpIds,
        address[] calldata managers,
        address[] calldata signers,
        string[] calldata unverifiedWellKnownDomains
    ) external;

    /**
     * @dev Partially update a Relying Party record. Must be signed by the manager.
     */
    function updateRp(
        uint64 rpId,
        uint160 oprfKeyId,
        address manager,
        address signer,
        bool toggleActive,
        string calldata unverifiedWellKnownDomain,
        uint256 nonce,
        bytes calldata signature
    ) external;

    // ========================================
    // OWNER FUNCTIONS
    // ========================================

    /**
     * @dev Sets the fee recipient address.
     */
    function setFeeRecipient(address newFeeRecipient) external;

    /**
     * @dev Sets the registration fee.
     */
    function setRegistrationFee(uint256 newFee) external;

    /**
     * @dev Sets the fee token address.
     */
    function setFeeToken(address newFeeToken) external;

    // ========================================
    // VIEW FUNCTIONS
    // ========================================

    /**
     * @dev Returns the domain separator for the EIP712 structs.
     */
    function domainSeparatorV4() external view returns (bytes32);

    /**
     * @dev Get a relying party by id. will revert if it's not a valid id or is inactive.
     */
    function getRp(uint64 rpId) external view returns (RelyingParty memory);

    /**
     * @dev Get a relying party by id. will return even if the rp is inactive.
     */
    function getRpUnchecked(uint64 rpId) external view returns (RelyingParty memory);

    /**
     * @dev Convenience method to get the oprf key id and signer of a relying party.
     */
    function getOprfKeyIdAndSigner(uint64 rpId) external view returns (uint160, address);

    /**
     * @dev Returns the current nonce for a relying party.
     */
    function nonceOf(uint64 rpId) external view returns (uint256);

    /**
     * @dev Returns the current registration fee for a relying party.
     */
    function getRegistrationFee() external view returns (uint256);

    /**
     * @dev Returns the current recipient for RP registration fees.
     */
    function getFeeRecipient() external view returns (address);

    /**
     * @dev Returns the current token with which fees are paid.
     */
    function getFeeToken() external view returns (address);

    /**
     * @dev Returns the OPRF key registry address.
     */
    function getOprfKeyRegistry() external view returns (address);
}

