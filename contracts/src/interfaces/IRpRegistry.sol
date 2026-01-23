// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title IRpRegistry
 * @author World Contributors
 * @dev Interface for the Relying Party Registry contract
 */
interface IRpRegistry {
    ////////////////////////////////////////////////////////////
    //                        STRUCTS                         //
    ////////////////////////////////////////////////////////////

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

    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

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

    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
    ////////////////////////////////////////////////////////////

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

    ////////////////////////////////////////////////////////////
    //                   PUBLIC FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Registers a new relying party.
     * @param rpId The unique identifier for the relying party.
     * @param manager The address authorized to manage the relying party.
     * @param signer The address authorized to sign proof requests for the relying party.
     * @param unverifiedWellKnownDomain The FQDN where the well-known metadata file is published (e.g., "world.org").
     */
    function register(uint64 rpId, address manager, address signer, string calldata unverifiedWellKnownDomain) external;

    /**
     * @dev Registers multiple new relying parties at once.
     * @param rpIds Array of unique identifiers for the relying parties.
     * @param managers Array of addresses authorized to manage each relying party.
     * @param signers Array of addresses authorized to sign proof requests for each relying party.
     * @param unverifiedWellKnownDomains Array of FQDNs where well-known metadata files are published.
     */
    function registerMany(
        uint64[] calldata rpIds,
        address[] calldata managers,
        address[] calldata signers,
        string[] calldata unverifiedWellKnownDomains
    ) external;

    /**
     * @dev Partially update a Relying Party record. Must be signed by the manager.
     * @param rpId The unique identifier of the relying party to update.
     * @param oprfKeyId The OPRF key identifier from the OprfKeyRegistry contract.
     * @param manager The new manager address (or current if unchanged).
     * @param signer The new signer address (or current if unchanged).
     * @param toggleActive Whether to toggle the active status of the relying party.
     * @param unverifiedWellKnownDomain The new FQDN (or current if unchanged).
     * @param nonce The signature nonce for replay protection.
     * @param signature The signature from the current manager authorizing the update.
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

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

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

    ////////////////////////////////////////////////////////////
    //                   OWNER FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Sets the fee recipient address where registration fees are sent.
     * @param newFeeRecipient The new address to receive registration fees.
     */
    function setFeeRecipient(address newFeeRecipient) external;

    /**
     * @dev Sets the registration fee amount required to register a new relying party.
     * @param newFee The new registration fee amount.
     */
    function setRegistrationFee(uint256 newFee) external;

    /**
     * @dev Sets the ERC20 token address used for paying registration fees. Use address(0) for native ETH.
     * @param newFeeToken The new token address for fee payments.
     */
    function setFeeToken(address newFeeToken) external;
}

