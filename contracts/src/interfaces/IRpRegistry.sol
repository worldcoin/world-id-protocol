// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title IRpRegistry
 * @author World Contributors
 * @dev Interface for the Relying Party Registry contract
 */
interface IRpRegistry {
    ////////////////////////////////////////////////////////////
    //                         Types                          //
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
    //                        Events                          //
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
    //                        Errors                         //
    ////////////////////////////////////////////////////////////

    error ImplementationNotInitialized();
    error RpIdAlreadyInUse(uint64 rpId);
    error RpIdDoesNotExist();
    error RpIdInactive();
    error ManagerCannotBeZeroAddress();
    error SignerCannotBeZeroAddress();
    error MismatchingArrayLengths();
    error InvalidNonce();
    error InvalidSignature();
    error InsufficientFunds();
    error PaymentFailure();
    error ZeroAddress();

    ////////////////////////////////////////////////////////////
    //                        Functions                       //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Returns the domain separator for the EIP712 structs.
     */
    function domainSeparatorV4() external view returns (bytes32);

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

    ////////////////////////////////////////////////////////////
    //                    Owner Functions                     //
    ////////////////////////////////////////////////////////////

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
}

