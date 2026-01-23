// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IOprfKeyRegistry} from "lib/oprf-key-registry/src/OprfKeyRegistry.sol";

/**
 * @title Relying Party Registry (World ID)
 * @author World Contributors
 * @dev The registry of Relying Parties (RPs) for the World ID Protocol.
 * @dev This is the implementation delegated to by a proxy. Please review the README in the source
 * repository before making any updates.
 * @custom:repo https://github.com/world-id/world-id-protocol
 */
contract RpRegistry is Initializable, EIP712Upgradeable, Ownable2StepUpgradeable, UUPSUpgradeable {
    using SafeERC20 for IERC20;

    modifier onlyInitialized() {
        _onlyInitialized();
        _;
    }

    function _onlyInitialized() internal view {
        if (_getInitializedVersion() == 0) {
            revert ImplementationNotInitialized();
        }
    }

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
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    // DO NOT REORDER! To ensure compatibility between upgrades, it is exceedingly important
    // that no reordering of these variables takes place. If reordering happens, a storage
    // clash will occur (effectively a memory safety error).

    // rpId -> RelyingParty, the main record for a relying party
    mapping(uint64 => RelyingParty) internal _relyingParties;

    // rpId -> nonce, used to prevent replays on management operations
    mapping(uint64 => uint256) internal _rpIdToSignatureNonce;

    // the fee to register a relying party
    uint256 internal _registrationFee;

    // the recipient of registration fees
    address internal _feeRecipient;

    // the token used to pay registration fees
    IERC20 internal _feeToken;

    // the OPRF key registry contract, used to init OPRF key gen for RPs
    IOprfKeyRegistry internal _oprfKeyRegistry;

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
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    // sentinel value for no domain updates
    string public constant NO_UPDATE = "__NO_UPDATE__";
    bytes32 constant NO_UPDATE_HASH = keccak256(bytes(NO_UPDATE));

    string public constant EIP712_NAME = "RpRegistry";
    string public constant EIP712_VERSION = "1.0";

    bytes32 public constant UPDATE_RP_TYPEHASH = keccak256(
        "UpdateRp(uint64 rpId,uint160 oprfKeyId,address manager,address signer,bool toggleActive,string unverifiedWellKnownDomain,uint256 nonce)"
    );

    ////////////////////////////////////////////////////////////
    //                        Errors                         //
    ////////////////////////////////////////////////////////////

    error ImplementationNotInitialized();

    /**
     * @dev Thrown when the requested rpId to be registered is already in use. rpIds must be unique.
     */
    error RpIdAlreadyInUse(uint64 rpId);

    /**
     * @dev Thrown when the provided rpId is not registered.
     */
    error RpIdDoesNotExist();

    /**
     * @dev Thrown the the provided rpId is not active.
     */
    error RpIdInactive();

    /**
     * @dev Thrown when trying to set a manager to the zero address.
     */
    error ManagerCannotBeZeroAddress();

    /**
     * @dev Thrown when trying to set a signer to the zero address.
     */
    error SignerCannotBeZeroAddress();

    /**
     * @dev Thrown when the provided array lengths do not match.
     */
    error MismatchingArrayLengths();

    /**
     * @dev Thrown when the provided nonce does not match the expected nonce.
     */
    error InvalidNonce();

    /**
     * @dev Thrown when the provided signature is invalid for the operation.
     */
    error InvalidSignature();

    /**
     * @dev Thrown when the fee payment is not enough to cover registration.
     */
    error InsufficientFunds();

    /**
     * @dev Thrown when the registration fee is not paid.
     */
    error PaymentFailure();

    /**
     * @dev Thrown when trying to set an address to the zero address.
     */
    error ZeroAddress();

    ////////////////////////////////////////////////////////////
    //                        Constructor                     //
    ////////////////////////////////////////////////////////////

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializes the contract.
     */
    function initialize(address feeRecipient, address feeToken, uint256 registrationFee, address oprfKeyRegistry)
        public
        initializer
    {
        if (feeRecipient == address(0)) revert ZeroAddress();
        if (feeToken == address(0)) revert ZeroAddress();
        if (oprfKeyRegistry == address(0)) revert ZeroAddress();

        __EIP712_init(EIP712_NAME, EIP712_VERSION);
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();

        _feeRecipient = feeRecipient;
        _feeToken = IERC20(feeToken);
        _registrationFee = registrationFee;
        _oprfKeyRegistry = IOprfKeyRegistry(oprfKeyRegistry);
    }

    ////////////////////////////////////////////////////////////
    //                   Public Functions                     //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Returns the domain separator for the EIP712 structs.
     */
    function domainSeparatorV4() public view virtual onlyProxy onlyInitialized returns (bytes32) {
        return _domainSeparatorV4();
    }

    /**
     * @dev Registers a new relying party.
     * @param rpId The ID of the relying party. A random ID is recommended.
     * @param manager The address of the manager (on-chain operations).
     * @param signer The address of the signer (Proof requests).
     * @param unverifiedWellKnownDomain The (unverified) well-known domain of the relying party.
     */
    function register(uint64 rpId, address manager, address signer, string calldata unverifiedWellKnownDomain)
        external
        virtual
        onlyProxy
        onlyInitialized
    {
        if (_feeToken.balanceOf(msg.sender) < _registrationFee) revert InsufficientFunds();
        _register(rpId, manager, signer, unverifiedWellKnownDomain);
    }

    /**
     * @dev Registers multiple new relying parties at once.
     * @param rpIds the list of rpIds
     * @param managers the list of managers
     * @param signers the list of signers
     * @param unverifiedWellKnownDomains the list of unverified well-known domains
     */
    function registerMany(
        uint64[] calldata rpIds,
        address[] calldata managers,
        address[] calldata signers,
        string[] calldata unverifiedWellKnownDomains
    ) external virtual onlyProxy onlyInitialized {
        if (
            rpIds.length != managers.length || rpIds.length != signers.length
                || rpIds.length != unverifiedWellKnownDomains.length
        ) {
            revert MismatchingArrayLengths();
        }

        if (_feeToken.balanceOf(msg.sender) < rpIds.length * _registrationFee) revert InsufficientFunds();

        for (uint256 i = 0; i < rpIds.length; i++) {
            _register(rpIds[i], managers[i], signers[i], unverifiedWellKnownDomains[i]);
        }
    }

    /**
     * @dev Get a relying party by id. will revert if it's not a valid id or is inactive.
     * @param rpId the id of the relying party to get
     */
    function getRp(uint64 rpId) external view virtual onlyProxy onlyInitialized returns (RelyingParty memory) {
        if (!_relyingParties[rpId].initialized) revert RpIdDoesNotExist();

        if (!_relyingParties[rpId].active) revert RpIdInactive();

        return _relyingParties[rpId];
    }

    /**
     * @dev Get a relying party by id. will return even if the rp is inactive.
     * @param rpId the id of the relying party to get
     */
    function getRpUnchecked(uint64 rpId) external view virtual onlyProxy onlyInitialized returns (RelyingParty memory) {
        if (!_relyingParties[rpId].initialized) revert RpIdDoesNotExist();

        return _relyingParties[rpId];
    }

    /**
     * @dev Convenience method to get the oprf key id and signer of a relying party. Useful for proof generation/verification.
     * @param rpId the id of the relying party to get
     */
    function getOprfKeyIdAndSigner(uint64 rpId)
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (uint160, address)
    {
        if (!_relyingParties[rpId].initialized) revert RpIdDoesNotExist();

        if (!_relyingParties[rpId].active) revert RpIdInactive();

        return (_relyingParties[rpId].oprfKeyId, _relyingParties[rpId].signer);
    }

    /**
     * @dev Returns the current nonce for a relying party. will return 0 even if the rpId does not exist.
     * @param rpId the id of the relying party to get
     */
    function nonceOf(uint64 rpId) public view virtual onlyProxy onlyInitialized returns (uint256) {
        return _rpIdToSignatureNonce[rpId];
    }

    /**
     * @dev Returns the current registration fee for a relying party.
     */
    function getRegistrationFee() public view virtual onlyProxy onlyInitialized returns (uint256) {
        return _registrationFee;
    }

    /**
     * @dev Returns the current recipient for RP registration fees.
     */
    function getFeeRecipient() public view virtual onlyProxy onlyInitialized returns (address) {
        return _feeRecipient;
    }

    /**
     * @dev Returns the current token with which fees are paid.
     */
    function getFeeToken() public view virtual onlyProxy onlyInitialized returns (address) {
        return address(_feeToken);
    }

    function getOprfKeyRegistry() public view virtual onlyProxy onlyInitialized returns (address) {
        return address(_oprfKeyRegistry);
    }

    /**
     * @dev Partially update a Relying Party record. Must be signed by the manager.
     * @param rpId the id of the relying party to update
     * @param oprfKeyId the new oprf key id of the relying party. set to zero to maintain current oprfKeyId.
     * @param manager the new manager of the relying party. set to zero address to maintain current manager.
     * @param signer the new signer of the relying party. set to zero address to maintain current signer.
     * @param toggleActive whether to toggle the active status of the relying party
     * @param unverifiedWellKnownDomain the new unverified well-known domain of the relying party. set to sentinel value to skip update.
     * @param nonce the nonce used for this operation
     * @param signature the signature of the manager
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
    ) external virtual onlyProxy onlyInitialized {
        if (!_relyingParties[rpId].initialized) revert RpIdDoesNotExist();

        if (nonce != _rpIdToSignatureNonce[rpId]) revert InvalidNonce();

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    UPDATE_RP_TYPEHASH,
                    rpId,
                    oprfKeyId,
                    manager,
                    signer,
                    toggleActive,
                    keccak256(bytes(unverifiedWellKnownDomain)),
                    nonce
                )
            )
        );

        if (!SignatureChecker.isValidSignatureNow(_relyingParties[rpId].manager, messageHash, signature)) {
            revert InvalidSignature();
        }

        if (oprfKeyId != 0) {
            _relyingParties[rpId].oprfKeyId = oprfKeyId;
        }

        if (manager != address(0)) {
            _relyingParties[rpId].manager = manager;
        }

        if (signer != address(0)) {
            _relyingParties[rpId].signer = signer;
        }

        if (keccak256(bytes(unverifiedWellKnownDomain)) != NO_UPDATE_HASH) {
            _relyingParties[rpId].unverifiedWellKnownDomain = unverifiedWellKnownDomain;
        }

        if (toggleActive) {
            _relyingParties[rpId].active = !_relyingParties[rpId].active;
        }

        _rpIdToSignatureNonce[rpId]++;
        emit RpUpdated(
            rpId,
            _relyingParties[rpId].oprfKeyId,
            _relyingParties[rpId].active,
            _relyingParties[rpId].manager,
            _relyingParties[rpId].signer,
            _relyingParties[rpId].unverifiedWellKnownDomain
        );
    }

    ////////////////////////////////////////////////////////////
    //                  Internal Functions                    //
    ////////////////////////////////////////////////////////////

    function _register(uint64 rpId, address manager, address signer, string memory unverifiedWellKnownDomain) internal {
        if (_relyingParties[rpId].initialized) revert RpIdAlreadyInUse(rpId);

        if (manager == address(0)) revert ManagerCannotBeZeroAddress();

        if (signer == address(0)) revert SignerCannotBeZeroAddress();

        uint160 oprfKeyId = uint160(rpId);
        _oprfKeyRegistry.initKeyGen(oprfKeyId);

        RelyingParty memory rp = RelyingParty({
            initialized: true,
            active: true,
            manager: manager,
            signer: signer,
            oprfKeyId: oprfKeyId,
            unverifiedWellKnownDomain: unverifiedWellKnownDomain
        });

        _relyingParties[rpId] = rp;

        emit RpRegistered(rpId, oprfKeyId, manager, unverifiedWellKnownDomain);

        if (_registrationFee > 0) {
            _feeToken.safeTransferFrom(msg.sender, _feeRecipient, _registrationFee);
        }
    }

    ////////////////////////////////////////////////////////////
    //                    Owner Functions               //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Authorize upgrade to a new implementation
     * @param newImplementation Address of the new implementation contract
     * @notice Only the contract owner can authorize upgrades
     */
    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner {}

    function setFeeRecipient(address newFeeRecipient) external virtual onlyOwner onlyProxy onlyInitialized {
        if (newFeeRecipient == address(0)) revert ZeroAddress();
        address oldRecipient = _feeRecipient;
        _feeRecipient = newFeeRecipient;
        emit FeeRecipientUpdated(oldRecipient, newFeeRecipient);
    }

    function setRegistrationFee(uint256 newFee) external virtual onlyOwner onlyProxy onlyInitialized {
        uint256 oldFee = _registrationFee;
        _registrationFee = newFee;
        emit RegistrationFeeUpdated(oldFee, newFee);
    }

    function setFeeToken(address newFeeToken) external virtual onlyOwner onlyProxy onlyInitialized {
        if (newFeeToken == address(0)) revert ZeroAddress();
        address oldToken = address(_feeToken);
        _feeToken = IERC20(newFeeToken);
        emit FeeTokenUpdated(oldToken, newFeeToken);
    }

    ////////////////////////////////////////////////////////////
    //                    Storage Gap                         //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Storage gap to allow for future upgrades without storage collisions
     * This reserves 50 storage slots for future state variables
     */
    uint256[50] private __gap;
}
