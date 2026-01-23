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
import {IRpRegistry} from "./interfaces/IRpRegistry.sol";

/**
 * @title Relying Party Registry (World ID)
 * @author World Contributors
 * @dev The registry of Relying Parties (RPs) for the World ID Protocol.
 * @dev This is the implementation delegated to by a proxy. Please review the README in the source
 * repository before making any updates.
 * @custom:repo https://github.com/world-id/world-id-protocol
 */
contract RpRegistry is Initializable, EIP712Upgradeable, Ownable2StepUpgradeable, UUPSUpgradeable, IRpRegistry {
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
    //                   PUBLIC FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /**
     * @inheritdoc IRpRegistry
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
     * @inheritdoc IRpRegistry
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
     * @inheritdoc IRpRegistry
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
    //                   INTERNAL FUNCTIONS                   //
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
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /**
     * @inheritdoc IRpRegistry
     */
    function domainSeparatorV4() public view onlyProxy onlyInitialized returns (bytes32) {
        return _domainSeparatorV4();
    }

    /**
     * @inheritdoc IRpRegistry
     */
    function getRp(uint64 rpId) public view onlyProxy onlyInitialized returns (RelyingParty memory) {
        if (!_relyingParties[rpId].initialized) revert RpIdDoesNotExist();

        if (!_relyingParties[rpId].active) revert RpIdInactive();

        return _relyingParties[rpId];
    }

    /**
     * @inheritdoc IRpRegistry
     */
    function getRpUnchecked(uint64 rpId) public view onlyProxy onlyInitialized returns (RelyingParty memory) {
        if (!_relyingParties[rpId].initialized) revert RpIdDoesNotExist();

        return _relyingParties[rpId];
    }

    /**
     * @inheritdoc IRpRegistry
     */
    function getOprfKeyIdAndSigner(uint64 rpId) public view onlyProxy onlyInitialized returns (uint160, address) {
        if (!_relyingParties[rpId].initialized) revert RpIdDoesNotExist();

        if (!_relyingParties[rpId].active) revert RpIdInactive();

        return (_relyingParties[rpId].oprfKeyId, _relyingParties[rpId].signer);
    }

    /**
     * @inheritdoc IRpRegistry
     */
    function nonceOf(uint64 rpId) public view onlyProxy onlyInitialized returns (uint256) {
        return _rpIdToSignatureNonce[rpId];
    }

    /**
     * @inheritdoc IRpRegistry
     */
    function getRegistrationFee() public view onlyProxy onlyInitialized returns (uint256) {
        return _registrationFee;
    }

    /**
     * @inheritdoc IRpRegistry
     */
    function getFeeRecipient() public view onlyProxy onlyInitialized returns (address) {
        return _feeRecipient;
    }

    /**
     * @inheritdoc IRpRegistry
     */
    function getFeeToken() public view onlyProxy onlyInitialized returns (address) {
        return address(_feeToken);
    }

    /**
     * @inheritdoc IRpRegistry
     */
    function getOprfKeyRegistry() public view onlyProxy onlyInitialized returns (address) {
        return address(_oprfKeyRegistry);
    }

    ////////////////////////////////////////////////////////////
    //                    OWNER FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /**
     * @inheritdoc IRpRegistry
     */
    function setFeeRecipient(address newFeeRecipient) public onlyOwner onlyProxy onlyInitialized {
        if (newFeeRecipient == address(0)) revert ZeroAddress();
        address oldRecipient = _feeRecipient;
        _feeRecipient = newFeeRecipient;
        emit FeeRecipientUpdated(oldRecipient, newFeeRecipient);
    }

    /**
     * @inheritdoc IRpRegistry
     */
    function setRegistrationFee(uint256 newFee) public onlyOwner onlyProxy onlyInitialized {
        uint256 oldFee = _registrationFee;
        _registrationFee = newFee;
        emit RegistrationFeeUpdated(oldFee, newFee);
    }

    /**
     * @inheritdoc IRpRegistry
     */
    function setFeeToken(address newFeeToken) public onlyOwner onlyProxy onlyInitialized {
        if (newFeeToken == address(0)) revert ZeroAddress();
        address oldToken = address(_feeToken);
        _feeToken = IERC20(newFeeToken);
        emit FeeTokenUpdated(oldToken, newFeeToken);
    }

    /**
     * @dev Authorize upgrade to a new implementation
     * @param newImplementation Address of the new implementation contract
     * @notice Only the contract owner can authorize upgrades
     */
    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner {}

    ////////////////////////////////////////////////////////////
    //                    Storage Gap                         //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Storage gap to allow for future upgrades without storage collisions
     * This reserves 50 storage slots for future state variables
     */
    uint256[50] private __gap;
}
