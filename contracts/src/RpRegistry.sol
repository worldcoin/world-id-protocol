// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IOprfKeyRegistry} from "lib/oprf-key-registry/src/OprfKeyRegistry.sol";
import {WorldIDBase} from "./abstract/WorldIDBase.sol";
import {IRpRegistry} from "./interfaces/IRpRegistry.sol";

/**
 * @title RpRegistry (World ID)
 * @author World Contributors
 * @notice World ID. Registry of Relying Parties (RPs).
 * @dev A Relying Party (RP) is an entity that requests World ID proofs from users.
 * @custom:repo https://github.com/world-id/world-id-protocol
 */
contract RpRegistry is WorldIDBase, IRpRegistry {
    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    // DO NOT REORDER! To ensure compatibility between upgrades, it is exceedingly important
    // that no reordering of these variables takes place. If reordering happens, a storage
    // clash will occur (effectively a memory safety error).

    /// @dev rpId -> RelyingParty record
    mapping(uint64 => RelyingParty) internal _relyingParties;

    /// @dev rpId -> signature nonce for replay protection
    mapping(uint64 => uint256) internal _rpIdToSignatureNonce;

    /// @dev OPRF key registry contract, used to init OPRF key gen for RPs
    IOprfKeyRegistry internal _oprfKeyRegistry;

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    /// @dev Sentinel value for no domain updates
    string public constant NO_UPDATE = "__NO_UPDATE__";

    /// @dev Hash of the sentinel value for efficient comparison
    bytes32 internal constant NO_UPDATE_HASH = keccak256(bytes(NO_UPDATE));

    string public constant EIP712_NAME = "RpRegistry";
    string public constant EIP712_VERSION = "1.0";

    bytes32 public constant UPDATE_RP_TYPEHASH = keccak256(
        "UpdateRp(uint64 rpId,address manager,address signer,bool toggleActive,string unverifiedWellKnownDomain,uint256 nonce)"
    );

    ////////////////////////////////////////////////////////////
    //                        Constructor                     //
    ////////////////////////////////////////////////////////////

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the contract.
     * @param feeRecipient The recipient of registration fees (can be address(0) if no fees).
     * @param feeToken The token used to pay registration fees (can be address(0) if no fees).
     * @param registrationFee The fee to register an RP (default: 0).
     * @param oprfKeyRegistry The address of the OPRF key registry contract.
     */
    function initialize(address feeRecipient, address feeToken, uint256 registrationFee, address oprfKeyRegistry)
        public
        virtual
        initializer
    {
        if (oprfKeyRegistry == address(0)) revert ZeroAddress();

        __BaseUpgradeable_init(EIP712_NAME, EIP712_VERSION, feeRecipient, feeToken, registrationFee);
        _oprfKeyRegistry = IOprfKeyRegistry(oprfKeyRegistry);
    }

    ////////////////////////////////////////////////////////////
    //                    PUBLIC FUNCTIONS                    //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IRpRegistry
    function register(uint64 rpId, address manager, address signer, string calldata unverifiedWellKnownDomain)
        external
        virtual
        onlyProxy
        onlyInitialized
    {
        _register(rpId, manager, signer, unverifiedWellKnownDomain);
    }

    /// @inheritdoc IRpRegistry
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

        for (uint256 i = 0; i < rpIds.length; i++) {
            _register(rpIds[i], managers[i], signers[i], unverifiedWellKnownDomains[i]);
        }
    }

    /// @inheritdoc IRpRegistry
    function updateRp(
        uint64 rpId,
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
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IRpRegistry
    function domainSeparatorV4() public view virtual onlyProxy onlyInitialized returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @inheritdoc IRpRegistry
    function getRp(uint64 rpId) external view virtual onlyProxy onlyInitialized returns (RelyingParty memory) {
        if (!_relyingParties[rpId].initialized) revert RpIdDoesNotExist();

        if (!_relyingParties[rpId].active) revert RpIdInactive();

        return _relyingParties[rpId];
    }

    /// @inheritdoc IRpRegistry
    function getRpUnchecked(uint64 rpId) external view virtual onlyProxy onlyInitialized returns (RelyingParty memory) {
        if (!_relyingParties[rpId].initialized) revert RpIdDoesNotExist();

        return _relyingParties[rpId];
    }

    /// @inheritdoc IRpRegistry
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

    /// @inheritdoc IRpRegistry
    function nonceOf(uint64 rpId) public view virtual onlyProxy onlyInitialized returns (uint256) {
        return _rpIdToSignatureNonce[rpId];
    }

    /// @inheritdoc IRpRegistry
    function getOprfKeyRegistry() public view virtual onlyProxy onlyInitialized returns (address) {
        return address(_oprfKeyRegistry);
    }

    ////////////////////////////////////////////////////////////
    //                    OWNER FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IRpRegistry
    function updateOprfKeyRegistry(address newOprfKeyRegistry) external virtual onlyOwner onlyProxy onlyInitialized {
        if (newOprfKeyRegistry == address(0)) revert ZeroAddress();
        address oldOprfKeyRegistry = address(_oprfKeyRegistry);
        _oprfKeyRegistry = IOprfKeyRegistry(newOprfKeyRegistry);
        emit OprfKeyRegistryUpdated(oldOprfKeyRegistry, newOprfKeyRegistry);
    }

    ////////////////////////////////////////////////////////////
    //                   INTERNAL FUNCTIONS                   //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Internal function to register a new relying party.
     * @param rpId The unique identifier for the relying party.
     * @param manager The address authorized to manage the relying party.
     * @param signer The address authorized to sign proof requests.
     * @param unverifiedWellKnownDomain The FQDN where the well-known metadata file is published.
     */
    function _register(uint64 rpId, address manager, address signer, string memory unverifiedWellKnownDomain)
        internal
        virtual
    {
        if (_relyingParties[rpId].initialized) revert IdAlreadyInUse(rpId);

        if (rpId == 0) revert InvalidId();

        if (manager == address(0)) revert ManagerCannotBeZeroAddress();

        if (signer == address(0)) revert SignerCannotBeZeroAddress();

        _collectFee();

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
    }
}
