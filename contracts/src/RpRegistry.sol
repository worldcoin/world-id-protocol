// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract RpRegistry is Initializable, EIP712Upgradeable, Ownable2StepUpgradeable, UUPSUpgradeable {
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

    // rpId -> RelyingParty, the main record for a relying party
    mapping(uint64 => RelyingParty) private _relyingParties;

    // rpId -> nonce, used to prevent replays on management operations
    mapping(uint64 => uint256) private _rpIdToSignatureNonce;

    ////////////////////////////////////////////////////////////
    //                        Events                          //
    ////////////////////////////////////////////////////////////

    event RpRegistered(
        uint64 indexed rpId, uint160 indexed oprfKeyId, address manager, string unverifiedWellKnownDomain
    );

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    // sentinel value for no domain updates
    string public constant NO_UPDATE = "__NO_UPDATE__";
    bytes32 constant NO_UPDATE_HASH = keccak256(bytes(NO_UPDATE));

    string public constant EIP712_NAME = "RpRegistry";
    string public constant EIP712_VERSION = "1.0";

    bytes32 public constant UPDATE_RP_TYPEHASH = keccak256(
        "UpdateRp(uint64 rpId,address manager,address signer,bool toggleActive,string unverifiedWellKnownDomain,uint256 nonce)"
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
    function initialize() public initializer {
        __EIP712_init(EIP712_NAME, EIP712_VERSION);
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
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
     * TODO: At launch, only the owner can register a relying party.
     */
    function register(uint64 rpId, address manager, address signer, string calldata unverifiedWellKnownDomain)
        external
        onlyProxy
        onlyInitialized
        onlyOwner
    {
        _register(rpId, manager, signer, unverifiedWellKnownDomain);
    }

    /**
     * @dev Registers multiple new relying parties at once.
     * @param rpIds the list of rpIds
     * @param managers the list of managers
     * @param signers the list of signers
     * @param unverifiedWellKnownDomains the list of unverified well-known domains
     * TODO: At launch, only the owner can register a relying party.
     */
    function registerMany(
        uint64[] calldata rpIds,
        address[] calldata managers,
        address[] calldata signers,
        string[] calldata unverifiedWellKnownDomains
    ) external onlyProxy onlyInitialized onlyOwner {
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

    /**
     * @dev Get a relying party by id. will revert if it's not a valid id or is inactive.
     * @param rpId the id of the relying party to get
     */
    function getRp(uint64 rpId) external view returns (RelyingParty memory) {
        if (!_relyingParties[rpId].initialized) {
            revert RpIdDoesNotExist();
        }

        if (!_relyingParties[rpId].active) {
            revert RpIdInactive();
        }

        return _relyingParties[rpId];
    }

    /**
     * @dev Get a relying party by id. will return even if the rp is inactive.
     * @param rpId the id of the relying party to get
     */
    function getRpUnchecked(uint64 rpId) external view returns (RelyingParty memory) {
        if (!_relyingParties[rpId].initialized) {
            revert RpIdDoesNotExist();
        }

        return _relyingParties[rpId];
    }

    /**
     * @dev Convenience method to get the oprf key id and signer of a relying party. Useful for proof generation/verification.
     * @param rpId the id of the relying party to get
     */
    function getOprfKeyIdAndSigner(uint64 rpId) external view returns (uint160, address) {
        if (!_relyingParties[rpId].initialized) {
            revert RpIdDoesNotExist();
        }

        if (!_relyingParties[rpId].active) {
            revert RpIdInactive();
        }

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
     * @dev Partially update a Relying Party record. Must be signed by the manager.
     * @param rpId the id of the relying party to update
     * @param manager the new manager of the relying party. set to zero address to maintain current manager.
     * @param signer the new signer of the relying party. set to zero address to maintain current signer.
     * @param toggleActive whether to toggle the active status of the relying party
     * @param unverifiedWellKnownDomain the new unverified well-known domain of the relying party. set to sentinel value to skip update.
     * @param signature the signature of the manager
     * @param nonce the nonce used for this operation
     */
    function updateRp(
        uint64 rpId,
        address manager,
        address signer,
        bool toggleActive,
        string calldata unverifiedWellKnownDomain,
        bytes calldata signature,
        uint256 nonce
    ) external {
        if (!_relyingParties[rpId].initialized) {
            revert RpIdDoesNotExist();
        }

        if (nonce != _rpIdToSignatureNonce[rpId]) {
            revert InvalidNonce();
        }

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(UPDATE_RP_TYPEHASH, rpId, manager, signer, toggleActive, unverifiedWellKnownDomain, nonce)
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
    }

    ////////////////////////////////////////////////////////////
    //                  Internal Functions                    //
    ////////////////////////////////////////////////////////////

    function _register(uint64 rpId, address manager, address signer, string memory unverifiedWellKnownDomain) internal {
        if (_relyingParties[rpId].initialized) {
            revert RpIdAlreadyInUse(rpId);
        }

        if (manager == address(0)) {
            revert ManagerCannotBeZeroAddress();
        }

        if (signer == address(0)) {
            revert SignerCannotBeZeroAddress();
        }

        RelyingParty memory rp = RelyingParty({
            initialized: true,
            active: true,
            manager: manager,
            signer: signer,
            oprfKeyId: 0, // FIXME: register key with OprfKeyRegistry contract
            unverifiedWellKnownDomain: unverifiedWellKnownDomain
        });

        _relyingParties[rpId] = rp;

        emit RpRegistered(rpId, 0, manager, unverifiedWellKnownDomain);
    }

    ////////////////////////////////////////////////////////////
    //                    Upgrade Authorization               //
    ////////////////////////////////////////////////////////////

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
