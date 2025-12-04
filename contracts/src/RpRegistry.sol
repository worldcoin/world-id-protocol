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
        bytes unverifiedWellKnownDomain;
    }

    // rpId -> RelyingParty, the main record for a relying party
    mapping(uint64 => RelyingParty) private _relyingParties;

    // rpId -> nonce, used to prevent replays on management operations
    mapping(uint64 => uint256) private _rpIdToSignatureNonce;

    ////////////////////////////////////////////////////////////
    //                        Events                          //
    ////////////////////////////////////////////////////////////

    event RpCreated(uint64 indexed rpId, uint160 indexed oprfKeyId, address manager, bytes unverifiedWellKnownDomain);

    ////////////////////////////////////////////////////////////
    //                        Errors                         //
    ////////////////////////////////////////////////////////////

    error ImplementationNotInitialized();

    /**
     * @dev Thrown when the requested `rpId` to be registered is already in use. `rpId`s must be unique.
     */
    error RpIdAlreadyInUse(uint64 rpId);

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
    function initialize() public initializer {}

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
    function register(uint64 rpId, address manager, address signer, bytes calldata unverifiedWellKnownDomain)
        external
        onlyProxy
        onlyInitialized
        onlyOwner
    {
        // TODO: At launch, only the owner can register a relying party.
        _register(rpId, manager, signer, unverifiedWellKnownDomain);
    }

    function registerMany(uint64[] rpIds, address[] managers, address[] signers, bytes[] unverifiedWellKnownDomains)
        external
        onlyProxy
        onlyInitialized
        onlyOwner
    {
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

    ////////////////////////////////////////////////////////////
    //                  Internal Functions                    //
    ////////////////////////////////////////////////////////////

    function _register(uint64 rpId, address manager, address signer, bytes unverifiedWellKnownDomain) internal {
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

        emit RelyingPartyRegistered(rpId, manager, signer, unverifiedWellKnownDomain);
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
