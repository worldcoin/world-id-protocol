// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {RpRegistry} from "./RpRegistry.sol";
import {IRpRegistry} from "./interfaces/IRpRegistry.sol";
import {IRpRegistryV2} from "./interfaces/IRpRegistryV2.sol";

/**
 * @title RpRegistryV2 (World ID)
 * @author World Contributors
 * @notice Adds registrar authorization and owner-governed recovery to the RP registry.
 * @dev V1 allowed any account to permanently claim any uninitialized RP identifier. V2 restricts
 *      initial registration to owner-approved registrars and adds a recovery path for incorrect
 *      first registrations while preserving the existing proxy storage layout.
 * @custom:repo https://github.com/world-id/world-id-protocol
 */
contract RpRegistryV2 is IRpRegistryV2, RpRegistry {
    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    /// @dev Accounts authorized by the owner to register new RPs.
    mapping(address => bool) internal _authorizedRegistrars;

    ////////////////////////////////////////////////////////////
    //                        Modifiers                       //
    ////////////////////////////////////////////////////////////

    /// @dev Restricts initial RP registration to owner-approved accounts.
    modifier onlyRegistrar() {
        if (!_authorizedRegistrars[msg.sender]) revert UnauthorizedRegistrar(msg.sender);
        _;
    }

    ////////////////////////////////////////////////////////////
    //                    PUBLIC FUNCTIONS                    //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IRpRegistryV2
    function initializeV2(address initialRegistrar) external virtual reinitializer(2) onlyOwner {
        _setRegistrar(initialRegistrar, true);
    }

    /// @inheritdoc IRpRegistry
    function register(uint64 rpId, address manager, address signer, string calldata unverifiedWellKnownDomain)
        external
        virtual
        override(IRpRegistry, RpRegistry)
        onlyProxy
        onlyInitialized
        onlyRegistrar
    {
        _register(rpId, manager, signer, unverifiedWellKnownDomain);
    }

    /// @inheritdoc IRpRegistry
    function registerMany(
        uint64[] calldata rpIds,
        address[] calldata managers,
        address[] calldata signers,
        string[] calldata unverifiedWellKnownDomains
    ) external virtual override(IRpRegistry, RpRegistry) onlyProxy onlyInitialized onlyRegistrar {
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

    /// @inheritdoc IRpRegistryV2
    function isRegistrar(address registrar) external view virtual onlyProxy onlyInitialized returns (bool) {
        return _authorizedRegistrars[registrar];
    }

    ////////////////////////////////////////////////////////////
    //                    OWNER FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IRpRegistryV2
    function setRegistrar(address registrar, bool authorized) external virtual onlyOwner onlyProxy onlyInitialized {
        _setRegistrar(registrar, authorized);
    }

    /// @inheritdoc IRpRegistryV2
    function recoverRp(uint64 rpId, address manager, address signer, string calldata unverifiedWellKnownDomain)
        external
        virtual
        onlyOwner
        onlyProxy
        onlyInitialized
    {
        RelyingParty storage rp = _relyingParties[rpId];
        if (!rp.initialized) revert RpIdDoesNotExist();
        if (manager == address(0)) revert ManagerCannotBeZeroAddress();
        if (signer == address(0)) revert SignerCannotBeZeroAddress();

        address previousManager = rp.manager;
        rp.active = true;
        rp.manager = manager;
        rp.signer = signer;
        rp.unverifiedWellKnownDomain = unverifiedWellKnownDomain;

        // A recovery establishes a new management epoch. Advancing the nonce also prevents a
        // replacement manager from accidentally replaying an authorization from an earlier epoch.
        _rpIdToSignatureNonce[rpId]++;

        emit RpRecovered(rpId, previousManager, manager, signer);
        emit RpUpdated(rpId, rp.oprfKeyId, rp.active, manager, signer, unverifiedWellKnownDomain);
    }

    ////////////////////////////////////////////////////////////
    //                   INTERNAL FUNCTIONS                   //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Updates registrar authorization after validating the account.
     */
    function _setRegistrar(address registrar, bool authorized) internal virtual {
        if (registrar == address(0)) revert RegistrarCannotBeZeroAddress();
        _authorizedRegistrars[registrar] = authorized;
        emit RegistrarAuthorizationUpdated(registrar, authorized);
    }
}
