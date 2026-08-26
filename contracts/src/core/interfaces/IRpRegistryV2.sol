// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IRpRegistry} from "./IRpRegistry.sol";

/**
 * @title IRpRegistryV2
 * @author World Contributors
 * @notice Interface for the access-controlled and recoverable RP registry.
 */
interface IRpRegistryV2 is IRpRegistry {
    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Thrown when an account that is not an authorized registrar attempts to register an RP.
     * @param caller The unauthorized caller.
     */
    error UnauthorizedRegistrar(address caller);

    /**
     * @dev Thrown when attempting to configure the zero address as a registrar.
     */
    error RegistrarCannotBeZeroAddress();

    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Emitted when the owner changes an account's registrar authorization.
     * @param registrar The account whose authorization changed.
     * @param authorized Whether the account is authorized to register RPs.
     */
    event RegistrarAuthorizationUpdated(address indexed registrar, bool authorized);

    /**
     * @dev Emitted when the owner recovers an RP record from an incorrect manager.
     * @param rpId The recovered RP identifier.
     * @param previousManager The manager configured before recovery.
     * @param newManager The manager configured by the recovery.
     * @param newSigner The signer configured by the recovery.
     */
    event RpRecovered(uint64 indexed rpId, address indexed previousManager, address newManager, address newSigner);

    ////////////////////////////////////////////////////////////
    //                    PUBLIC FUNCTIONS                    //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Initializes V2 registrar authorization during a proxy upgrade.
     * @param initialRegistrar The first account authorized to register RPs.
     */
    function initializeV2(address initialRegistrar) external;

    /**
     * @notice Returns whether an account may register RPs.
     * @param registrar The account to inspect.
     */
    function isRegistrar(address registrar) external view returns (bool);

    ////////////////////////////////////////////////////////////
    //                    OWNER FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Grants or revokes an account's ability to register RPs.
     * @param registrar The account to update.
     * @param authorized Whether the account should be authorized.
     */
    function setRegistrar(address registrar, bool authorized) external;

    /**
     * @notice Reassigns an existing RP after an incorrect or unauthorized first registration.
     * @param rpId The RP identifier to recover.
     * @param manager The replacement manager.
     * @param signer The replacement proof-request signer.
     * @param unverifiedWellKnownDomain The replacement well-known domain.
     */
    function recoverRp(uint64 rpId, address manager, address signer, string calldata unverifiedWellKnownDomain) external;
}
