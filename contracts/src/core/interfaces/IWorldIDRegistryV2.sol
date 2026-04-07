// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IWorldIDRegistry} from "./IWorldIDRegistry.sol";

/**
 * @title IWorldIDRegistry
 * @author World Contributors
 * @notice Interface for the World ID Registry contract.
 * @dev Manages World IDs and the authenticators which are authorized to perform operations on behalf of them.
 */
interface IWorldIDRegistryV2 is IWorldIDRegistry {
    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Thrown when the provided authenticator address does not match the type stored in the bitmap.
     *      For limited-signing authenticators (WIP-104), address must be zero. For management-key
     *      authenticators, address must be non-zero.
     */
    error AuthenticatorTypeMismatch(uint32 pubkeyId, bool isLimitedSigner);

    /**
     * @dev The requested method is no longer supported.
     */
    error MethodUnsupported();
}
