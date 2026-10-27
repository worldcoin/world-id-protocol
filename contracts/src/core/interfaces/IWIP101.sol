// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IWIP101
 * @author World Contributors
 * @dev Interface of the WIP-101 standard for World ID,
 *   RP Request Authorization Method for Smart Contracts.
 */
interface IWIP101 is IERC165 {
    /**
     * @dev The RP request is not valid. The code may be used to provide additional debugging information.
     */
    error RpInvalidRequest(uint256 code);

    /**
     * @notice Verifies a World ID Proof Request is authorized by the RP.
     * @dev Should return whether the RP request is valid and should be honored. The `rpId` is implicit in this request,
     *  any contract implementing this interface will be pointed to in the `RpRegistry`.
     * @param version The version determines the format of the request and the signature.
     * @param nonce Unique nonce for this request
     * @param createdAt Creation timestamp of the request
     * @param expiresAt Expiration timestamp specified for the request
     * @param action Provided action for the request. Importantly, this is already a hashed
     *  action as a field element.
     * @param data Arbitrary data useful for the verification.
     * @return magicValue The expected magic value when the signature is valid. Reverts otherwise.
     *
     * MUST return the bytes4 magic value 0x35dbc8de when function passes (function selector for verifyRpRequest).
     * MUST NOT modify state (view modifier for solc > 0.5)
     * MUST allow external calls
     */
    function verifyRpRequest(
        uint8 version,
        uint256 nonce,
        uint64 createdAt,
        uint64 expiresAt,
        uint256 action,
        bytes calldata data
    ) external view returns (bytes4 magicValue);
}
