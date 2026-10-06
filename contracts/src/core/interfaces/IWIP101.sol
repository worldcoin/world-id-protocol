// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IWIP101
 * @author World Contributors
 * @notice Contract-based RP request authorization (WIP-101).
 */
interface IWIP101 is IERC165 {
    error RpInvalidRequest(uint256 code);

    /// @notice Returns `0x35dbc8de` when the RP authorizes the request.
    function verifyRpRequest(
        uint8 version,
        uint256 nonce,
        uint64 createdAt,
        uint64 expiresAt,
        uint256 action,
        bytes calldata data
    ) external view returns (bytes4 magicValue);
}
