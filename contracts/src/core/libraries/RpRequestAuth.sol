// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {IWIP101} from "../interfaces/IWIP101.sol";

/// @title RpRequestAuth
/// @author World Contributors
/// @notice Verifies that an RP authorized a World ID proof request, accepting exactly what the OPRF nodes accept.
library RpRequestAuth {
    /// @notice Version byte of the RP signature message.
    uint8 internal constant VERSION = 0x01;

    /// @notice Maximum accepted WIP-101 verification data, in bytes (WIP-107 §4.5).
    uint256 internal constant MAX_WIP101_DATA_LENGTH = 1024;

    /// @dev Order of the secp256k1 group.
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @notice The EOA signature is malformed or was not produced by the RP signer.
    error InvalidRpSignature();
    /// @notice WIP-101 data was supplied for an EOA signer.
    error Wip101DataOnEoa();
    /// @notice The signer has code but does not support `IWIP101` through ERC-165.
    error Wip101Unsupported();
    /// @notice The WIP-101 data exceeds `MAX_WIP101_DATA_LENGTH`.
    error Wip101DataTooLong();
    /// @notice The WIP-101 signer reverted or did not return the magic value.
    error Wip101Rejected();

    /// @notice The RP signature message `version || nonce || createdAt || expiresAt || action`, 81 bytes, as built
    ///  by `world_id_primitives::rp::compute_rp_signature_msg` for a request with an action.
    function message(uint256 nonce, uint64 createdAt, uint64 expiresAt, uint256 action)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(VERSION, nonce, createdAt, expiresAt, action);
    }

    /// @notice Reverts unless `signer` authorized the request. A signer without code is an EOA and must have signed
    ///  `message` under EIP-191; a signer with code must authorize it through WIP-101 `verifyRpRequest`.
    /// @dev The message binds neither `rpId` nor the OPRF key, so RPs that share a signer can use each other's
    ///  requests. Each RP should use its own signer.
    function verify(
        address signer,
        uint256 nonce,
        uint64 createdAt,
        uint64 expiresAt,
        uint256 action,
        bytes calldata signature,
        bytes calldata wip101Data
    ) internal view {
        if (signer.code.length == 0) {
            if (wip101Data.length != 0) revert Wip101DataOnEoa();
            bytes32 digest = MessageHashUtils.toEthSignedMessageHash(message(nonce, createdAt, expiresAt, action));
            address recovered = recover(digest, signature);
            if (recovered == address(0) || recovered != signer) revert InvalidRpSignature();
        } else {
            if (wip101Data.length > MAX_WIP101_DATA_LENGTH) revert Wip101DataTooLong();
            if (!ERC165Checker.supportsInterface(signer, type(IWIP101).interfaceId)) revert Wip101Unsupported();
            // Low-level call so malformed return data maps to `Wip101Rejected` instead of a decode revert.
            (bool ok, bytes memory result) = signer.staticcall(
                abi.encodeCall(IWIP101.verifyRpRequest, (VERSION, nonce, createdAt, expiresAt, action, wip101Data))
            );
            if (!ok || result.length != 32 || bytes32(result) != bytes32(IWIP101.verifyRpRequest.selector)) {
                revert Wip101Rejected();
            }
        }
    }

    /// @notice Recovers the signer of a 65-byte `r || s || v` signature over `digest`, or `address(0)` if invalid.
    /// @dev Mirrors alloy's `Signature::from_raw` and `recover_from_prehash` used by the OPRF nodes: `v` may be
    ///  0/1, 27/28 or an EIP-155 value (35 and above), and a high-`s` signature is normalized to low-`s` (BIP-62).
    function recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        if (signature.length != 65) return address(0);
        bytes32 r = bytes32(signature[0:32]);
        uint256 s = uint256(bytes32(signature[32:64]));
        uint8 v = uint8(signature[64]);

        if (v > 1 && v != 27 && v != 28 && v < 35) return address(0);
        bool parity = v % 2 == (v <= 1 ? 1 : 0);
        if (s == 0 || s >= SECP256K1_N) return address(0);
        if (s > SECP256K1_N / 2) {
            (s, parity) = (SECP256K1_N - s, !parity);
        }

        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, parity ? 28 : 27, r, bytes32(s));
        return err == ECDSA.RecoverError.NoError ? recovered : address(0);
    }
}
