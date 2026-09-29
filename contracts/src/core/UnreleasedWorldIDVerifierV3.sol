// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {WorldIDVerifierV2} from "./WorldIDVerifierV2.sol";
import {IWorldIDVerifier} from "./interfaces/IWorldIDVerifier.sol";
import {IWorldIDVerifierV3} from "./interfaces/UnreleasedIWorldIDVerifierV3.sol";
import {PackedAccountData} from "./libraries/PackedAccountData.sol";

/**
 * @title WorldIDVerifierV3
 * @author World Contributors
 * @notice Verifies World ID proofs (Uniqueness and Session proofs).
 * @dev In addition to verifying the Groth16 Proof, it verifies relevant public inputs to the
 *  circuits through checks with the WorldIDRegistry, CredentialSchemaIssuerRegistry, and OprfKeyRegistry.
 * @custom:repo https://github.com/world-id/world-id-protocol
 */
contract WorldIDVerifierV3 is IWorldIDVerifierV3, WorldIDVerifierV2 {
    /// @inheritdoc IWorldIDVerifierV3
    /// @dev Returns 0 for an unknown authenticator, matching `WorldIDRegistry.getPackedAccountData`.
    function getPackedAccountData(address authenticatorAddress)
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (uint256)
    {
        uint256 packedAccountData = _worldIDRegistry.getPackedAccountData(authenticatorAddress);
        uint64 leafIndex = PackedAccountData.leafIndex(packedAccountData);

        // `recoverAccount` bumps the account's counter but leaves the old authenticator mapped
        if (PackedAccountData.recoveryCounter(packedAccountData) < _worldIDRegistry.getRecoveryCounter(leafIndex)) {
            revert AuthenticatorRevoked();
        }

        return packedAccountData;
    }

    /// @inheritdoc IWorldIDVerifierV3
    function getUnverifiedPackedAccountData(address authenticatorAddress)
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (uint256)
    {
        return _worldIDRegistry.getPackedAccountData(authenticatorAddress);
    }

    /// @inheritdoc IWorldIDVerifierV3
    function verifyWithSession(
        uint256 nullifier,
        uint256 action,
        uint64 rpId,
        uint256 nonce,
        uint256 signalHash,
        uint64 expiresAtMin,
        uint64 issuerSchemaId,
        uint256 credentialGenesisIssuedAtMin,
        uint256 sessionId,
        uint256[5] calldata zeroKnowledgeProof
    ) external view virtual override onlyProxy onlyInitialized {
        if (uint8(action >> 248) != uint8(0)) {
            revert InvalidAction();
        }
        if (sessionId == 0) {
            revert InvalidSessionId();
        }

        verifyProofAndSignals(
            nullifier,
            action,
            rpId,
            nonce,
            signalHash,
            expiresAtMin,
            issuerSchemaId,
            credentialGenesisIssuedAtMin,
            sessionId,
            zeroKnowledgeProof
        );
    }

    /// @inheritdoc IWorldIDVerifier
    /// @dev Reverts with `InvalidSessionId` when `sessionId` is zero. The action prefix check is
    ///  repeated from V2 because Solidity cannot `super`-call an `external` function.
    function verifySession(
        uint64 rpId,
        uint256 nonce,
        uint256 signalHash,
        uint64 expiresAtMin,
        uint64 issuerSchemaId,
        uint256 credentialGenesisIssuedAtMin,
        uint256 sessionId,
        uint256[2] calldata sessionNullifier,
        uint256[5] calldata zeroKnowledgeProof
    ) external view virtual override(IWorldIDVerifier, WorldIDVerifierV2) onlyProxy onlyInitialized {
        uint256 action = sessionNullifier[1];
        if (uint8(action >> 248) != uint8(2)) {
            revert InvalidAction();
        }
        if (sessionId == 0) {
            revert InvalidSessionId();
        }

        verifyProofAndSignals(
            sessionNullifier[0],
            action,
            rpId,
            nonce,
            signalHash,
            expiresAtMin,
            issuerSchemaId,
            credentialGenesisIssuedAtMin,
            sessionId,
            zeroKnowledgeProof
        );
    }
}
