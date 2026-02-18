// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Verifier} from "@world-id-core/Verifier.sol";
import {BabyJubJub} from "lib/oprf-key-registry/src/BabyJubJub.sol";

/**
 * @title IWorldID
 * @author World Contributors
 * @notice Interface for verifying World ID proofs (Uniqueness and Session proofs).
 * @dev In addition to verifying the Groth16 Proof, it verifies relevant public inputs to the
 *  circuits through checks with the WorldIDRegistry, CredentialSchemaIssuerRegistry, and OprfKeyRegistry.
 */
interface IWorldID {
    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Emitted when the credential schema issuer registry is updated.
     * @param oldCredentialSchemaIssuerRegistry The previous registry address.
     * @param newCredentialSchemaIssuerRegistry The new registry address.
     */
    event CredentialSchemaIssuerRegistryUpdated(
        address oldCredentialSchemaIssuerRegistry, address newCredentialSchemaIssuerRegistry
    );

    /**
     * @notice Emitted when the World ID Registry is updated.
     * @param oldWorldIDRegistry The previous registry address.
     * @param newWorldIDRegistry The new registry address.
     */
    event WorldIDRegistryUpdated(address oldWorldIDRegistry, address newWorldIDRegistry);

    /**
     * @notice Emitted when the OPRF key registry is updated.
     * @param oldOprfKeyRegistry The previous registry address.
     * @param newOprfKeyRegistry The new registry address.
     */
    event OprfKeyRegistryUpdated(address oldOprfKeyRegistry, address newOprfKeyRegistry);

    /**
     * @notice Emitted when the verifier is updated.
     * @param oldVerifier The previous verifier address.
     * @param newVerifier The new verifier address.
     */
    event VerifierUpdated(address oldVerifier, address newVerifier);

    /**
     * @notice Emitted when the minimum expiration threshold is updated.
     * @param oldMinExpirationThreshold The previous minimum expiration threshold value.
     * @param newMinExpirationThreshold The new minimum expiration threshold value.
     */
    event MinExpirationThresholdUpdated(uint64 oldMinExpirationThreshold, uint64 newMinExpirationThreshold);

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Verifies a Uniqueness Proof.
     * @dev Validates the World ID registration and inclusion, credential issuer registration,
     *   and delegates to the Groth16 proof verifier for proof verification.
     * @dev Public inputs refer to the ZK-circuit public inputs.
     * @param nullifier Public output. A unique, one-time identifier derived from (user, rpId, action) that
     *   lets RPs detect duplicate actions without learning who the user is.
     * @param action Public input. An RP-defined context that scopes what the user is proving uniqueness on.
     *  This parameter generally expects a hashed version reduced to the field.
     * @param rpId Public input. Registered RP identifier from the `RpRegistry`.
     * @param nonce Public input. Unique nonce for this request provided by the RP.
     * @param signalHash Public input. Hash of arbitrary data provided by the RP that gets cryptographically bound into the proof.
     * @param expiresAtMin Public input. The minimum expiration required for the Credential used in the proof. If the constraint is not required,
     *   it should use the current time as the minimum expiration. The Authenticator will normally expose the effective input used in the proof.
     * @param issuerSchemaId Public input. Unique identifier for the credential schema and issuer pair.
     * @param credentialGenesisIssuedAtMin Public input. Minimum `genesis_issued_at` timestamp that the used credential
     *   must meet. Can be set to 0 to skip.
     * @param zeroKnowledgeProof Encoded World ID Proof. Internally, the first 4 elements are a
     *   compressed Groth16 proof [a (G1), b (G2), b (G2), c (G1)], and the last element is the Merkle root from the `WorldIDRegistry`.
     */
    function verify(
        uint256 nullifier,
        uint256 action,
        uint64 rpId,
        uint256 nonce,
        uint256 signalHash,
        uint64 expiresAtMin,
        uint64 issuerSchemaId,
        uint256 credentialGenesisIssuedAtMin,
        uint256[5] calldata zeroKnowledgeProof
    ) external view;

    /**
     * @notice Verifies a Session Proof.
     * @dev Validates the World ID registration and inclusion, credential issuer registration,
     *   and delegates to the Groth16 proof verifier for proof verification.
     * @dev Public inputs refer to the ZK-circuit public inputs.
     * @param rpId Public input. Registered RP identifier from the `RpRegistry`.
     * @param nonce Public input. Unique nonce for this request provided by the RP.
     * @param signalHash Public input. Hash of arbitrary data provided by the RP that gets cryptographically bound into the proof.
     * @param expiresAtMin Public input. The minimum expiration required for the Credential used in the proof. If the constraint is not required,
     *   it should use the current time as the minimum expiration. The Authenticator will normally expose the effective input used in the proof.
     * @param issuerSchemaId Public input. Unique identifier for the credential schema and issuer pair.
     * @param credentialGenesisIssuedAtMin Public input. Minimum `genesis_issued_at` timestamp that the used credential
     *   must meet. Can be set to 0 to skip.
     * @param sessionId Public input. Session identifier that connects proofs for the same user+RP pair across requests.
     * @param sessionNullifier Session nullifier tuple: index 0 is the nullifier, index 1 is a randomly generated action.
     * @param zeroKnowledgeProof Encoded World ID Proof. Internally, the first 4 elements are a
     *   compressed Groth16 proof [a (G1), b (G2), b (G2), c (G1)], and the last element is the Merkle root from the `WorldIDRegistry`.
     */
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
    ) external view;

    /**
     * @notice Verifies a World ID Proof and the relevant public signals.
     * @dev This method can be used to verify any type of World ID Proof and requires explicit inputs.
     *   Using `verify` or `verifySession` is recommended for most use cases.
     * @dev Public inputs refer to the ZK-circuit public inputs.
     * @param nullifier Public output. A unique, one-time identifier derived from (user, rpId, action) that
     *   lets RPs detect duplicate actions without learning who the user is.
     * @param action Public input. An RP-defined context that scopes what the user is proving uniqueness on.
     *  This parameter generally expects a hashed version reduced to the field.
     * @param rpId Public input. Registered RP identifier from the `RpRegistry`.
     * @param nonce Public input. Unique nonce for this request provided by the RP.
     * @param signalHash Public input. Hash of arbitrary data provided by the RP that gets cryptographically bound into the proof.
     * @param expiresAtMin Public input. The minimum expiration required for the Credential used in the proof. If the constraint is not required,
     *   it should use the current time as the minimum expiration. The Authenticator will normally expose the effective input used in the proof.
     * @param issuerSchemaId Public input. Unique identifier for the credential schema and issuer pair.
     * @param credentialGenesisIssuedAtMin Public input. Minimum `genesis_issued_at` timestamp that the used credential
     *   must meet. Can be set to 0 to skip.
     * @param sessionId Public input. Session identifier that connects proofs for the same user+RP pair. Set to 0 for Uniqueness Proofs.
     * @param zeroKnowledgeProof Encoded World ID Proof. Internally, the first 4 elements are a
     *   compressed Groth16 proof [a (G1), b (G2), b (G2), c (G1)], and the last element is the Merkle root from the `WorldIDRegistry`.
     */
    function verifyProofAndSignals(
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
    ) external view;

    /**
     * @notice Checks if a given Merkle root is valid in the `WorldIDRegistry`.
     * @param root The Merkle root to check for validity.
     * @return True if the root is valid, false otherwise.
     */
    function isValidRoot(uint256 root) external view returns (bool);

    /**
     * @notice Returns the verifier contract address.
     * @return The address of the Verifier contract.
     */
    function VERIFIER() external view returns (Verifier);

    /**
     * @notice Returns the minimum expiration threshold.
     * @return The minimum expiration threshold in seconds.
     */
    function MIN_EXPIRATION_THRESHOLD() external view returns (uint64);

    /**
     * @notice Returns the root validity window.
     * @return The root validity window in seconds.
     */
    function ROOT_VALIDITY_WINDOW() external view returns (uint256);

    /**
     * @notice Returns the tree depth.
     * @return The depth of the Merkle tree in WorldIDRegistry.
     */
    function TREE_DEPTH() external view returns (uint256);
}
