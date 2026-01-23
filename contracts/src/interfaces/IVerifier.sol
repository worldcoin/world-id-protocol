// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {ICredentialSchemaIssuerRegistry} from "./ICredentialSchemaIssuerRegistry.sol";
import {IWorldIDRegistry} from "./IWorldIDRegistry.sol";
import {IVerifierNullifier} from "./IVerifierNullifier.sol";

/**
 * @title IVerifier
 * @author World Contributors
 * @notice Interface for verifying nullifier proofs for World ID credentials
 * @dev Coordinates verification between the World ID registry, the credential schema issuer registry, and the OPRF key registry
 */
interface IVerifier {
    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Thrown when the proof timestamp is too old, exceeding the allowed proof timestamp delta.
     */
    error OutdatedNullifier();

    /**
     * @dev Thrown when the proof timestamp is in the future (greater than the current block timestamp).
     */
    error NullifierFromFuture();

    /**
     * @dev Thrown when the provided authenticator root is not valid in the World ID registry.
     */
    error InvalidMerkleRoot();

    /**
     * @dev Thrown when the credential issuer schema ID is not registered in the credential schema issuer registry.
     */
    error UnregisteredIssuerSchemaId();

    /**
     * @dev Thrown when setting an external contract address to the zero address.
     */
    error ZeroAddress();

    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Emitted when the credential schema issuer registry is updated
     */
    event CredentialSchemaIssuerRegistryUpdated(
        address oldCredentialSchemaIssuerRegistry, address newCredentialSchemaIssuerRegistry
    );

    /**
     * @notice Emitted when the World ID Registry is updated
     */
    event WorldIDRegistryUpdated(address oldWorldIDRegistry, address newWorldIDRegistry);

    /**
     * @notice Emitted when the OPRF key registry is updated
     */
    event OprfKeyRegistryUpdated(address oldOprfKeyRegistry, address newOprfKeyRegistry);

    /**
     * @notice Emitted when the Groth16Verifier is updated
     */
    event Groth16VerifierNullifierUpdated(address oldGroth16Verifier, address newGroth16Verifier);

    /**
     * @notice Emitted when the proof timestamp delta is updated
     */
    event ProofTimestampDeltaUpdated(uint256 oldProofTimestampDelta, uint256 newProofTimestampDelta);

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Verifies a Uniqueness Proof for a specific World ID.
     */
    function verify(
        uint256 nullifier,
        uint256 action,
        uint64 rpId,
        uint256 sessionId,
        uint256 nonce,
        uint256 signalHash,
        uint256 authenticatorRoot,
        uint256 proofTimestamp,
        uint256 credentialIssuerId,
        uint256 credentialGenesisIssuedAtMin,
        uint256[4] calldata compressedProof
    ) external view;

    ////////////////////////////////////////////////////////////
    //                    OWNER FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Updates the credential schema issuer registry address
     */
    function updateCredentialSchemaIssuerRegistry(address _credentialSchemaIssuerRegistry) external;

    /**
     * @notice Updates the World ID registry address
     */
    function updateWorldIDRegistry(address _worldIDRegistry) external;

    /**
     * @notice Updates the OPRF key registry address
     */
    function updateOprfKeyRegistry(address _oprfKeyRegistry) external;

    /**
     * @notice Updates the Nullifier Verifier address
     */
    function updateVerifierNullifier(address _verifierNullifier) external;

    /**
     * @notice Updates the proof timestamp delta
     */
    function updateProofTimestampDelta(uint256 _proofTimestampDelta) external;
}

