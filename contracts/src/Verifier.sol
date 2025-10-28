// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {CredentialSchemaIssuerRegistry} from "./CredentialSchemaIssuerRegistry.sol";
import {AccountRegistry} from "./AccountRegistry.sol";
import {IRpRegistry, Types} from "./interfaces/RpRegistry.sol";

/**
 * @title Verifier
 * @notice Verifies nullifier proofs for World ID credentials
 * @dev Coordinates verification between credential issuer registry, account registry, and RP registry
 */
contract Verifier is Ownable2Step {
    /// @notice Registry for credential schema and issuer management
    CredentialSchemaIssuerRegistry public credentialSchemaIssuerRegistry;

    /// @notice Registry for account and authenticator management
    AccountRegistry public accountRegistry;

    /// @notice Registry for relying party nullifier proof verification
    IRpRegistry public rpRegistry;

    /**
     * @notice Initializes the Verifier contract with required registries
     * @param _credentialIssuerRegistry Address of the CredentialSchemaIssuerRegistry contract
     * @param _accountRegistry Address of the AccountRegistry contract
     */
    constructor(address _credentialIssuerRegistry, address _accountRegistry) Ownable(msg.sender) {
        credentialSchemaIssuerRegistry = CredentialSchemaIssuerRegistry(_credentialIssuerRegistry);
        accountRegistry = AccountRegistry(_accountRegistry);
    }

    /**
     * @notice Emitted when the credential schema issuer registry is updated
     * @param oldCredentialSchemaIssuerRegistry Previous registry address
     * @param newCredentialSchemaIssuerRegistry New registry address
     */
    event CredentialSchemaIssuerRegistryUpdated(
        address oldCredentialSchemaIssuerRegistry, address newCredentialSchemaIssuerRegistry
    );

    /**
     * @notice Emitted when the account registry is updated
     * @param oldAccountRegistry Previous registry address
     * @param newAccountRegistry New registry address
     */
    event AccountRegistryUpdated(address oldAccountRegistry, address newAccountRegistry);

    /**
     * @notice Emitted when the RP registry is updated
     * @param oldRpRegistry Previous registry address
     * @param newRpRegistry New registry address
     */
    event RpRegistryUpdated(address oldRpRegistry, address newRpRegistry);

    /**
     * @notice Verifies a nullifier proof for a World ID credential
     * @dev Validates the authenticator root, credential issuer registration, and delegates to RP registry for proof verification
     * @param nullifier The nullifier hash to verify uniqueness
     * @param action The action identifier
     * @param rpId The relying party identifier
     * @param accountCommitment The account commitment from the World ID
     * @param nonce The nonce used in the proof
     * @param signalHash The hash of the signal being signed
     * @param authenticatorRoot The merkle root of the authenticator set
     * @param proofTimestamp The timestamp when the proof was generated
     * @param credentialIssuerId The ID of the credential issuer
     * @param proof The Groth16 proof
     * @return bool True if the proof is valid, false otherwise
     */
    function verify(
        uint256 nullifier,
        uint256 action,
        uint128 rpId,
        uint256 accountCommitment,
        uint256 nonce,
        uint256 signalHash,
        uint256 authenticatorRoot,
        uint256 proofTimestamp,
        uint256 credentialIssuerId,
        Types.Groth16Proof calldata proof
    ) external view returns (bool) {
        require(accountRegistry.isValidRoot(authenticatorRoot), "Invalid authenticator root");

        CredentialSchemaIssuerRegistry.Pubkey memory credentialIssuerPubkey =
            credentialSchemaIssuerRegistry.issuerSchemaIdToPubkey(credentialIssuerId);
        require(credentialIssuerPubkey.x != 0 && credentialIssuerPubkey.y != 0, "Credential issuer not registered");

        require(address(rpRegistry) != address(0), "RP Registry not set");

        return rpRegistry.verifyNullifierProof(
            nullifier,
            action,
            rpId,
            accountCommitment,
            nonce,
            signalHash,
            authenticatorRoot,
            proofTimestamp,
            credentialIssuerPubkey,
            proof
        );
    }

    /**
     * @notice Updates the credential schema issuer registry address
     * @dev Only callable by the contract owner
     * @param _credentialSchemaIssuerRegistry The new credential schema issuer registry address
     */
    function updateCredentialSchemaIssuerRegistry(address _credentialSchemaIssuerRegistry) external onlyOwner {
        address oldCredentialSchemaIssuerRegistry = address(credentialSchemaIssuerRegistry);
        credentialSchemaIssuerRegistry = CredentialSchemaIssuerRegistry(_credentialSchemaIssuerRegistry);
        emit CredentialSchemaIssuerRegistryUpdated(oldCredentialSchemaIssuerRegistry, _credentialSchemaIssuerRegistry);
    }

    /**
     * @notice Updates the account registry address
     * @dev Only callable by the contract owner
     * @param _accountRegistry The new account registry address
     */
    function updateAccountRegistry(address _accountRegistry) external onlyOwner {
        address oldAccountRegistry = address(accountRegistry);
        accountRegistry = AccountRegistry(_accountRegistry);
        emit AccountRegistryUpdated(oldAccountRegistry, _accountRegistry);
    }

    /**
     * @notice Updates the RP registry address
     * @dev Only callable by the contract owner
     * @param _rpRegistry The new RP registry address
     */
    function updateRpRegistry(address _rpRegistry) external onlyOwner {
        address oldRpRegistry = address(rpRegistry);
        rpRegistry = IRpRegistry(_rpRegistry);
        emit RpRegistryUpdated(oldRpRegistry, _rpRegistry);
    }
}
