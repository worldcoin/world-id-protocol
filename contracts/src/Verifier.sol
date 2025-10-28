// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {CredentialSchemaIssuerRegistry} from "./CredentialSchemaIssuerRegistry.sol";
import {AccountRegistry} from "./AccountRegistry.sol";
import {IRpRegistry, Types} from "./interfaces/RpRegistry.sol";

/**
 * @title Verifier
 * @notice Verifies nullifier proofs for World ID credentials
 * @dev Coordinates verification between credential issuer registry, account registry, and RP registry
 */
contract Verifier is Initializable, Ownable2StepUpgradeable, UUPSUpgradeable {
    error ImplementationNotInitialized();

    modifier onlyInitialized() {
        if (_getInitializedVersion() == 0) {
            revert ImplementationNotInitialized();
        }
        _;
    }
    /// @notice Registry for credential schema and issuer management
    CredentialSchemaIssuerRegistry public credentialSchemaIssuerRegistry;

    /// @notice Registry for account and authenticator management
    AccountRegistry public accountRegistry;

    /// @notice Registry for relying party nullifier proof verification
    IRpRegistry public rpRegistry;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the Verifier contract with required registries
     * @param _credentialIssuerRegistry Address of the CredentialSchemaIssuerRegistry contract
     * @param _accountRegistry Address of the AccountRegistry contract
     */
    function initialize(address _credentialIssuerRegistry, address _accountRegistry) public virtual initializer {
        __Ownable_init(msg.sender);
        __Ownable2Step_init();
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
    ) external view virtual onlyProxy onlyInitialized returns (bool) {
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
    function updateCredentialSchemaIssuerRegistry(address _credentialSchemaIssuerRegistry)
        external
        virtual
        onlyOwner
        onlyProxy
        onlyInitialized
    {
        address oldCredentialSchemaIssuerRegistry = address(credentialSchemaIssuerRegistry);
        credentialSchemaIssuerRegistry = CredentialSchemaIssuerRegistry(_credentialSchemaIssuerRegistry);
        emit CredentialSchemaIssuerRegistryUpdated(oldCredentialSchemaIssuerRegistry, _credentialSchemaIssuerRegistry);
    }

    /**
     * @notice Updates the account registry address
     * @dev Only callable by the contract owner
     * @param _accountRegistry The new account registry address
     */
    function updateAccountRegistry(address _accountRegistry) external virtual onlyOwner onlyProxy onlyInitialized {
        address oldAccountRegistry = address(accountRegistry);
        accountRegistry = AccountRegistry(_accountRegistry);
        emit AccountRegistryUpdated(oldAccountRegistry, _accountRegistry);
    }

    /**
     * @notice Updates the RP registry address
     * @dev Only callable by the contract owner
     * @param _rpRegistry The new RP registry address
     */
    function updateRpRegistry(address _rpRegistry) external virtual onlyOwner onlyProxy onlyInitialized {
        address oldRpRegistry = address(rpRegistry);
        rpRegistry = IRpRegistry(_rpRegistry);
        emit RpRegistryUpdated(oldRpRegistry, _rpRegistry);
    }

    ////////////////////////////////////////////////////////////
    //                    Upgrade Authorization               //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Authorize upgrade to a new implementation
     * @param newImplementation Address of the new implementation contract
     * @notice Only the contract owner can authorize upgrades
     */
    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner {}

    ////////////////////////////////////////////////////////////
    //                    Storage Gap                         //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Storage gap to allow for future upgrades without storage collisions
     * This reserves 50 storage slots for future state variables
     */
    uint256[50] private __gap;
}
