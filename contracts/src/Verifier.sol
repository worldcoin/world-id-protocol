// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Types} from "oprf-key-registry/src/Types.sol";
import {OprfKeyRegistry} from "oprf-key-registry/src/OprfKeyRegistry.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {CredentialSchemaIssuerRegistry} from "./CredentialSchemaIssuerRegistry.sol";
import {WorldIDRegistry} from "./WorldIDRegistry.sol";
import {Groth16Verifier as Groth16VerifierNullifier} from "./Groth16VerifierNullifier.sol";

/**
 * @title Verifier
 * @notice Verifies nullifier proofs for World ID credentials
 * @dev Coordinates verification between the World ID registry, the credential schema issuer registry, and the OPRF key registry
 */
contract Verifier is Initializable, Ownable2StepUpgradeable, UUPSUpgradeable {
    error ImplementationNotInitialized();

    modifier onlyInitialized() {
        _onlyInitialized();
        _;
    }

    function _onlyInitialized() internal view {
        if (_getInitializedVersion() == 0) {
            revert ImplementationNotInitialized();
        }
    }

    /// @notice Registry for credential schema and issuer management
    CredentialSchemaIssuerRegistry public credentialSchemaIssuerRegistry;

    /// @notice Registry for World IDs and authenticator management
    WorldIDRegistry public worldIDRegistry;

    /// @notice Registry for OPRF key management
    OprfKeyRegistry public oprfKeyRegistry;

    /// @notice Contract for nullifier proof verification
    Groth16VerifierNullifier public groth16VerifierNullifier;

    /// @notice Allowed delta for proof timestamps
    uint256 public proofTimestampDelta;

    /// @notice The depth of the Merkle tree
    uint256 public treeDepth;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the Verifier contract with required registries
     * @param _credentialIssuerRegistry Address of the CredentialSchemaIssuerRegistry contract
     * @param _worldIDRegistry Address of the WorldIDRegistry contract
     * @param _groth16VerifierNullifier Address of the Groth16Verifier contract for the nullifier circuit.
     * @param _proofTimestampDelta uint256 Allowed delta for proof timestamps.
     */
    function initialize(
        address _credentialIssuerRegistry,
        address _worldIDRegistry,
        address _groth16VerifierNullifier,
        uint256 _proofTimestampDelta
    ) public virtual initializer {
        __Ownable_init(msg.sender);
        __Ownable2Step_init();
        credentialSchemaIssuerRegistry = CredentialSchemaIssuerRegistry(_credentialIssuerRegistry);
        worldIDRegistry = WorldIDRegistry(_worldIDRegistry);
        groth16VerifierNullifier = Groth16VerifierNullifier(_groth16VerifierNullifier);
        proofTimestampDelta = _proofTimestampDelta;
        treeDepth = worldIDRegistry.treeDepth();
    }

    /**
     * @notice The nullifier is outdated
     */
    error OutdatedNullifier();

    /**
     * @notice The nullifier is from the future
     */
    error NullifierFromFuture();

    /**
     * @notice Emitted when the credential schema issuer registry is updated
     * @param oldCredentialSchemaIssuerRegistry Previous registry address
     * @param newCredentialSchemaIssuerRegistry New registry address
     */
    event CredentialSchemaIssuerRegistryUpdated(
        address oldCredentialSchemaIssuerRegistry, address newCredentialSchemaIssuerRegistry
    );

    /**
     * @notice Emitted when the World ID Registry is updated
     * @param oldWorldIDRegistry Previous registry address
     * @param newWorldIDRegistry New registry address
     */
    event WorldIDRegistryUpdated(address oldWorldIDRegistry, address newWorldIDRegistry);

    /**
     * @notice Emitted when the OPRF key registry is updated
     * @param oldOprfKeyRegistry Previous registry address
     * @param newOprfKeyRegistry New registry address
     */
    event OprfKeyRegistryUpdated(address oldOprfKeyRegistry, address newOprfKeyRegistry);

    /**
     * @notice Emitted when the Groth16Verifier is updated
     * @param oldGroth16Verifier Previous Groth16Verifier address
     * @param newGroth16Verifier New Groth16Verifier address
     */
    event Groth16VerifierNullifierUpdated(address oldGroth16Verifier, address newGroth16Verifier);

    /**
     * @notice Emitted when the proof timestamp delta is updated
     * @param oldProofTimestampDelta Previous proof timestamp delta
     * @param newProofTimestampDelta New proof timestamp delta
     */
    event ProofTimestampDeltaUpdated(uint256 oldProofTimestampDelta, uint256 newProofTimestampDelta);

    /**
     * @notice Verifies a nullifier proof for a World ID credential
     * @dev Validates the authenticator root, credential issuer registration, and delegates to Groth16VerifierNullifier for proof verification
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
        uint160 rpId,
        uint256 accountCommitment,
        uint256 nonce,
        uint256 signalHash,
        uint256 authenticatorRoot,
        uint256 proofTimestamp,
        uint256 credentialIssuerId,
        Types.Groth16Proof calldata proof
    ) external view virtual onlyProxy onlyInitialized returns (bool) {
        require(worldIDRegistry.isValidRoot(authenticatorRoot), "Invalid authenticator root");

        CredentialSchemaIssuerRegistry.Pubkey memory credentialIssuerPubkey =
            credentialSchemaIssuerRegistry.issuerSchemaIdToPubkey(credentialIssuerId);
        require(credentialIssuerPubkey.x != 0 && credentialIssuerPubkey.y != 0, "Credential issuer not registered");

        require(address(oprfKeyRegistry) != address(0), "OPRF key Registry not set");
        // TODO get from rpId -> oprfKeyId mapping?
        uint160 oprfKeyId = rpId;
        Types.BabyJubJubElement memory oprfPublicKey = oprfKeyRegistry.getOprfPublicKey(oprfKeyId);

        require(address(groth16VerifierNullifier) != address(0), "Groth16Verifier not set");

        // do not allow proofs from the future
        if (proofTimestamp > block.timestamp) {
            revert NullifierFromFuture();
        }
        // do not allow proofs older than proofTimestampDelta
        if (proofTimestamp + proofTimestampDelta < block.timestamp) {
            revert OutdatedNullifier();
        }
        uint256[13] memory pubSignals;

        pubSignals[0] = accountCommitment;
        pubSignals[1] = nullifier;
        pubSignals[2] = credentialIssuerPubkey.x;
        pubSignals[3] = credentialIssuerPubkey.y;
        pubSignals[4] = proofTimestamp;
        pubSignals[5] = authenticatorRoot;
        pubSignals[6] = treeDepth;
        pubSignals[7] = uint256(rpId);
        pubSignals[8] = action;
        pubSignals[9] = oprfPublicKey.x;
        pubSignals[10] = oprfPublicKey.y;
        pubSignals[11] = signalHash;
        pubSignals[12] = nonce;

        return groth16VerifierNullifier.verifyProof(proof.pA, proof.pB, proof.pC, pubSignals);
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
     * @notice Updates the World ID registry address
     * @dev Only callable by the contract owner
     * @param _worldIDRegistry The new World ID Registry address
     */
    function updateWorldIDRegistry(address _worldIDRegistry) external virtual onlyOwner onlyProxy onlyInitialized {
        address oldWorldIDRegistry = address(worldIDRegistry);
        worldIDRegistry = WorldIDRegistry(_worldIDRegistry);
        emit WorldIDRegistryUpdated(oldWorldIDRegistry, _worldIDRegistry);
    }

    /**
     * @notice Updates the OPRF key registry address
     * @dev Only callable by the contract owner
     * @param _oprfKeyRegistry The new OPRF key registry address
     */
    function updateOprfKeyRegistry(address _oprfKeyRegistry) external virtual onlyOwner onlyProxy onlyInitialized {
        address oldOprfKeyRegistry = address(oprfKeyRegistry);
        oprfKeyRegistry = OprfKeyRegistry(_oprfKeyRegistry);
        emit OprfKeyRegistryUpdated(oldOprfKeyRegistry, _oprfKeyRegistry);
    }

    /**
     * @notice Updates the Groth16 Verifier address
     * @dev Only callable by the contract owner
     * @param _groth16Verifier The new Groth16 Verifier address
     */
    function updateGroth16Verifier(address _groth16Verifier) external virtual onlyOwner onlyProxy onlyInitialized {
        address oldVerifier = address(groth16VerifierNullifier);
        groth16VerifierNullifier = Groth16VerifierNullifier(_groth16Verifier);
        emit Groth16VerifierNullifierUpdated(oldVerifier, _groth16Verifier);
    }

    /**
     * @notice Updates the proof timestamp delta
     * @dev Only callable by the contract owner
     * @param _proofTimestampDelta The new proof timestamp delta
     */
    function updateProofTimestampDelta(uint256 _proofTimestampDelta)
        external
        virtual
        onlyOwner
        onlyProxy
        onlyInitialized
    {
        uint256 oldProofTimestampDelta = proofTimestampDelta;
        proofTimestampDelta = _proofTimestampDelta;
        emit ProofTimestampDeltaUpdated(oldProofTimestampDelta, _proofTimestampDelta);
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
