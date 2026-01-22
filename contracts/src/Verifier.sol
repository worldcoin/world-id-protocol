// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {OprfKeyRegistry} from "oprf-key-registry/src/OprfKeyRegistry.sol";
import {BabyJubJub} from "oprf-key-registry/src/BabyJubJub.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ICredentialSchemaIssuerRegistry} from "./interfaces/ICredentialSchemaIssuerRegistry.sol";
import {IWorldIDRegistry} from "./interfaces/IWorldIDRegistry.sol";
import {IVerifierNullifier} from "./interfaces/IVerifierNullifier.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";

/**
 * @title Verifier
 * @notice Verifies nullifier proofs for World ID credentials
 * @dev Coordinates verification between the World ID registry, the credential schema issuer registry, and the OPRF key registry
 */
contract Verifier is Initializable, Ownable2StepUpgradeable, UUPSUpgradeable, IVerifier {
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
    ICredentialSchemaIssuerRegistry public credentialSchemaIssuerRegistry;

    /// @notice Registry for World IDs and authenticator management
    IWorldIDRegistry public worldIDRegistry;

    /// @notice Registry for OPRF key management
    OprfKeyRegistry public oprfKeyRegistry;

    /// @notice Contract for nullifier proof verification
    IVerifierNullifier public verifierNullifier;

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
     * @param _verifierNullifier Address of the VerifierNullifier contract for the nullifier circuit.
     * @param _proofTimestampDelta uint256 Allowed delta for proof timestamps.
     */
    function initialize(
        address _credentialIssuerRegistry,
        address _worldIDRegistry,
        address _oprfKeyRegistry,
        address _verifierNullifier,
        uint256 _proofTimestampDelta
    ) public virtual initializer {
        __Ownable_init(msg.sender);
        __Ownable2Step_init();
        credentialSchemaIssuerRegistry = ICredentialSchemaIssuerRegistry(_credentialIssuerRegistry);
        worldIDRegistry = IWorldIDRegistry(_worldIDRegistry);
        verifierNullifier = IVerifierNullifier(_verifierNullifier);
        oprfKeyRegistry = OprfKeyRegistry(_oprfKeyRegistry);
        proofTimestampDelta = _proofTimestampDelta;
        treeDepth = worldIDRegistry.getTreeDepth();
    }

    /**
     * @notice Verifies a Uniqueness Proof for a specific World ID.
     * @dev Validates the authenticator root, credential issuer registration, and delegates to Groth16VerifierNullifier for proof verification
     * @param nullifier The nullifier hash to verify uniqueness
     * @param action The action identifier
     * @param rpId The relying party identifier
     * @param sessionId The identifier for a specific RPW-specific session.
     * @param nonce The nonce used in the proof
     * @param signalHash The hash of the signal which was committed in the proof
     * @param authenticatorRoot The merkle root of the authenticator set
     * @param proofTimestamp The timestamp when the proof was generated
     * @param credentialIssuerId The ID of the credential issuer
     * @param credentialGenesisIssuedAtMin (Proof constraint, public input). The minimum timestamp for when the credential
     *   was **initially** issued. This may be set to `0` to essentially skip the constraint.
     * @param compressedProof The compressed Groth16 proof
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
    ) external view virtual onlyProxy onlyInitialized {
        require(address(oprfKeyRegistry) != address(0), "OPRF key Registry not set");
        require(address(verifierNullifier) != address(0), "verifierNullifier not set");

        if (!worldIDRegistry.isValidRoot(authenticatorRoot)) {
            revert InvalidMerkleRoot();
        }

        ICredentialSchemaIssuerRegistry.Pubkey memory credentialIssuerPubkey =
            credentialSchemaIssuerRegistry.issuerSchemaIdToPubkey(credentialIssuerId);
        if (credentialIssuerPubkey.x == 0 || credentialIssuerPubkey.y == 0) {
            revert UnregisteredIssuerSchemaId();
        }

        // NOTICE: Currently the `oprfKeyId` is the same as the `rpId`. This may change in the future in the `RpRegistry` contract
        uint160 oprfKeyId = uint160(rpId);
        BabyJubJub.Affine memory oprfPublicKey = oprfKeyRegistry.getOprfPublicKey(oprfKeyId);

        // do not allow proofs from the future
        if (proofTimestamp > block.timestamp) {
            revert NullifierFromFuture();
        }

        // do not allow proofs older than proofTimestampDelta
        if (proofTimestamp + proofTimestampDelta < block.timestamp) {
            revert OutdatedNullifier();
        }

        uint256[15] memory pubSignals;

        pubSignals[0] = nullifier;
        pubSignals[1] = credentialIssuerId;
        pubSignals[2] = credentialIssuerPubkey.x;
        pubSignals[3] = credentialIssuerPubkey.y;
        pubSignals[4] = proofTimestamp;
        pubSignals[5] = credentialGenesisIssuedAtMin;
        pubSignals[6] = authenticatorRoot;
        pubSignals[7] = treeDepth;
        pubSignals[8] = uint256(rpId);
        pubSignals[9] = action;
        pubSignals[10] = oprfPublicKey.x;
        pubSignals[11] = oprfPublicKey.y;
        pubSignals[12] = signalHash;
        pubSignals[13] = nonce;
        pubSignals[14] = sessionId;

        verifierNullifier.verifyCompressedProof(compressedProof, pubSignals);
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
        credentialSchemaIssuerRegistry = ICredentialSchemaIssuerRegistry(_credentialSchemaIssuerRegistry);
        emit CredentialSchemaIssuerRegistryUpdated(oldCredentialSchemaIssuerRegistry, _credentialSchemaIssuerRegistry);
    }

    /**
     * @notice Updates the World ID registry address
     * @dev Only callable by the contract owner
     * @param _worldIDRegistry The new World ID Registry address
     */
    function updateWorldIDRegistry(address _worldIDRegistry) external virtual onlyOwner onlyProxy onlyInitialized {
        address oldWorldIDRegistry = address(worldIDRegistry);
        worldIDRegistry = IWorldIDRegistry(_worldIDRegistry);
        treeDepth = worldIDRegistry.getTreeDepth();
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
     * @notice Updates the Nullifier Verifier address
     * @dev Only callable by the contract owner
     * @param _verifierNullifier The new Groth16 Verifier address
     */
    function updateVerifierNullifier(address _verifierNullifier) external virtual onlyOwner onlyProxy onlyInitialized {
        address oldVerifier = address(verifierNullifier);
        verifierNullifier = IVerifierNullifier(_verifierNullifier);
        emit Groth16VerifierNullifierUpdated(oldVerifier, _verifierNullifier);
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
