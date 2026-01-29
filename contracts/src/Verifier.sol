// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {OprfKeyRegistry} from "oprf-key-registry/src/OprfKeyRegistry.sol";
import {BabyJubJub} from "oprf-key-registry/src/BabyJubJub.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {CredentialSchemaIssuerRegistry} from "./CredentialSchemaIssuerRegistry.sol";
import {ICredentialSchemaIssuerRegistry} from "./interfaces/ICredentialSchemaIssuerRegistry.sol";
import {WorldIDRegistry} from "./WorldIDRegistry.sol";
import {Verifier as VerifierNullifier} from "./VerifierNullifier.sol";
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

    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    // DO NOT REORDER! To ensure compatibility between upgrades, it is exceedingly important
    // that no reordering of these variables takes place. If reordering happens, a storage
    // clash will occur (effectively a memory safety error).

    /// @notice Registry for credential schema and issuer management
    CredentialSchemaIssuerRegistry public credentialSchemaIssuerRegistry;

    /// @notice Registry for World IDs and authenticator management
    WorldIDRegistry public worldIDRegistry;

    /// @notice Registry for OPRF key management
    OprfKeyRegistry public oprfKeyRegistry;

    /// @notice Contract for nullifier proof verification
    VerifierNullifier public verifierNullifier;

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
        if (_credentialIssuerRegistry == address(0)) revert ZeroAddress();
        if (_worldIDRegistry == address(0)) revert ZeroAddress();
        if (_oprfKeyRegistry == address(0)) revert ZeroAddress();
        if (_verifierNullifier == address(0)) revert ZeroAddress();

        __Ownable_init(msg.sender);
        __Ownable2Step_init();
        credentialSchemaIssuerRegistry = CredentialSchemaIssuerRegistry(_credentialIssuerRegistry);
        worldIDRegistry = WorldIDRegistry(_worldIDRegistry);
        verifierNullifier = VerifierNullifier(_verifierNullifier);
        oprfKeyRegistry = OprfKeyRegistry(_oprfKeyRegistry);
        proofTimestampDelta = _proofTimestampDelta;
        treeDepth = worldIDRegistry.getTreeDepth();
    }

    /// @inheritdoc IVerifier
    function verify(
        uint256 nullifier,
        uint256 action,
        uint64 rpId,
        uint256 nonce,
        uint256 signalHash,
        uint256 proofTimestamp,
        uint64 issuerSchemaId,
        uint256 credentialGenesisIssuedAtMin,
        uint256[5] calldata zeroKnowledgeProof
    ) external view virtual onlyProxy onlyInitialized {
        uint256 merkleRoot = zeroKnowledgeProof[4];
        if (!worldIDRegistry.isValidRoot(merkleRoot)) {
            revert InvalidMerkleRoot();
        }

        ICredentialSchemaIssuerRegistry.Pubkey memory credentialIssuerPubkey =
            credentialSchemaIssuerRegistry.issuerSchemaIdToPubkey(issuerSchemaId);
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
        pubSignals[1] = issuerSchemaId;
        pubSignals[2] = credentialIssuerPubkey.x;
        pubSignals[3] = credentialIssuerPubkey.y;
        pubSignals[4] = proofTimestamp;
        pubSignals[5] = credentialGenesisIssuedAtMin;
        pubSignals[6] = merkleRoot;
        pubSignals[7] = treeDepth;
        pubSignals[8] = uint256(rpId);
        pubSignals[9] = action;
        pubSignals[10] = oprfPublicKey.x;
        pubSignals[11] = oprfPublicKey.y;
        pubSignals[12] = signalHash;
        pubSignals[13] = nonce;

        // For Uniqueness Proofs, the `session_id` is not used, hence the constraint defaults to 0
        // To verify a Session Proof use `verifySession` instead.
        pubSignals[14] = 0;

        uint256[4] memory groth16CompressedProof;
        for (uint256 i = 0; i < 4; i++) {
            groth16CompressedProof[i] = zeroKnowledgeProof[i];
        }

        verifierNullifier.verifyCompressedProof(groth16CompressedProof, pubSignals);
    }

    /// @inheritdoc IVerifier
    function updateCredentialSchemaIssuerRegistry(address _credentialSchemaIssuerRegistry)
        external
        virtual
        onlyOwner
        onlyProxy
        onlyInitialized
    {
        if (_credentialSchemaIssuerRegistry == address(0)) revert ZeroAddress();
        address oldCredentialSchemaIssuerRegistry = address(credentialSchemaIssuerRegistry);
        credentialSchemaIssuerRegistry = CredentialSchemaIssuerRegistry(_credentialSchemaIssuerRegistry);
        emit CredentialSchemaIssuerRegistryUpdated(oldCredentialSchemaIssuerRegistry, _credentialSchemaIssuerRegistry);
    }

    /// @inheritdoc IVerifier
    function updateWorldIDRegistry(address _worldIDRegistry) external virtual onlyOwner onlyProxy onlyInitialized {
        if (_worldIDRegistry == address(0)) revert ZeroAddress();
        address oldWorldIDRegistry = address(worldIDRegistry);
        worldIDRegistry = WorldIDRegistry(_worldIDRegistry);
        treeDepth = worldIDRegistry.getTreeDepth();
        emit WorldIDRegistryUpdated(oldWorldIDRegistry, _worldIDRegistry);
    }

    /// @inheritdoc IVerifier
    function updateOprfKeyRegistry(address _oprfKeyRegistry) external virtual onlyOwner onlyProxy onlyInitialized {
        if (_oprfKeyRegistry == address(0)) revert ZeroAddress();
        address oldOprfKeyRegistry = address(oprfKeyRegistry);
        oprfKeyRegistry = OprfKeyRegistry(_oprfKeyRegistry);
        emit OprfKeyRegistryUpdated(oldOprfKeyRegistry, _oprfKeyRegistry);
    }

    /// @inheritdoc IVerifier
    function updateVerifierNullifier(address _verifierNullifier) external virtual onlyOwner onlyProxy onlyInitialized {
        if (_verifierNullifier == address(0)) revert ZeroAddress();
        address oldVerifier = address(verifierNullifier);
        verifierNullifier = VerifierNullifier(_verifierNullifier);
        emit Groth16VerifierNullifierUpdated(oldVerifier, _verifierNullifier);
    }

    /// @inheritdoc IVerifier
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
