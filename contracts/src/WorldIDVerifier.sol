// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {OprfKeyRegistry} from "oprf-key-registry/src/OprfKeyRegistry.sol";
import {BabyJubJub} from "oprf-key-registry/src/BabyJubJub.sol";
import {CredentialSchemaIssuerRegistry} from "./CredentialSchemaIssuerRegistry.sol";
import {ICredentialSchemaIssuerRegistry} from "./interfaces/ICredentialSchemaIssuerRegistry.sol";
import {WorldIDRegistry} from "./WorldIDRegistry.sol";
import {Verifier} from "./Verifier.sol";
import {IWorldIDVerifier} from "./interfaces/IWorldIDVerifier.sol";
import {WorldIDBase} from "./abstract/WorldIDBase.sol";

/**
 * @title WorldIDVerifier
 * @notice Verifies proofs on the World ID Protocol.
 * @dev Coordinates verification between the World ID registry, the credential schema issuer registry, and the OPRF key registry. Requires
 *  proofs to be generated with the 4.0+ Protocol.
 */
contract WorldIDVerifier is WorldIDBase, IWorldIDVerifier {
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
    Verifier public verifier;

    /// @notice Allowed delta for proof timestamps
    uint64 public proofTimestampDelta;

    /// @notice The depth of the Merkle tree
    uint256 public treeDepth;

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    string public constant EIP712_NAME = "WorldIDVerifier";
    string public constant EIP712_VERSION = "1.0";

    ////////////////////////////////////////////////////////////
    //                        Constructor                     //
    ////////////////////////////////////////////////////////////

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the WorldIDVerifier contract with required registries
     * @param _credentialIssuerRegistry Address of the CredentialSchemaIssuerRegistry contract
     * @param _worldIDRegistry Address of the WorldIDRegistry contract
     * @param _verifier Address of the Verifier contract for the nullifier circuit.
     * @param _proofTimestampDelta Allowed delta for proof timestamps.
     */
    function initialize(
        address _credentialIssuerRegistry,
        address _worldIDRegistry,
        address _oprfKeyRegistry,
        address _verifier,
        uint64 _proofTimestampDelta
    ) public virtual initializer {
        if (_credentialIssuerRegistry == address(0)) revert ZeroAddress();
        if (_worldIDRegistry == address(0)) revert ZeroAddress();
        if (_oprfKeyRegistry == address(0)) revert ZeroAddress();
        if (_verifier == address(0)) revert ZeroAddress();

        __BaseUpgradeable_init(EIP712_NAME, EIP712_VERSION, address(0), address(0), 0);
        credentialSchemaIssuerRegistry = CredentialSchemaIssuerRegistry(_credentialIssuerRegistry);
        worldIDRegistry = WorldIDRegistry(_worldIDRegistry);
        verifier = Verifier(_verifier);
        oprfKeyRegistry = OprfKeyRegistry(_oprfKeyRegistry);
        proofTimestampDelta = _proofTimestampDelta;
        treeDepth = worldIDRegistry.getTreeDepth();
    }

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IWorldIDVerifier
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
    ) external view virtual onlyProxy onlyInitialized {
        this._verifyProofAndSignals(
            nullifier,
            action,
            rpId,
            nonce,
            signalHash,
            expiresAtMin,
            issuerSchemaId,
            credentialGenesisIssuedAtMin,
            // For Uniqueness Proofs, the `session_id` is not used, hence the constraint defaults to 0
            // To verify a Session Proof use `verifySession` instead.
            0,
            zeroKnowledgeProof
        );
    }

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
    ) external view virtual onlyProxy onlyInitialized {
        this._verifyProofAndSignals(
            sessionNullifier[0],
            sessionNullifier[1],
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
    function _verifyProofAndSignals(
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
    ) external view virtual onlyProxy onlyInitialized {
        uint256 worldIdRegistryMerkleRoot = zeroKnowledgeProof[4];
        if (!worldIDRegistry.isValidRoot(worldIdRegistryMerkleRoot)) {
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

        // do not allow proofs with expiration older than proofTimestampDelta
        // this is a sanity check to ensure non-expired credentials are used
        if (uint256(expiresAtMin + proofTimestampDelta) < block.timestamp) {
            revert ExpirationTooOld();
        }

        uint256[15] memory pubSignals;

        pubSignals[0] = nullifier;
        pubSignals[1] = issuerSchemaId;
        pubSignals[2] = credentialIssuerPubkey.x;
        pubSignals[3] = credentialIssuerPubkey.y;
        pubSignals[4] = uint256(expiresAtMin);
        pubSignals[5] = credentialGenesisIssuedAtMin;
        pubSignals[6] = worldIdRegistryMerkleRoot;
        pubSignals[7] = treeDepth;
        pubSignals[8] = uint256(rpId);
        pubSignals[9] = action;
        pubSignals[10] = oprfPublicKey.x;
        pubSignals[11] = oprfPublicKey.y;
        pubSignals[12] = signalHash;
        pubSignals[13] = nonce;
        pubSignals[14] = sessionId;

        uint256[4] memory groth16CompressedProof;
        for (uint256 i = 0; i < 4; i++) {
            groth16CompressedProof[i] = zeroKnowledgeProof[i];
        }

        verifier.verifyCompressedProof(groth16CompressedProof, pubSignals);
    }

    ////////////////////////////////////////////////////////////
    //                      Owner Functions                   //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IWorldIDVerifier
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

    /// @inheritdoc IWorldIDVerifier
    function updateWorldIDRegistry(address _worldIDRegistry) external virtual onlyOwner onlyProxy onlyInitialized {
        if (_worldIDRegistry == address(0)) revert ZeroAddress();
        address oldWorldIDRegistry = address(worldIDRegistry);
        worldIDRegistry = WorldIDRegistry(_worldIDRegistry);
        treeDepth = worldIDRegistry.getTreeDepth();
        emit WorldIDRegistryUpdated(oldWorldIDRegistry, _worldIDRegistry);
    }

    /// @inheritdoc IWorldIDVerifier
    function updateOprfKeyRegistry(address _oprfKeyRegistry) external virtual onlyOwner onlyProxy onlyInitialized {
        if (_oprfKeyRegistry == address(0)) revert ZeroAddress();
        address oldOprfKeyRegistry = address(oprfKeyRegistry);
        oprfKeyRegistry = OprfKeyRegistry(_oprfKeyRegistry);
        emit OprfKeyRegistryUpdated(oldOprfKeyRegistry, _oprfKeyRegistry);
    }

    /// @inheritdoc IWorldIDVerifier
    function updateVerifier(address _verifier) external virtual onlyOwner onlyProxy onlyInitialized {
        if (_verifier == address(0)) revert ZeroAddress();
        address oldVerifier = address(verifier);
        verifier = Verifier(_verifier);
        emit VerifierUpdated(oldVerifier, _verifier);
    }

    /// @inheritdoc IWorldIDVerifier
    function updateProofTimestampDelta(uint64 _proofTimestampDelta)
        external
        virtual
        onlyOwner
        onlyProxy
        onlyInitialized
    {
        uint64 oldProofTimestampDelta = proofTimestampDelta;
        proofTimestampDelta = _proofTimestampDelta;
        emit ProofTimestampDeltaUpdated(oldProofTimestampDelta, _proofTimestampDelta);
    }
}
