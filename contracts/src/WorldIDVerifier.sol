// SPDX-License-Identifier: MIT
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
 * @author World Contributors
 * @notice Verifies World ID proofs (Uniqueness and Session proofs).
 * @dev In addition to verifying the Groth16 Proof, it verifies relevant public inputs to the
 *  circuits through checks with the WorldIDRegistry, CredentialSchemaIssuerRegistry, and OprfKeyRegistry.
 * @custom:repo https://github.com/world-id/world-id-protocol
 */
contract WorldIDVerifier is WorldIDBase, IWorldIDVerifier {
    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    // DO NOT REORDER! To ensure compatibility between upgrades, it is exceedingly important
    // that no reordering of these variables takes place. If reordering happens, a storage
    // clash will occur (effectively a memory safety error).

    /// @dev Registry for credential schema and issuer management
    CredentialSchemaIssuerRegistry internal _credentialSchemaIssuerRegistry;

    /// @dev Registry for World IDs and authenticator management
    WorldIDRegistry internal _worldIDRegistry;

    /// @dev Registry for OPRF key management
    OprfKeyRegistry internal _oprfKeyRegistry;

    /// @dev Contract for proof verification (Groth16)
    Verifier internal _verifier;

    /// @dev Allowed delta for proof timestamps (seconds)
    uint256 internal _proofTimestampDelta;

    /// @dev The depth of the Merkle tree in WorldIDRegistry
    uint256 internal _treeDepth;

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
     * @notice Initializes the WorldIDVerifier contract with required registries.
     * @param credentialIssuerRegistry Address of the CredentialSchemaIssuerRegistry contract.
     * @param worldIDRegistry Address of the WorldIDRegistry contract.
     * @param oprfKeyRegistry Address of the OprfKeyRegistry contract.
     * @param verifier Address of the Verifier contract for proof verification.
     * @param proofTimestampDelta Allowed delta for proof timestamps (seconds).
     */
    function initialize(
        address credentialIssuerRegistry,
        address worldIDRegistry,
        address oprfKeyRegistry,
        address verifier,
        uint256 proofTimestampDelta
    ) public virtual initializer {
        if (credentialIssuerRegistry == address(0)) revert ZeroAddress();
        if (worldIDRegistry == address(0)) revert ZeroAddress();
        if (oprfKeyRegistry == address(0)) revert ZeroAddress();
        if (verifier == address(0)) revert ZeroAddress();

        __BaseUpgradeable_init(EIP712_NAME, EIP712_VERSION, address(0), address(0), 0);
        _credentialSchemaIssuerRegistry = CredentialSchemaIssuerRegistry(credentialIssuerRegistry);
        _worldIDRegistry = WorldIDRegistry(worldIDRegistry);
        _verifier = Verifier(verifier);
        _oprfKeyRegistry = OprfKeyRegistry(oprfKeyRegistry);
        _proofTimestampDelta = proofTimestampDelta;
        _treeDepth = _worldIDRegistry.getTreeDepth();
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
        uint256 proofTimestamp,
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
            proofTimestamp,
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
        uint256 proofTimestamp,
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
            proofTimestamp,
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
        uint256 proofTimestamp,
        uint64 issuerSchemaId,
        uint256 credentialGenesisIssuedAtMin,
        uint256 sessionId,
        uint256[5] calldata zeroKnowledgeProof
    ) external view virtual onlyProxy onlyInitialized {
        uint256 worldIdRegistryMerkleRoot = zeroKnowledgeProof[4];
        if (!_worldIDRegistry.isValidRoot(worldIdRegistryMerkleRoot)) {
            revert InvalidMerkleRoot();
        }

        ICredentialSchemaIssuerRegistry.Pubkey memory credentialIssuerPubkey =
            _credentialSchemaIssuerRegistry.issuerSchemaIdToPubkey(issuerSchemaId);
        if (credentialIssuerPubkey.x == 0 || credentialIssuerPubkey.y == 0) {
            revert UnregisteredIssuerSchemaId();
        }

        // NOTICE: Currently the `oprfKeyId` is the same as the `rpId`. This may change in the future in the `RpRegistry` contract
        uint160 oprfKeyId = uint160(rpId);
        BabyJubJub.Affine memory oprfPublicKey = _oprfKeyRegistry.getOprfPublicKey(oprfKeyId);

        // do not allow proofs from the future
        if (proofTimestamp > block.timestamp) {
            revert NullifierFromFuture();
        }

        // do not allow proofs older than _proofTimestampDelta
        if (proofTimestamp + _proofTimestampDelta < block.timestamp) {
            revert OutdatedNullifier();
        }

        uint256[15] memory pubSignals;

        pubSignals[0] = nullifier;
        pubSignals[1] = issuerSchemaId;
        pubSignals[2] = credentialIssuerPubkey.x;
        pubSignals[3] = credentialIssuerPubkey.y;
        pubSignals[4] = proofTimestamp;
        pubSignals[5] = credentialGenesisIssuedAtMin;
        pubSignals[6] = worldIdRegistryMerkleRoot;
        pubSignals[7] = _treeDepth;
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

        _verifier.verifyCompressedProof(groth16CompressedProof, pubSignals);
    }

    /// @inheritdoc IWorldIDVerifier
    function getCredentialSchemaIssuerRegistry() external view virtual onlyProxy onlyInitialized returns (address) {
        return address(_credentialSchemaIssuerRegistry);
    }

    /// @inheritdoc IWorldIDVerifier
    function getWorldIDRegistry() external view virtual onlyProxy onlyInitialized returns (address) {
        return address(_worldIDRegistry);
    }

    /// @inheritdoc IWorldIDVerifier
    function getOprfKeyRegistry() external view virtual onlyProxy onlyInitialized returns (address) {
        return address(_oprfKeyRegistry);
    }

    /// @inheritdoc IWorldIDVerifier
    function getVerifier() external view virtual onlyProxy onlyInitialized returns (address) {
        return address(_verifier);
    }

    /// @inheritdoc IWorldIDVerifier
    function getProofTimestampDelta() external view virtual onlyProxy onlyInitialized returns (uint256) {
        return _proofTimestampDelta;
    }

    /// @inheritdoc IWorldIDVerifier
    function getTreeDepth() external view virtual onlyProxy onlyInitialized returns (uint256) {
        return _treeDepth;
    }

    ////////////////////////////////////////////////////////////
    //                    OWNER FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IWorldIDVerifier
    function updateCredentialSchemaIssuerRegistry(address newCredentialSchemaIssuerRegistry)
        external
        virtual
        onlyOwner
        onlyProxy
        onlyInitialized
    {
        if (newCredentialSchemaIssuerRegistry == address(0)) revert ZeroAddress();
        address oldCredentialSchemaIssuerRegistry = address(_credentialSchemaIssuerRegistry);
        _credentialSchemaIssuerRegistry = CredentialSchemaIssuerRegistry(newCredentialSchemaIssuerRegistry);
        emit CredentialSchemaIssuerRegistryUpdated(oldCredentialSchemaIssuerRegistry, newCredentialSchemaIssuerRegistry);
    }

    /// @inheritdoc IWorldIDVerifier
    function updateWorldIDRegistry(address newWorldIDRegistry) external virtual onlyOwner onlyProxy onlyInitialized {
        if (newWorldIDRegistry == address(0)) revert ZeroAddress();
        address oldWorldIDRegistry = address(_worldIDRegistry);
        _worldIDRegistry = WorldIDRegistry(newWorldIDRegistry);
        _treeDepth = _worldIDRegistry.getTreeDepth();
        emit WorldIDRegistryUpdated(oldWorldIDRegistry, newWorldIDRegistry);
    }

    /// @inheritdoc IWorldIDVerifier
    function updateOprfKeyRegistry(address newOprfKeyRegistry) external virtual onlyOwner onlyProxy onlyInitialized {
        if (newOprfKeyRegistry == address(0)) revert ZeroAddress();
        address oldOprfKeyRegistry = address(_oprfKeyRegistry);
        _oprfKeyRegistry = OprfKeyRegistry(newOprfKeyRegistry);
        emit OprfKeyRegistryUpdated(oldOprfKeyRegistry, newOprfKeyRegistry);
    }

    /// @inheritdoc IWorldIDVerifier
    function updateVerifier(address newVerifier) external virtual onlyOwner onlyProxy onlyInitialized {
        if (newVerifier == address(0)) revert ZeroAddress();
        address oldVerifier = address(_verifier);
        _verifier = Verifier(newVerifier);
        emit VerifierUpdated(oldVerifier, newVerifier);
    }

    /// @inheritdoc IWorldIDVerifier
    function updateProofTimestampDelta(uint256 newProofTimestampDelta)
        external
        virtual
        onlyOwner
        onlyProxy
        onlyInitialized
    {
        uint256 oldProofTimestampDelta = _proofTimestampDelta;
        _proofTimestampDelta = newProofTimestampDelta;
        emit ProofTimestampDeltaUpdated(oldProofTimestampDelta, newProofTimestampDelta);
    }
}
