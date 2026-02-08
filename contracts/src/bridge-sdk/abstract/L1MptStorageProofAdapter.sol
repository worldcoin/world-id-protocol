// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IMptStorageProofAdapter} from "../interfaces/IMptStorageProofAdapter.sol";
import {ICrossDomainRegistryState} from "../interfaces/ICrossDomainRegistryState.sol";
import {IBridgedStateAdapter} from "../interfaces/IBridgedStateAdapter.sol";
import {IDisputeGameFactory} from "../vendored/optimism/IDisputeGameFactory.sol";
import {IDisputeGame} from "../vendored/optimism/IDisputeGame.sol";
import {GameStatus, Claim} from "../vendored/optimism/DisputeTypes.sol";
import {Hashing} from "../vendored/optimism/Hashing.sol";
import {MptVerifier} from "../libraries/MptVerifier.sol";
import {BabyJubJub} from "oprf-key-registry/src/BabyJubJub.sol";

/// @title MptStorageProofAdapter
/// @author World Contributors
/// @notice Proves World Chain registry state on Ethereum L1 via MPT storage proofs against the
///   `DisputeGameFactory`. Implements `IMptStorageProofAdapter` (which extends
///   `ICrossDomainRegistryState`) and delivers proven values to an `IBridgedStateAdapter`.
/// @dev The adapter verifies the full proof chain:
///   1. Look up the dispute game by index from `DisputeGameFactory`.
///   2. Validate that the game status is `DEFENDER_WINS`.
///   3. Verify the output root preimage against the game's `rootClaim()`.
///   4. Verify the MPT account proof: L2 state root -> target contract's storage root.
///   5. Verify storage proofs against the storage root to extract slot values.
///   6. Cache values locally and deliver to the verifier atomically.
abstract contract L1MptStorageProofAdapter is IMptStorageProofAdapter {
    ////////////////////////////////////////////////////////////
    //                       IMMUTABLES                       //
    ////////////////////////////////////////////////////////////

    /// @notice The DisputeGameFactory contract on L1.
    IDisputeGameFactory public immutable DISPUTE_GAME_FACTORY;

    /// @notice The WorldIDRegistry contract address on World Chain.
    address public immutable WORLD_CHAIN_REGISTRY;

    /// @notice The CredentialSchemaIssuerRegistry contract address on World Chain.
    address public immutable WORLD_CHAIN_ISSUER_REGISTRY;

    /// @notice The OprfKeyRegistry contract address on World Chain.
    address public immutable WORLD_CHAIN_OPRF_REGISTRY;

    ////////////////////////////////////////////////////////////
    //                        STORAGE                         //
    ////////////////////////////////////////////////////////////

    /// @dev Latest proven root from World Chain.
    uint256 internal _latestRoot;

    /// @dev Mapping from root to its timestamp on World Chain.
    mapping(uint256 => uint256) internal _rootTimestamps;

    /// @dev Root validity window in seconds (set at construction, mirrors World Chain).
    uint256 internal _rootValidityWindow;

    /// @dev Tree depth (proven from World Chain storage).
    uint256 internal _treeDepth;

    /// @dev Mapping from issuer schema ID to pubkey (x, y).
    mapping(uint64 => uint256[2]) internal _issuerPubkeys;

    /// @dev Mapping from OPRF key ID to pubkey (x, y).
    mapping(uint160 => uint256[2]) internal _oprfKeys;

    ////////////////////////////////////////////////////////////
    //                      CONSTRUCTOR                       //
    ////////////////////////////////////////////////////////////

    /// @param disputeGameFactory The DisputeGameFactory contract on L1.
    /// @param worldChainRegistry The WorldIDRegistry address on World Chain.
    /// @param worldChainIssuerRegistry The CredentialSchemaIssuerRegistry address on World Chain.
    /// @param worldChainOprfRegistry The OprfKeyRegistry address on World Chain.
    /// @param rootValidityWindow_ The root validity window in seconds.
    constructor(
        IDisputeGameFactory disputeGameFactory,
        address worldChainRegistry,
        address worldChainIssuerRegistry,
        address worldChainOprfRegistry,
        uint256 rootValidityWindow_
    ) {
        DISPUTE_GAME_FACTORY = disputeGameFactory;
        WORLD_CHAIN_REGISTRY = worldChainRegistry;
        WORLD_CHAIN_ISSUER_REGISTRY = worldChainIssuerRegistry;
        WORLD_CHAIN_OPRF_REGISTRY = worldChainOprfRegistry;
        _rootValidityWindow = rootValidityWindow_;
    }

    function receiveRoot(uint256 root, uint256 worldChainTimestamp, uint256 treeDepth, bytes32 proofId)
        public
        virtual {}

    function receiveIssuerPubkey(uint64 issuerSchemaId, BabyJubJub.Affine memory pubkey, bytes32 proofId) public virtual {}

    function receiveOprfKey(uint160 oprfKeyId, BabyJubJub.Affine memory pubkey, bytes32 proofId) public virtual {}

    ////////////////////////////////////////////////////////////
    //              ICrossDomainRegistryState                  //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc ICrossDomainRegistryState
    function getLatestRoot() external view virtual returns (uint256) {
        return _latestRoot;
    }

    /// @inheritdoc ICrossDomainRegistryState
    function getRootTimestamp(uint256 root) external view virtual returns (uint256) {
        return _rootTimestamps[root];
    }

    /// @inheritdoc ICrossDomainRegistryState
    function issuerPubkey(uint64 issuerSchemaId) external view virtual returns (uint256 x, uint256 y) {
        uint256[2] storage pk = _issuerPubkeys[issuerSchemaId];
        return (pk[0], pk[1]);
    }

    /// @inheritdoc ICrossDomainRegistryState
    function oprfKey(uint160 oprfKeyId) external view virtual returns (uint256 x, uint256 y) {
        uint256[2] storage pk = _oprfKeys[oprfKeyId];
        return (pk[0], pk[1]);
    }

    /// @inheritdoc ICrossDomainRegistryState
    function rootValidityWindow() external view virtual returns (uint256) {
        return _rootValidityWindow;
    }

    ////////////////////////////////////////////////////////////
    //              IMptStorageProofAdapter                    //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IMptStorageProofAdapter
    function proveRoot(
        uint256 disputeGameIndex,
        bytes[4] calldata outputRootProof,
        bytes[] calldata accountProof,
        bytes[] calldata rootTimestampProof,
        bytes[] calldata latestRootProof,
        bytes[] calldata treeDepthProof
    ) external virtual {
        // 1-3. Validate game, verify output root, verify account proof
        bytes32 proofId;
        bytes32 storageRoot;
        {
            IDisputeGame game;
            bytes32 rootClaim;
            (game, rootClaim) = _validateDisputeGame(disputeGameIndex);
            proofId = _deriveProofId(game);
            bytes32 stateRoot = _verifyOutputRootPreimage(outputRootProof, rootClaim);
            storageRoot = MptVerifier.verifyAccountAndGetStorageRoot(WORLD_CHAIN_REGISTRY, accountProof, stateRoot);
        }

        bytes memory latestRoot =
            MptVerifier.storageFromProof(latestRootProof, storageRoot, MptVerifier.LATEST_ROOT_SLOT);
        bytes memory timestamp = MptVerifier.storageFromProof(
            rootTimestampProof,
            storageRoot,
            MptVerifier._computeMappingSlot(MptVerifier.ROOT_TO_TIMESTAMP_SLOT_BASE, bytes32(uint256(storageRoot)))
        );
        bytes memory treeDepth = MptVerifier.storageFromProof(treeDepthProof, storageRoot, MptVerifier.TREE_DEPTH_SLOT);

        // 5. Cache values
        _latestRoot = uint256(bytes32(latestRoot));
        _rootTimestamps[_latestRoot] = uint256(bytes32(timestamp));
        _treeDepth = uint256(bytes32(treeDepth));

        // 6. Deliver to verifier
        receiveRoot(_latestRoot, uint256(bytes32(timestamp)), uint256(bytes32(treeDepth)), proofId);
    }

    /// @inheritdoc IMptStorageProofAdapter
    function proveIssuerPubkey(
        uint64 issuerSchemaId,
        uint256 disputeGameIndex,
        bytes[4] calldata outputRootProof,
        bytes[] calldata accountProof,
        bytes[] calldata storageProofX,
        bytes[] calldata storageProofY
    ) external virtual {
        // 1-3. Validate game, verify output root, verify account proof
        bytes32 proofId;
        bytes32 storageRoot;
        {
            IDisputeGame game;
            bytes32 rootClaim;
            (game, rootClaim) = _validateDisputeGame(disputeGameIndex);
            proofId = _deriveProofId(game);
            bytes32 stateRoot = _verifyOutputRootPreimage(outputRootProof, rootClaim);
            storageRoot =
                MptVerifier.verifyAccountAndGetStorageRoot(WORLD_CHAIN_ISSUER_REGISTRY, accountProof, stateRoot);
        }

        // 4. Extract pubkey coordinates from storage proofs
        bytes32 pubKeySlot =
            MptVerifier._computeMappingSlot(MptVerifier.ISSUER_PUBKEY_SLOT_BASE, bytes32(uint256(issuerSchemaId)));

        bytes memory pubkeyX = MptVerifier.storageFromProof(storageProofX, storageRoot, pubKeySlot);
        bytes memory pubkeyY =
            MptVerifier.storageFromProof(storageProofY, storageRoot, bytes32(uint256(pubKeySlot) + 1));

        BabyJubJub.Affine memory pubKey = BabyJubJub.Affine({x: uint256(bytes32(pubkeyX)), y: uint256(bytes32(pubkeyY))});
        receiveIssuerPubkey(issuerSchemaId, pubKey, proofId);
    }

    /// @inheritdoc IMptStorageProofAdapter
    function proveOprfKey(
        uint160 oprfKeyId,
        uint256 disputeGameIndex,
        bytes[4] calldata outputRootProof,
        bytes[] calldata accountProof,
        bytes[] calldata storageProofX,
        bytes[] calldata storageProofY
    ) external virtual {
        // 1-3. Validate game, verify output root, verify account proof
        bytes32 proofId;
        bytes32 storageRoot;
        {
            IDisputeGame game;
            bytes32 rootClaim;
            (game, rootClaim) = _validateDisputeGame(disputeGameIndex);
            proofId = _deriveProofId(game);
            bytes32 stateRoot = _verifyOutputRootPreimage(outputRootProof, rootClaim);
            storageRoot = MptVerifier.verifyAccountAndGetStorageRoot(WORLD_CHAIN_OPRF_REGISTRY, accountProof, stateRoot);
        }

        // 4. Extract pubkey coordinates from storage proofs
        bytes32 slot = MptVerifier._computeMappingSlot(
            MptVerifier.OPRF_PUBKEY_SLOT_BASE,
            bytes32(uint256(oprfKeyId))
        );
        uint256 pubkeyX = uint256(bytes32(MptVerifier.storageFromProof(storageProofX, storageRoot, slot)));
        uint256 pubkeyY = uint256(bytes32(MptVerifier.storageFromProof(storageProofY, storageRoot, bytes32(uint256(slot) + 1))));

        BabyJubJub.Affine memory pubKey = BabyJubJub.Affine({x: pubkeyX, y: pubkeyY});

        receiveOprfKey(oprfKeyId, pubKey, proofId);
    }

    ////////////////////////////////////////////////////////////
    //                  INTERNAL FUNCTIONS                    //
    ////////////////////////////////////////////////////////////

    /// @notice Validates a dispute game by index and returns the game proxy and root claim.
    /// @dev Reverts if the game index is out of range or the game has not resolved DEFENDER_WINS.
    /// @param index The index of the dispute game in the DisputeGameFactory.
    /// @return game The dispute game proxy.
    /// @return rootClaim The root claim (output root) of the game.
    function _validateDisputeGame(uint256 index) internal view virtual returns (IDisputeGame game, bytes32 rootClaim) {
        uint256 gameCount = DISPUTE_GAME_FACTORY.gameCount();
        if (index >= gameCount) revert InvalidDisputeGameIndex();

        (,, game) = DISPUTE_GAME_FACTORY.gameAtIndex(index);

        if (game.status() != GameStatus.DEFENDER_WINS) {
            revert InvalidOutputRoot();
        }

        rootClaim = Claim.unwrap(game.rootClaim());
    }

    /// @notice Verifies the output root preimage against the root claim and extracts the L2 state root.
    /// @dev The output root proof must be a 4-element array:
    ///   [0] = version, [1] = stateRoot, [2] = messagePasserStorageRoot, [3] = latestBlockhash
    ///   The hash of these elements must equal the root claim.
    /// @param outputRootProof The 4-element output root preimage.
    /// @param rootClaim The expected root claim from the dispute game.
    /// @return stateRoot The L2 state root extracted from the preimage.
    function _verifyOutputRootPreimage(bytes[4] calldata outputRootProof, bytes32 rootClaim)
        internal
        pure
        virtual
        returns (bytes32 stateRoot)
    {
        bytes32 version = bytes32(outputRootProof[0]);
        stateRoot = bytes32(outputRootProof[1]);
        bytes32 messagePasserStorageRoot = bytes32(outputRootProof[2]);
        bytes32 latestBlockhash = bytes32(outputRootProof[3]);

        bytes32 computedRoot =
            Hashing.hashOutputRootProof(version, stateRoot, messagePasserStorageRoot, latestBlockhash);

        if (computedRoot != rootClaim) revert InvalidOutputRootPreimage();
    }

    /// @notice Derives a proofId from a dispute game address.
    /// @param game The dispute game proxy.
    /// @return The proofId.
    function _deriveProofId(IDisputeGame game) internal pure virtual returns (bytes32) {
        return bytes32(uint256(uint160(address(game))));
    }
}
