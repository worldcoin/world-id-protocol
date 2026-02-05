// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {WorldIDStateBridgeBase} from "./abstract/WorldIDStateBridgeBase.sol";
import {RLPReader} from "optimism/packages/contracts-bedrock/src/libraries/rlp/RLPReader.sol";

/**
 * @title WorldIDStateBridgeOP
 * @author World Contributors
 * @notice Bridges World ID state from World Chain to Optimism using storage proofs.
 * @dev Uses L1Block predeploy to access L1 state, then verifies L2OutputOracle storage proof
 *   to get World Chain output root, then verifies World Chain storage proofs.
 * @custom:repo https://github.com/world-id/world-id-protocol
 */
contract WorldIDStateBridgeOP is WorldIDStateBridgeBase {
    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    string public constant EIP712_NAME = "WorldIDStateBridgeOP";
    string public constant EIP712_VERSION = "1.0";

    /// @dev L1Block predeploy address on OP Stack chains.
    address internal constant L1_BLOCK_PREDEPLOY =
        0x4200000000000000000000000000000000000015;

    /// @dev Storage slot base for outputRoots in L2OutputOracle.
    bytes32 internal constant L2_OUTPUT_ORACLE_SLOT_BASE = bytes32(uint256(3));

    ////////////////////////////////////////////////////////////
    //                        Constructor                     //
    ////////////////////////////////////////////////////////////

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the WorldIDStateBridgeOP contract.
     * @param l2OutputOracle Address of the L2OutputOracle contract on L1.
     * @param worldChainRegistryAddress Address of the WorldIDRegistry on World Chain.
     * @param worldChainIssuerRegistryAddress Address of the CredentialSchemaIssuerRegistry on World Chain.
     * @param worldChainOprfRegistryAddress Address of the OprfKeyRegistry on World Chain.
     * @param rootValidityWindow Validity window for roots in seconds.
     * @param treeDepth Merkle tree depth (should match World Chain).
     */
    function initialize(
        address l2OutputOracle,
        address worldChainRegistryAddress,
        address worldChainIssuerRegistryAddress,
        address worldChainOprfRegistryAddress,
        uint256 rootValidityWindow,
        uint256 treeDepth
    ) public virtual initializer {
        __WorldIDStateBridgeBase_init(
            EIP712_NAME,
            EIP712_VERSION,
            l2OutputOracle,
            worldChainRegistryAddress,
            worldChainIssuerRegistryAddress,
            worldChainOprfRegistryAddress,
            rootValidityWindow,
            treeDepth
        );
    }

    ////////////////////////////////////////////////////////////
    //                   PUBLIC FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Bridges a new root from World Chain to Optimism.
     * @dev Verifies L1 block header against L1Block predeploy, then verifies L2OutputOracle
     *   storage proof to get World Chain output root, then verifies World Chain storage proofs.
     * @param l1BlockHeader RLP encoded L1 block header.
     * @param l2OutputIndex The index in L2OutputOracle.outputRoots.
     * @param l1AccountProof Account proof for L2OutputOracle on L1.
     * @param l1StorageProof Storage proof for L2OutputOracle.outputRoots[index].
     * @param wcAccountProof Account proof for WorldIDRegistry on World Chain.
     * @param wcRootStorageProof Storage proof for _latestRoot.
     * @param wcTimestampStorageProof Storage proof for _rootToTimestamp[root].
     */
    function bridgeRoot(
        bytes calldata l1BlockHeader,
        uint256 l2OutputIndex,
        bytes[] calldata l1AccountProof,
        bytes[] calldata l1StorageProof,
        bytes[] calldata wcAccountProof,
        bytes[] calldata wcRootStorageProof,
        bytes[] calldata wcTimestampStorageProof
    ) external virtual onlyProxy onlyInitialized {
        bytes32 wcStateRoot = _getWorldChainStateRoot(
            l1BlockHeader,
            l2OutputIndex,
            l1AccountProof,
            l1StorageProof
        );

        // Verify WorldIDRegistry account exists and get its storage root
        bytes32 storageRoot = _verifyAccountAndGetStorageRoot(
            _worldChainRegistryAddress,
            wcAccountProof,
            wcStateRoot
        );

        // Extract latest root and timestamp from storage proofs
        uint256 newRoot = _getStorageValue(
            wcRootStorageProof,
            storageRoot,
            LATEST_ROOT_SLOT
        );
        uint256 timestamp = _getStorageValue(
            wcTimestampStorageProof,
            storageRoot,
            _getTimestampSlot(newRoot)
        );

        _storeRoot(newRoot, timestamp, l2OutputIndex);
    }

    /**
     * @notice Bridges a credential issuer pubkey from World Chain to Optimism.
     * @param l1BlockHeader RLP encoded L1 block header.
     * @param l2OutputIndex The index in L2OutputOracle.outputRoots.
     * @param issuerSchemaId The issuer schema ID to bridge.
     * @param l1AccountProof Account proof for L2OutputOracle on L1.
     * @param l1StorageProof Storage proof for L2OutputOracle.outputRoots[index].
     * @param wcAccountProof Account proof for CredentialSchemaIssuerRegistry on World Chain.
     * @param wcPubkeyXStorageProof Storage proof for pubkey.x.
     * @param wcPubkeyYStorageProof Storage proof for pubkey.y.
     */
    function bridgeIssuerPubkey(
        bytes calldata l1BlockHeader,
        uint256 l2OutputIndex,
        uint64 issuerSchemaId,
        bytes[] calldata l1AccountProof,
        bytes[] calldata l1StorageProof,
        bytes[] calldata wcAccountProof,
        bytes[] calldata wcPubkeyXStorageProof,
        bytes[] calldata wcPubkeyYStorageProof
    ) external virtual onlyProxy onlyInitialized {
        if (issuerSchemaId == 0) revert InvalidIssuerSchemaId();

        bytes32 wcStateRoot = _getWorldChainStateRoot(
            l1BlockHeader,
            l2OutputIndex,
            l1AccountProof,
            l1StorageProof
        );
        bytes32 storageRoot = _verifyAccountAndGetStorageRoot(
            _worldChainIssuerRegistryAddress,
            wcAccountProof,
            wcStateRoot
        );

        (bytes32 pubkeyXSlot, bytes32 pubkeyYSlot) = _getIssuerPubkeySlots(
            issuerSchemaId
        );
        uint256 pubkeyX = _getStorageValue(
            wcPubkeyXStorageProof,
            storageRoot,
            pubkeyXSlot
        );
        uint256 pubkeyY = _getStorageValue(
            wcPubkeyYStorageProof,
            storageRoot,
            pubkeyYSlot
        );

        _storeIssuerPubkey(issuerSchemaId, pubkeyX, pubkeyY);
    }

    /**
     * @notice Bridges an OPRF pubkey from World Chain to Optimism.
     * @param l1BlockHeader RLP encoded L1 block header.
     * @param l2OutputIndex The index in L2OutputOracle.outputRoots.
     * @param oprfKeyId The OPRF key ID to bridge.
     * @param l1AccountProof Account proof for L2OutputOracle on L1.
     * @param l1StorageProof Storage proof for L2OutputOracle.outputRoots[index].
     * @param wcAccountProof Account proof for OprfKeyRegistry on World Chain.
     * @param wcPubkeyXStorageProof Storage proof for pubkey.x.
     * @param wcPubkeyYStorageProof Storage proof for pubkey.y.
     */
    function bridgeOprfPubkey(
        bytes calldata l1BlockHeader,
        uint256 l2OutputIndex,
        uint160 oprfKeyId,
        bytes[] calldata l1AccountProof,
        bytes[] calldata l1StorageProof,
        bytes[] calldata wcAccountProof,
        bytes[] calldata wcPubkeyXStorageProof,
        bytes[] calldata wcPubkeyYStorageProof
    ) external virtual onlyProxy onlyInitialized {
        if (oprfKeyId == 0) revert InvalidOprfKeyId();

        bytes32 wcStateRoot = _getWorldChainStateRoot(
            l1BlockHeader,
            l2OutputIndex,
            l1AccountProof,
            l1StorageProof
        );
        bytes32 storageRoot = _verifyAccountAndGetStorageRoot(
            _worldChainOprfRegistryAddress,
            wcAccountProof,
            wcStateRoot
        );

        (bytes32 pubkeyXSlot, bytes32 pubkeyYSlot) = _getOprfPubkeySlots(
            oprfKeyId
        );
        uint256 pubkeyX = _getStorageValue(
            wcPubkeyXStorageProof,
            storageRoot,
            pubkeyXSlot
        );
        uint256 pubkeyY = _getStorageValue(
            wcPubkeyYStorageProof,
            storageRoot,
            pubkeyYSlot
        );

        _storeOprfPubkey(oprfKeyId, pubkeyX, pubkeyY);
    }

    ////////////////////////////////////////////////////////////
    //                   INTERNAL FUNCTIONS                   //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Gets the World Chain state root by verifying L1 block header and L2OutputOracle storage proof.
     * @param l1BlockHeader RLP encoded L1 block header.
     * @param l2OutputIndex The index in L2OutputOracle.outputRoots.
     * @param l1AccountProof Account proof for L2OutputOracle on L1.
     * @param l1StorageProof Storage proof for the output root.
     * @return The World Chain state root.
     */
    function _getWorldChainStateRoot(
        bytes calldata l1BlockHeader,
        uint256 l2OutputIndex,
        bytes[] calldata l1AccountProof,
        bytes[] calldata l1StorageProof
    ) internal view virtual returns (bytes32) {
        // Verify L1 block header against L1Block predeploy
        bytes32 l1StateRoot = _verifyL1BlockHeader(l1BlockHeader);

        // Verify L2OutputOracle account exists on L1
        bytes32 storageRoot = _verifyAccountAndGetStorageRoot(
            _l2OutputOracle,
            l1AccountProof,
            l1StateRoot
        );

        // Calculate storage slot for outputRoots[l2OutputIndex]
        // outputRoots is a dynamic array, so: keccak256(L2_OUTPUT_ORACLE_SLOT_BASE) + index * 2
        // OutputProposal struct has 2 slots: outputRoot (bytes32), timestamp+l2BlockNumber (packed)
        bytes32 arraySlot = keccak256(abi.encode(L2_OUTPUT_ORACLE_SLOT_BASE));
        bytes32 outputRootSlot = bytes32(
            uint256(arraySlot) + l2OutputIndex * 2
        );

        // Extract output root from storage proof
        uint256 outputRootValue = _getStorageValue(
            l1StorageProof,
            storageRoot,
            outputRootSlot
        );
        bytes32 outputRoot = bytes32(outputRootValue);

        if (outputRoot == bytes32(0)) revert InvalidOutputRoot();

        return _extractStateRoot(outputRoot);
    }

    /**
     * @notice Verifies the L1 block header against L1Block predeploy and extracts state root.
     * @param l1BlockHeader RLP encoded L1 block header.
     * @return l1StateRoot The L1 state root.
     */
    function _verifyL1BlockHeader(
        bytes calldata l1BlockHeader
    ) internal view virtual returns (bytes32 l1StateRoot) {
        // Get the L1 block hash from L1Block predeploy
        (bool success, bytes memory data) = L1_BLOCK_PREDEPLOY.staticcall(
            abi.encodeWithSignature("hash()")
        );
        if (!success || data.length < 32) revert InvalidL1BlockHash();

        bytes32 expectedHash;
        assembly {
            expectedHash := mload(add(data, 32))
        }

        // Verify the block header hash matches
        bytes32 actualHash = keccak256(l1BlockHeader);
        if (actualHash != expectedHash) revert InvalidL1BlockHash();

        // Parse the block header to extract state root (index 3 in RLP list)
        RLPReader.RLPItem[] memory headerFields = RLPReader.readList(
            l1BlockHeader
        );
        if (headerFields.length < 4) revert InvalidBlockHeader();

        // State root is at index 3 (parentHash, uncleHash, coinbase, stateRoot, ...)
        l1StateRoot = bytes32(RLPReader.readBytes(headerFields[3]));
    }
}
