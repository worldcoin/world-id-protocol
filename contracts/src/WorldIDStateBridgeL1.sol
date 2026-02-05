// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {WorldIDStateBridgeBase} from "./abstract/WorldIDStateBridgeBase.sol";

/**
 * @title WorldIDStateBridgeL1
 * @author World Contributors
 * @notice Bridges World ID state from World Chain to Ethereum L1 using storage proofs.
 * @dev Verifies World Chain storage proofs against the L2OutputOracle output root.
 *   The bridge service submits proofs ~hourly to update roots and registry pubkeys.
 * @custom:repo https://github.com/world-id/world-id-protocol
 */
contract WorldIDStateBridgeL1 is WorldIDStateBridgeBase {
    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    string public constant EIP712_NAME = "WorldIDStateBridgeL1";
    string public constant EIP712_VERSION = "1.0";

    ////////////////////////////////////////////////////////////
    //                        Constructor                     //
    ////////////////////////////////////////////////////////////

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the WorldIDStateBridgeL1 contract.
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
     * @notice Bridges a new root from World Chain to L1.
     * @dev Verifies storage proofs against the L2OutputOracle output root.
     * @param l2OutputIndex The index in L2OutputOracle.outputRoots.
     * @param wcAccountProof Account proof for WorldIDRegistry on World Chain (array of RLP-encoded nodes).
     * @param wcRootStorageProof Storage proof for _latestRoot (array of RLP-encoded nodes).
     * @param wcTimestampStorageProof Storage proof for _rootToTimestamp[root] (array of RLP-encoded nodes).
     */
    function bridgeRoot(
        uint256 l2OutputIndex,
        bytes[] calldata wcAccountProof,
        bytes[] calldata wcRootStorageProof,
        bytes[] calldata wcTimestampStorageProof
    ) external virtual onlyProxy onlyInitialized {
        bytes32 wcStateRoot = _getWorldChainStateRoot(l2OutputIndex);

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
     * @notice Bridges a credential issuer pubkey from World Chain to L1.
     * @param l2OutputIndex The index in L2OutputOracle.outputRoots.
     * @param issuerSchemaId The issuer schema ID to bridge.
     * @param wcAccountProof Account proof for CredentialSchemaIssuerRegistry on World Chain.
     * @param wcPubkeyXStorageProof Storage proof for pubkey.x.
     * @param wcPubkeyYStorageProof Storage proof for pubkey.y.
     */
    function bridgeIssuerPubkey(
        uint256 l2OutputIndex,
        uint64 issuerSchemaId,
        bytes[] calldata wcAccountProof,
        bytes[] calldata wcPubkeyXStorageProof,
        bytes[] calldata wcPubkeyYStorageProof
    ) external virtual onlyProxy onlyInitialized {
        if (issuerSchemaId == 0) revert InvalidIssuerSchemaId();

        bytes32 wcStateRoot = _getWorldChainStateRoot(l2OutputIndex);
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
     * @notice Bridges an OPRF pubkey from World Chain to L1.
     * @param l2OutputIndex The index in L2OutputOracle.outputRoots.
     * @param oprfKeyId The OPRF key ID to bridge.
     * @param wcAccountProof Account proof for OprfKeyRegistry on World Chain.
     * @param wcPubkeyXStorageProof Storage proof for pubkey.x.
     * @param wcPubkeyYStorageProof Storage proof for pubkey.y.
     */
    function bridgeOprfPubkey(
        uint256 l2OutputIndex,
        uint160 oprfKeyId,
        bytes[] calldata wcAccountProof,
        bytes[] calldata wcPubkeyXStorageProof,
        bytes[] calldata wcPubkeyYStorageProof
    ) external virtual onlyProxy onlyInitialized {
        if (oprfKeyId == 0) revert InvalidOprfKeyId();

        bytes32 wcStateRoot = _getWorldChainStateRoot(l2OutputIndex);
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
     * @notice Gets the World Chain state root by reading L2OutputOracle directly.
     * @param l2OutputIndex The index in L2OutputOracle.outputRoots.
     * @return The World Chain state root.
     */
    function _getWorldChainStateRoot(
        uint256 l2OutputIndex
    ) internal view virtual returns (bytes32) {
        // L2OutputOracle.getL2Output(uint256 _l2OutputIndex) returns OutputProposal
        // OutputProposal { bytes32 outputRoot, uint128 timestamp, uint128 l2BlockNumber }
        (bool success, bytes memory data) = _l2OutputOracle.staticcall(
            abi.encodeWithSignature("getL2Output(uint256)", l2OutputIndex)
        );
        if (!success || data.length < 32) revert InvalidL2OutputIndex();

        // The first 32 bytes of the returned struct is the outputRoot
        bytes32 outputRoot;
        assembly {
            outputRoot := mload(add(data, 32))
        }

        return _extractStateRoot(outputRoot);
    }
}
