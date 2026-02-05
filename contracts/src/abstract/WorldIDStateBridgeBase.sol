// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {WorldIDBase} from "./WorldIDBase.sol";
import {IWorldIDStateBridge} from "../interfaces/IWorldIDStateBridge.sol";
import {SecureMerkleTrie} from "optimism/packages/contracts-bedrock/src/libraries/trie/SecureMerkleTrie.sol";
import {RLPReader} from "optimism/packages/contracts-bedrock/src/libraries/rlp/RLPReader.sol";

/**
 * @title WorldIDStateBridgeBase
 * @author World Contributors
 * @notice Abstract base contract for World ID state bridges.
 * @dev Contains shared storage, view functions, owner functions, and proof verification logic.
 *   Concrete implementations (L1, Optimism) inherit from this and implement chain-specific bridging.
 * @custom:repo https://github.com/world-id/world-id-protocol
 */
abstract contract WorldIDStateBridgeBase is WorldIDBase, IWorldIDStateBridge {
    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    // DO NOT REORDER! To ensure compatibility between upgrades, it is exceedingly important
    // that no reordering of these variables takes place. If reordering happens, a storage
    // clash will occur (effectively a memory safety error).

    /// @dev L2OutputOracle contract address on L1 (for World Chain outputs).
    address internal _l2OutputOracle;

    /// @dev World Chain WorldIDRegistry contract address.
    address internal _worldChainRegistryAddress;

    /// @dev World Chain CredentialSchemaIssuerRegistry contract address.
    address internal _worldChainIssuerRegistryAddress;

    /// @dev World Chain OprfKeyRegistry contract address.
    address internal _worldChainOprfRegistryAddress;

    /// @dev Latest bridged root from World Chain.
    uint256 internal _latestRoot;

    /// @dev Mapping from root to its timestamp on World Chain.
    mapping(uint256 => uint256) internal _rootToTimestamp;

    /// @dev Root validity window in seconds (matches World Chain setting).
    uint256 internal _rootValidityWindow;

    /// @dev Tree depth (hardcoded, matches World Chain).
    uint256 internal _treeDepth;

    /// @dev Mapping from issuer schema ID to pubkey.
    mapping(uint64 => Pubkey) internal _issuerSchemaIdToPubkey;

    /// @dev Mapping from OPRF key ID to pubkey.
    mapping(uint160 => Pubkey) internal _oprfKeyIdToPubkey;

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    /// @dev Storage slot for _latestRoot in WorldIDRegistry.
    bytes32 internal constant LATEST_ROOT_SLOT = bytes32(uint256(5));

    /// @dev Storage slot base for _rootToTimestamp mapping in WorldIDRegistry.
    /// The actual slot is keccak256(abi.encode(root, SLOT_BASE))
    bytes32 internal constant ROOT_TO_TIMESTAMP_SLOT_BASE = bytes32(uint256(6));

    /// @dev Storage slot base for _idToPubkey mapping in CredentialSchemaIssuerRegistry.
    /// Pubkey.x is at keccak256(abi.encode(id, SLOT_BASE)), Pubkey.y is at +1
    bytes32 internal constant ISSUER_PUBKEY_SLOT_BASE = bytes32(uint256(0));

    /// @dev Storage slot base for OPRF public keys in OprfKeyRegistry.
    bytes32 internal constant OPRF_PUBKEY_SLOT_BASE = bytes32(uint256(0));

    ////////////////////////////////////////////////////////////
    //                        Constructor                     //
    ////////////////////////////////////////////////////////////

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the base state bridge contract.
     * @param name The EIP-712 signing domain name.
     * @param version The EIP-712 signing domain version.
     * @param l2OutputOracle Address of the L2OutputOracle contract on L1.
     * @param worldChainRegistryAddress Address of the WorldIDRegistry on World Chain.
     * @param worldChainIssuerRegistryAddress Address of the CredentialSchemaIssuerRegistry on World Chain.
     * @param worldChainOprfRegistryAddress Address of the OprfKeyRegistry on World Chain.
     * @param rootValidityWindow Validity window for roots in seconds.
     * @param treeDepth Merkle tree depth (should match World Chain).
     */
    function __WorldIDStateBridgeBase_init(
        string memory name,
        string memory version,
        address l2OutputOracle,
        address worldChainRegistryAddress,
        address worldChainIssuerRegistryAddress,
        address worldChainOprfRegistryAddress,
        uint256 rootValidityWindow,
        uint256 treeDepth
    ) internal onlyInitializing {
        if (l2OutputOracle == address(0)) revert ZeroAddress();
        if (worldChainRegistryAddress == address(0)) revert ZeroAddress();
        if (worldChainIssuerRegistryAddress == address(0)) revert ZeroAddress();
        if (worldChainOprfRegistryAddress == address(0)) revert ZeroAddress();

        __BaseUpgradeable_init(name, version, address(0), address(0), 0);

        _l2OutputOracle = l2OutputOracle;
        _worldChainRegistryAddress = worldChainRegistryAddress;
        _worldChainIssuerRegistryAddress = worldChainIssuerRegistryAddress;
        _worldChainOprfRegistryAddress = worldChainOprfRegistryAddress;
        _rootValidityWindow = rootValidityWindow;
        _treeDepth = treeDepth;
    }

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IWorldIDStateBridge
    function getLatestRoot()
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (uint256)
    {
        return _latestRoot;
    }

    /// @inheritdoc IWorldIDStateBridge
    function getRootTimestamp(
        uint256 root
    ) external view virtual onlyProxy onlyInitialized returns (uint256) {
        return _rootToTimestamp[root];
    }

    /// @inheritdoc IWorldIDStateBridge
    function isValidRoot(
        uint256 root
    ) external view virtual onlyProxy onlyInitialized returns (bool) {
        uint256 timestamp = _rootToTimestamp[root];
        if (timestamp == 0) return false;
        if (root == _latestRoot) return true;
        return block.timestamp <= timestamp + _rootValidityWindow;
    }

    /// @inheritdoc IWorldIDStateBridge
    function getRootValidityWindow()
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (uint256)
    {
        return _rootValidityWindow;
    }

    /// @inheritdoc IWorldIDStateBridge
    function getTreeDepth()
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (uint256)
    {
        return _treeDepth;
    }

    /// @inheritdoc IWorldIDStateBridge
    function getIssuerPubkey(
        uint64 issuerSchemaId
    ) external view virtual onlyProxy onlyInitialized returns (Pubkey memory) {
        return _issuerSchemaIdToPubkey[issuerSchemaId];
    }

    /// @inheritdoc IWorldIDStateBridge
    function getOprfPubkey(
        uint160 oprfKeyId
    ) external view virtual onlyProxy onlyInitialized returns (Pubkey memory) {
        return _oprfKeyIdToPubkey[oprfKeyId];
    }

    /**
     * @notice Returns the L2OutputOracle address.
     * @return The address.
     */
    function getL2OutputOracle()
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (address)
    {
        return _l2OutputOracle;
    }

    /**
     * @notice Returns the World Chain WorldIDRegistry address.
     * @return The address.
     */
    function getWorldChainRegistryAddress()
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (address)
    {
        return _worldChainRegistryAddress;
    }

    /**
     * @notice Returns the World Chain CredentialSchemaIssuerRegistry address.
     * @return The address.
     */
    function getWorldChainIssuerRegistryAddress()
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (address)
    {
        return _worldChainIssuerRegistryAddress;
    }

    /**
     * @notice Returns the World Chain OprfKeyRegistry address.
     * @return The address.
     */
    function getWorldChainOprfRegistryAddress()
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (address)
    {
        return _worldChainOprfRegistryAddress;
    }

    ////////////////////////////////////////////////////////////
    //                    OWNER FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IWorldIDStateBridge
    function setRootValidityWindow(
        uint256 newWindow
    ) external virtual onlyOwner onlyProxy onlyInitialized {
        uint256 oldWindow = _rootValidityWindow;
        _rootValidityWindow = newWindow;
        emit RootValidityWindowUpdated(oldWindow, newWindow);
    }

    /// @inheritdoc IWorldIDStateBridge
    function setWorldChainRegistryAddress(
        address newAddress
    ) external virtual onlyOwner onlyProxy onlyInitialized {
        if (newAddress == address(0)) revert ZeroAddress();
        address oldAddress = _worldChainRegistryAddress;
        _worldChainRegistryAddress = newAddress;
        emit WorldChainRegistryAddressUpdated(oldAddress, newAddress);
    }

    /// @inheritdoc IWorldIDStateBridge
    function setWorldChainIssuerRegistryAddress(
        address newAddress
    ) external virtual onlyOwner onlyProxy onlyInitialized {
        if (newAddress == address(0)) revert ZeroAddress();
        address oldAddress = _worldChainIssuerRegistryAddress;
        _worldChainIssuerRegistryAddress = newAddress;
        emit WorldChainIssuerRegistryAddressUpdated(oldAddress, newAddress);
    }

    /// @inheritdoc IWorldIDStateBridge
    function setWorldChainOprfRegistryAddress(
        address newAddress
    ) external virtual onlyOwner onlyProxy onlyInitialized {
        if (newAddress == address(0)) revert ZeroAddress();
        address oldAddress = _worldChainOprfRegistryAddress;
        _worldChainOprfRegistryAddress = newAddress;
        emit WorldChainOprfRegistryAddressUpdated(oldAddress, newAddress);
    }

    /// @inheritdoc IWorldIDStateBridge
    function setL2OutputOracle(
        address newAddress
    ) external virtual onlyOwner onlyProxy onlyInitialized {
        if (newAddress == address(0)) revert ZeroAddress();
        address oldAddress = _l2OutputOracle;
        _l2OutputOracle = newAddress;
        emit L2OutputOracleUpdated(oldAddress, newAddress);
    }

    ////////////////////////////////////////////////////////////
    //                   INTERNAL FUNCTIONS                   //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Stores a bridged root and its timestamp.
     * @param newRoot The new root to store.
     * @param timestamp The timestamp when the root was recorded on World Chain.
     * @param l2OutputIndex The L2OutputOracle output index used for verification.
     */
    function _storeRoot(
        uint256 newRoot,
        uint256 timestamp,
        uint256 l2OutputIndex
    ) internal virtual {
        if (newRoot == 0) revert InvalidStorageProof();
        if (_rootToTimestamp[newRoot] != 0) revert StaleRoot();
        if (timestamp == 0) revert RootNotRecorded();

        _latestRoot = newRoot;
        _rootToTimestamp[newRoot] = timestamp;

        emit RootBridged(newRoot, timestamp, l2OutputIndex);
    }

    /**
     * @notice Stores a bridged issuer pubkey.
     * @param issuerSchemaId The issuer schema ID.
     * @param pubkeyX The x coordinate of the pubkey.
     * @param pubkeyY The y coordinate of the pubkey.
     */
    function _storeIssuerPubkey(
        uint64 issuerSchemaId,
        uint256 pubkeyX,
        uint256 pubkeyY
    ) internal virtual {
        _issuerSchemaIdToPubkey[issuerSchemaId] = Pubkey(pubkeyX, pubkeyY);
        emit IssuerPubkeyBridged(issuerSchemaId, pubkeyX, pubkeyY);
    }

    /**
     * @notice Stores a bridged OPRF pubkey.
     * @param oprfKeyId The OPRF key ID.
     * @param pubkeyX The x coordinate of the pubkey.
     * @param pubkeyY The y coordinate of the pubkey.
     */
    function _storeOprfPubkey(
        uint160 oprfKeyId,
        uint256 pubkeyX,
        uint256 pubkeyY
    ) internal virtual {
        _oprfKeyIdToPubkey[oprfKeyId] = Pubkey(pubkeyX, pubkeyY);
        emit OprfPubkeyBridged(oprfKeyId, pubkeyX, pubkeyY);
    }

    /**
     * @notice Extracts the state root from an OP Stack output root.
     * @dev The output root is computed as: keccak256(version || stateRoot || withdrawalStorageRoot || blockHash)
     *   Since we can't reverse keccak256, the caller must provide the state root via proof.
     *   For now, we treat the output root as the state root directly.
     *   In production, this should verify against the output root preimage.
     * @param outputRoot The output root from L2OutputOracle.
     * @return The state root.
     */
    function _extractStateRoot(
        bytes32 outputRoot
    ) internal pure virtual returns (bytes32) {
        // NOTE: In a full implementation, this would require the caller to provide
        // the output root preimage (version, stateRoot, withdrawalStorageRoot, blockHash)
        // and verify that keccak256(preimage) == outputRoot.
        // For simplicity, we assume the state root is provided/verified externally.
        // The actual state root extraction should be done by the bridge service.
        return outputRoot;
    }

    /**
     * @notice Verifies an account proof and extracts the storage root.
     * @param account The account address to verify.
     * @param proof The Merkle proof nodes.
     * @param stateRoot The state root to verify against.
     * @return storageRoot The account's storage root.
     */
    function _verifyAccountAndGetStorageRoot(
        address account,
        bytes[] calldata proof,
        bytes32 stateRoot
    ) internal pure virtual returns (bytes32 storageRoot) {
        // Get account RLP from the trie
        bytes memory accountRlp = SecureMerkleTrie.get(
            abi.encodePacked(account),
            proof,
            stateRoot
        );
        if (accountRlp.length == 0) revert InvalidAccountProof();

        // Parse account RLP: [nonce, balance, storageRoot, codeHash]
        RLPReader.RLPItem[] memory accountFields = RLPReader.readList(
            accountRlp
        );
        if (accountFields.length != 4) revert InvalidAccountProof();

        // Storage root is at index 2
        storageRoot = bytes32(RLPReader.readBytes(accountFields[2]));
    }

    /**
     * @notice Retrieves a storage value from a storage proof.
     * @param proof The storage Merkle proof nodes.
     * @param storageRoot The storage root to verify against.
     * @param slot The storage slot to retrieve.
     * @return value The storage value as uint256.
     */
    function _getStorageValue(
        bytes[] calldata proof,
        bytes32 storageRoot,
        bytes32 slot
    ) internal pure virtual returns (uint256 value) {
        // Get value RLP from the trie (slot is hashed by SecureMerkleTrie)
        bytes memory valueRlp = SecureMerkleTrie.get(
            abi.encodePacked(slot),
            proof,
            storageRoot
        );
        if (valueRlp.length == 0) {
            return 0;
        }

        // Parse the RLP-encoded value
        value = uint256(
            bytes32(RLPReader.readBytes(RLPReader.toRLPItem(valueRlp)))
        );
    }

    /**
     * @notice Calculates the storage slot for a timestamp mapping entry.
     * @param root The root to get the timestamp slot for.
     * @return The storage slot.
     */
    function _getTimestampSlot(
        uint256 root
    ) internal pure virtual returns (bytes32) {
        return keccak256(abi.encode(root, ROOT_TO_TIMESTAMP_SLOT_BASE));
    }

    /**
     * @notice Calculates the storage slots for an issuer pubkey.
     * @param issuerSchemaId The issuer schema ID.
     * @return pubkeyXSlot The storage slot for pubkey.x.
     * @return pubkeyYSlot The storage slot for pubkey.y.
     */
    function _getIssuerPubkeySlots(
        uint64 issuerSchemaId
    ) internal pure virtual returns (bytes32 pubkeyXSlot, bytes32 pubkeyYSlot) {
        bytes32 pubkeySlotBase = keccak256(
            abi.encode(uint256(issuerSchemaId), ISSUER_PUBKEY_SLOT_BASE)
        );
        pubkeyXSlot = pubkeySlotBase;
        pubkeyYSlot = bytes32(uint256(pubkeySlotBase) + 1);
    }

    /**
     * @notice Calculates the storage slots for an OPRF pubkey.
     * @param oprfKeyId The OPRF key ID.
     * @return pubkeyXSlot The storage slot for pubkey.x.
     * @return pubkeyYSlot The storage slot for pubkey.y.
     */
    function _getOprfPubkeySlots(
        uint160 oprfKeyId
    ) internal pure virtual returns (bytes32 pubkeyXSlot, bytes32 pubkeyYSlot) {
        bytes32 pubkeySlotBase = keccak256(
            abi.encode(uint256(oprfKeyId), OPRF_PUBKEY_SLOT_BASE)
        );
        pubkeyXSlot = pubkeySlotBase;
        pubkeyYSlot = bytes32(uint256(pubkeySlotBase) + 1);
    }
}
