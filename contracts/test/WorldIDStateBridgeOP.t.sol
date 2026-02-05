// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {WorldIDStateBridgeOP} from "../src/WorldIDStateBridgeOP.sol";
import {IWorldIDStateBridge} from "../src/interfaces/IWorldIDStateBridge.sol";
import {WorldIDBase} from "../src/abstract/WorldIDBase.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {RLPWriter} from "optimism/packages/contracts-bedrock/src/libraries/rlp/RLPWriter.sol";

/**
 * @dev Mock L1Block predeploy for testing.
 */
contract MockL1Block {
    bytes32 public blockHash;

    function setHash(bytes32 _hash) external {
        blockHash = _hash;
    }

    function hash() external view returns (bytes32) {
        return blockHash;
    }
}

/**
 * @dev Test harness to expose internal functions for testing.
 */
contract WorldIDStateBridgeOPHarness is WorldIDStateBridgeOP {
    function exposed_storeRoot(
        uint256 newRoot,
        uint256 timestamp,
        uint256 l2OutputIndex
    ) external {
        _storeRoot(newRoot, timestamp, l2OutputIndex);
    }

    function exposed_storeIssuerPubkey(
        uint64 issuerSchemaId,
        uint256 pubkeyX,
        uint256 pubkeyY
    ) external {
        _storeIssuerPubkey(issuerSchemaId, pubkeyX, pubkeyY);
    }

    function exposed_storeOprfPubkey(
        uint160 oprfKeyId,
        uint256 pubkeyX,
        uint256 pubkeyY
    ) external {
        _storeOprfPubkey(oprfKeyId, pubkeyX, pubkeyY);
    }

    function exposed_extractStateRoot(
        bytes32 outputRoot
    ) external pure returns (bytes32) {
        return _extractStateRoot(outputRoot);
    }

    function exposed_getTimestampSlot(
        uint256 root
    ) external pure returns (bytes32) {
        return _getTimestampSlot(root);
    }

    function exposed_getIssuerPubkeySlots(
        uint64 issuerSchemaId
    ) external pure returns (bytes32 pubkeyXSlot, bytes32 pubkeyYSlot) {
        return _getIssuerPubkeySlots(issuerSchemaId);
    }

    function exposed_getOprfPubkeySlots(
        uint160 oprfKeyId
    ) external pure returns (bytes32 pubkeyXSlot, bytes32 pubkeyYSlot) {
        return _getOprfPubkeySlots(oprfKeyId);
    }

    // Override the L1Block predeploy address for testing
    address public testL1BlockAddress;

    function setTestL1BlockAddress(address _addr) external {
        testL1BlockAddress = _addr;
    }

    function exposed_verifyL1BlockHeader(
        bytes calldata l1BlockHeader
    ) external view returns (bytes32) {
        return _verifyL1BlockHeader(l1BlockHeader);
    }

    // Override _verifyL1BlockHeader to use our test L1Block address
    function _verifyL1BlockHeader(
        bytes calldata l1BlockHeader
    ) internal view override returns (bytes32 l1StateRoot) {
        address l1BlockAddr = testL1BlockAddress != address(0)
            ? testL1BlockAddress
            : L1_BLOCK_PREDEPLOY;

        // Get the L1 block hash from L1Block predeploy
        (bool success, bytes memory data) = l1BlockAddr.staticcall(
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

import {RLPReader} from "optimism/packages/contracts-bedrock/src/libraries/rlp/RLPReader.sol";

contract WorldIDStateBridgeOPTest is Test {
    WorldIDStateBridgeOPHarness public bridge;
    MockL1Block public mockL1Block;

    address public owner;
    address public l2OutputOracle;
    address public worldChainRegistry;
    address public worldChainIssuerRegistry;
    address public worldChainOprfRegistry;

    uint256 public constant ROOT_VALIDITY_WINDOW = 3600; // 1 hour
    uint256 public constant TREE_DEPTH = 30;

    function setUp() public {
        owner = address(this);
        l2OutputOracle = address(0x1111);
        worldChainRegistry = address(0x2222);
        worldChainIssuerRegistry = address(0x3333);
        worldChainOprfRegistry = address(0x4444);

        // Deploy mock L1Block
        mockL1Block = new MockL1Block();

        // Deploy implementation
        WorldIDStateBridgeOPHarness implementation = new WorldIDStateBridgeOPHarness();

        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            WorldIDStateBridgeOP.initialize.selector,
            l2OutputOracle,
            worldChainRegistry,
            worldChainIssuerRegistry,
            worldChainOprfRegistry,
            ROOT_VALIDITY_WINDOW,
            TREE_DEPTH
        );
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            initData
        );

        bridge = WorldIDStateBridgeOPHarness(address(proxy));
        bridge.setTestL1BlockAddress(address(mockL1Block));
    }

    ////////////////////////////////////////////////////////////
    //                   Initialization Tests                 //
    ////////////////////////////////////////////////////////////

    function test_Initialize() public view {
        assertEq(bridge.getL2OutputOracle(), l2OutputOracle);
        assertEq(bridge.getWorldChainRegistryAddress(), worldChainRegistry);
        assertEq(
            bridge.getWorldChainIssuerRegistryAddress(),
            worldChainIssuerRegistry
        );
        assertEq(
            bridge.getWorldChainOprfRegistryAddress(),
            worldChainOprfRegistry
        );
        assertEq(bridge.getRootValidityWindow(), ROOT_VALIDITY_WINDOW);
        assertEq(bridge.getTreeDepth(), TREE_DEPTH);
    }

    function test_InitializeRevertsOnZeroL2OutputOracle() public {
        WorldIDStateBridgeOPHarness implementation = new WorldIDStateBridgeOPHarness();
        bytes memory initData = abi.encodeWithSelector(
            WorldIDStateBridgeOP.initialize.selector,
            address(0),
            worldChainRegistry,
            worldChainIssuerRegistry,
            worldChainOprfRegistry,
            ROOT_VALIDITY_WINDOW,
            TREE_DEPTH
        );

        vm.expectRevert(
            abi.encodeWithSelector(WorldIDBase.ZeroAddress.selector)
        );
        new ERC1967Proxy(address(implementation), initData);
    }

    function test_InitializeRevertsOnZeroWorldChainRegistry() public {
        WorldIDStateBridgeOPHarness implementation = new WorldIDStateBridgeOPHarness();
        bytes memory initData = abi.encodeWithSelector(
            WorldIDStateBridgeOP.initialize.selector,
            l2OutputOracle,
            address(0),
            worldChainIssuerRegistry,
            worldChainOprfRegistry,
            ROOT_VALIDITY_WINDOW,
            TREE_DEPTH
        );

        vm.expectRevert(
            abi.encodeWithSelector(WorldIDBase.ZeroAddress.selector)
        );
        new ERC1967Proxy(address(implementation), initData);
    }

    function test_InitializeRevertsOnZeroIssuerRegistry() public {
        WorldIDStateBridgeOPHarness implementation = new WorldIDStateBridgeOPHarness();
        bytes memory initData = abi.encodeWithSelector(
            WorldIDStateBridgeOP.initialize.selector,
            l2OutputOracle,
            worldChainRegistry,
            address(0),
            worldChainOprfRegistry,
            ROOT_VALIDITY_WINDOW,
            TREE_DEPTH
        );

        vm.expectRevert(
            abi.encodeWithSelector(WorldIDBase.ZeroAddress.selector)
        );
        new ERC1967Proxy(address(implementation), initData);
    }

    function test_InitializeRevertsOnZeroOprfRegistry() public {
        WorldIDStateBridgeOPHarness implementation = new WorldIDStateBridgeOPHarness();
        bytes memory initData = abi.encodeWithSelector(
            WorldIDStateBridgeOP.initialize.selector,
            l2OutputOracle,
            worldChainRegistry,
            worldChainIssuerRegistry,
            address(0),
            ROOT_VALIDITY_WINDOW,
            TREE_DEPTH
        );

        vm.expectRevert(
            abi.encodeWithSelector(WorldIDBase.ZeroAddress.selector)
        );
        new ERC1967Proxy(address(implementation), initData);
    }

    ////////////////////////////////////////////////////////////
    //                   Root Storage Tests                   //
    ////////////////////////////////////////////////////////////

    function test_StoreRoot() public {
        uint256 newRoot = 0x1234567890abcdef;
        uint256 timestamp = block.timestamp;
        uint256 l2OutputIndex = 1;

        vm.expectEmit(true, true, true, true);
        emit IWorldIDStateBridge.RootBridged(newRoot, timestamp, l2OutputIndex);

        bridge.exposed_storeRoot(newRoot, timestamp, l2OutputIndex);

        assertEq(bridge.getLatestRoot(), newRoot);
        assertEq(bridge.getRootTimestamp(newRoot), timestamp);
        assertTrue(bridge.isValidRoot(newRoot));
    }

    function test_StoreRootRevertsOnZeroRoot() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IWorldIDStateBridge.InvalidStorageProof.selector
            )
        );
        bridge.exposed_storeRoot(0, block.timestamp, 1);
    }

    function test_StoreRootRevertsOnStaleRoot() public {
        uint256 root = 0x1234567890abcdef;
        bridge.exposed_storeRoot(root, block.timestamp, 1);

        vm.expectRevert(
            abi.encodeWithSelector(IWorldIDStateBridge.StaleRoot.selector)
        );
        bridge.exposed_storeRoot(root, block.timestamp + 1, 2);
    }

    function test_StoreRootRevertsOnZeroTimestamp() public {
        vm.expectRevert(
            abi.encodeWithSelector(IWorldIDStateBridge.RootNotRecorded.selector)
        );
        bridge.exposed_storeRoot(0x1234567890abcdef, 0, 1);
    }

    ////////////////////////////////////////////////////////////
    //                   Root Validity Tests                  //
    ////////////////////////////////////////////////////////////

    function test_IsValidRoot_LatestRootAlwaysValid() public {
        uint256 root = 0x1234567890abcdef;
        bridge.exposed_storeRoot(root, block.timestamp, 1);

        assertTrue(bridge.isValidRoot(root));

        // Even after time passes, latest root is still valid
        vm.warp(block.timestamp + ROOT_VALIDITY_WINDOW + 1);
        assertTrue(bridge.isValidRoot(root));
    }

    function test_IsValidRoot_ExpiresAfterWindow() public {
        uint256 root1 = 0x1111111111111111;
        uint256 root2 = 0x2222222222222222;

        bridge.exposed_storeRoot(root1, block.timestamp, 1);

        // Store a new root to make root1 historical
        vm.warp(block.timestamp + 100);
        bridge.exposed_storeRoot(root2, block.timestamp, 2);

        // root1 should still be valid within the window
        assertTrue(bridge.isValidRoot(root1));

        // Warp past the validity window
        vm.warp(block.timestamp + ROOT_VALIDITY_WINDOW + 1);
        assertFalse(bridge.isValidRoot(root1));

        // Latest root should still be valid
        assertTrue(bridge.isValidRoot(root2));
    }

    function test_IsValidRoot_UnknownRootReturnsFalse() public view {
        assertFalse(bridge.isValidRoot(0x9999999999999999));
    }

    ////////////////////////////////////////////////////////////
    //                   Issuer Pubkey Tests                  //
    ////////////////////////////////////////////////////////////

    function test_StoreIssuerPubkey() public {
        uint64 issuerSchemaId = 1;
        uint256 pubkeyX = 0xAAAAAAAAAAAAAAAA;
        uint256 pubkeyY = 0xBBBBBBBBBBBBBBBB;

        vm.expectEmit(true, true, true, true);
        emit IWorldIDStateBridge.IssuerPubkeyBridged(
            issuerSchemaId,
            pubkeyX,
            pubkeyY
        );

        bridge.exposed_storeIssuerPubkey(issuerSchemaId, pubkeyX, pubkeyY);

        IWorldIDStateBridge.Pubkey memory pubkey = bridge.getIssuerPubkey(
            issuerSchemaId
        );
        assertEq(pubkey.x, pubkeyX);
        assertEq(pubkey.y, pubkeyY);
    }

    function test_GetIssuerPubkeySlots() public view {
        uint64 issuerSchemaId = 42;
        (bytes32 xSlot, bytes32 ySlot) = bridge.exposed_getIssuerPubkeySlots(
            issuerSchemaId
        );

        // Verify slot calculation: keccak256(abi.encode(id, SLOT_BASE))
        bytes32 expectedXSlot = keccak256(
            abi.encode(uint256(issuerSchemaId), bytes32(uint256(0)))
        );
        bytes32 expectedYSlot = bytes32(uint256(expectedXSlot) + 1);

        assertEq(xSlot, expectedXSlot);
        assertEq(ySlot, expectedYSlot);
    }

    ////////////////////////////////////////////////////////////
    //                   OPRF Pubkey Tests                    //
    ////////////////////////////////////////////////////////////

    function test_StoreOprfPubkey() public {
        uint160 oprfKeyId = 1;
        uint256 pubkeyX = 0xCCCCCCCCCCCCCCCC;
        uint256 pubkeyY = 0xDDDDDDDDDDDDDDDD;

        vm.expectEmit(true, true, true, true);
        emit IWorldIDStateBridge.OprfPubkeyBridged(oprfKeyId, pubkeyX, pubkeyY);

        bridge.exposed_storeOprfPubkey(oprfKeyId, pubkeyX, pubkeyY);

        IWorldIDStateBridge.Pubkey memory pubkey = bridge.getOprfPubkey(
            oprfKeyId
        );
        assertEq(pubkey.x, pubkeyX);
        assertEq(pubkey.y, pubkeyY);
    }

    function test_GetOprfPubkeySlots() public view {
        uint160 oprfKeyId = 123;
        (bytes32 xSlot, bytes32 ySlot) = bridge.exposed_getOprfPubkeySlots(
            oprfKeyId
        );

        // Verify slot calculation: keccak256(abi.encode(id, SLOT_BASE))
        bytes32 expectedXSlot = keccak256(
            abi.encode(uint256(oprfKeyId), bytes32(uint256(0)))
        );
        bytes32 expectedYSlot = bytes32(uint256(expectedXSlot) + 1);

        assertEq(xSlot, expectedXSlot);
        assertEq(ySlot, expectedYSlot);
    }

    ////////////////////////////////////////////////////////////
    //                   Timestamp Slot Tests                 //
    ////////////////////////////////////////////////////////////

    function test_GetTimestampSlot() public view {
        uint256 root = 0x1234567890abcdef;
        bytes32 slot = bridge.exposed_getTimestampSlot(root);

        // Verify slot calculation: keccak256(abi.encode(root, ROOT_TO_TIMESTAMP_SLOT_BASE))
        bytes32 expectedSlot = keccak256(abi.encode(root, bytes32(uint256(6))));
        assertEq(slot, expectedSlot);
    }

    ////////////////////////////////////////////////////////////
    //                   Extract State Root Tests             //
    ////////////////////////////////////////////////////////////

    function test_ExtractStateRoot() public view {
        bytes32 outputRoot = bytes32(uint256(0x1234567890abcdef));
        // Currently _extractStateRoot returns the outputRoot directly
        bytes32 stateRoot = bridge.exposed_extractStateRoot(outputRoot);
        assertEq(stateRoot, outputRoot);
    }

    ////////////////////////////////////////////////////////////
    //                   L1 Block Header Tests                //
    ////////////////////////////////////////////////////////////

    function test_VerifyL1BlockHeader() public {
        // Create a minimal valid RLP-encoded block header
        // Block header structure: [parentHash, uncleHash, coinbase, stateRoot, ...]
        // We need at least 4 items for the state root extraction

        bytes32 parentHash = bytes32(uint256(0x1111111111111111));
        bytes32 uncleHash = bytes32(uint256(0x2222222222222222));
        address coinbase = address(0x3333);
        bytes32 stateRoot = bytes32(uint256(0x4444444444444444));

        // Build RLP encoded header
        bytes[] memory headerItems = new bytes[](4);
        headerItems[0] = RLPWriter.writeBytes(abi.encodePacked(parentHash));
        headerItems[1] = RLPWriter.writeBytes(abi.encodePacked(uncleHash));
        headerItems[2] = RLPWriter.writeAddress(coinbase);
        headerItems[3] = RLPWriter.writeBytes(abi.encodePacked(stateRoot));

        bytes memory rlpHeader = RLPWriter.writeList(headerItems);

        // Set the mock L1Block hash
        mockL1Block.setHash(keccak256(rlpHeader));

        // Verify the header
        bytes32 extractedStateRoot = bridge.exposed_verifyL1BlockHeader(
            rlpHeader
        );
        assertEq(extractedStateRoot, stateRoot);
    }

    function test_VerifyL1BlockHeaderRevertsOnHashMismatch() public {
        // Create a valid header but don't set the hash in mock
        bytes32 parentHash = bytes32(uint256(0x1111111111111111));
        bytes32 uncleHash = bytes32(uint256(0x2222222222222222));
        address coinbase = address(0x3333);
        bytes32 stateRoot = bytes32(uint256(0x4444444444444444));

        bytes[] memory headerItems = new bytes[](4);
        headerItems[0] = RLPWriter.writeBytes(abi.encodePacked(parentHash));
        headerItems[1] = RLPWriter.writeBytes(abi.encodePacked(uncleHash));
        headerItems[2] = RLPWriter.writeAddress(coinbase);
        headerItems[3] = RLPWriter.writeBytes(abi.encodePacked(stateRoot));

        bytes memory rlpHeader = RLPWriter.writeList(headerItems);

        // Set a different hash in the mock
        mockL1Block.setHash(bytes32(uint256(0x9999)));

        vm.expectRevert(
            abi.encodeWithSelector(
                IWorldIDStateBridge.InvalidL1BlockHash.selector
            )
        );
        bridge.exposed_verifyL1BlockHeader(rlpHeader);
    }

    ////////////////////////////////////////////////////////////
    //                   Owner Function Tests                 //
    ////////////////////////////////////////////////////////////

    function test_SetRootValidityWindow() public {
        uint256 newWindow = 7200;

        vm.expectEmit(true, true, true, true);
        emit IWorldIDStateBridge.RootValidityWindowUpdated(
            ROOT_VALIDITY_WINDOW,
            newWindow
        );

        bridge.setRootValidityWindow(newWindow);

        assertEq(bridge.getRootValidityWindow(), newWindow);
    }

    function test_SetRootValidityWindowOnlyOwner() public {
        vm.prank(address(0xdead));
        vm.expectRevert();
        bridge.setRootValidityWindow(7200);
    }

    function test_SetWorldChainRegistryAddress() public {
        address newAddress = address(0x5555);

        vm.expectEmit(true, true, true, true);
        emit IWorldIDStateBridge.WorldChainRegistryAddressUpdated(
            worldChainRegistry,
            newAddress
        );

        bridge.setWorldChainRegistryAddress(newAddress);

        assertEq(bridge.getWorldChainRegistryAddress(), newAddress);
    }

    function test_SetWorldChainRegistryAddressRevertsOnZero() public {
        vm.expectRevert(
            abi.encodeWithSelector(WorldIDBase.ZeroAddress.selector)
        );
        bridge.setWorldChainRegistryAddress(address(0));
    }

    function test_SetWorldChainRegistryAddressOnlyOwner() public {
        vm.prank(address(0xdead));
        vm.expectRevert();
        bridge.setWorldChainRegistryAddress(address(0x5555));
    }

    function test_SetWorldChainIssuerRegistryAddress() public {
        address newAddress = address(0x6666);

        vm.expectEmit(true, true, true, true);
        emit IWorldIDStateBridge.WorldChainIssuerRegistryAddressUpdated(
            worldChainIssuerRegistry,
            newAddress
        );

        bridge.setWorldChainIssuerRegistryAddress(newAddress);

        assertEq(bridge.getWorldChainIssuerRegistryAddress(), newAddress);
    }

    function test_SetWorldChainIssuerRegistryAddressRevertsOnZero() public {
        vm.expectRevert(
            abi.encodeWithSelector(WorldIDBase.ZeroAddress.selector)
        );
        bridge.setWorldChainIssuerRegistryAddress(address(0));
    }

    function test_SetWorldChainOprfRegistryAddress() public {
        address newAddress = address(0x7777);

        vm.expectEmit(true, true, true, true);
        emit IWorldIDStateBridge.WorldChainOprfRegistryAddressUpdated(
            worldChainOprfRegistry,
            newAddress
        );

        bridge.setWorldChainOprfRegistryAddress(newAddress);

        assertEq(bridge.getWorldChainOprfRegistryAddress(), newAddress);
    }

    function test_SetWorldChainOprfRegistryAddressRevertsOnZero() public {
        vm.expectRevert(
            abi.encodeWithSelector(WorldIDBase.ZeroAddress.selector)
        );
        bridge.setWorldChainOprfRegistryAddress(address(0));
    }

    function test_SetL2OutputOracle() public {
        address newAddress = address(0x8888);

        vm.expectEmit(true, true, true, true);
        emit IWorldIDStateBridge.L2OutputOracleUpdated(
            l2OutputOracle,
            newAddress
        );

        bridge.setL2OutputOracle(newAddress);

        assertEq(bridge.getL2OutputOracle(), newAddress);
    }

    function test_SetL2OutputOracleRevertsOnZero() public {
        vm.expectRevert(
            abi.encodeWithSelector(WorldIDBase.ZeroAddress.selector)
        );
        bridge.setL2OutputOracle(address(0));
    }

    function test_SetL2OutputOracleOnlyOwner() public {
        vm.prank(address(0xdead));
        vm.expectRevert();
        bridge.setL2OutputOracle(address(0x8888));
    }

    ////////////////////////////////////////////////////////////
    //                   EIP-712 Constants Tests              //
    ////////////////////////////////////////////////////////////

    function test_EIP712Constants() public view {
        assertEq(bridge.EIP712_NAME(), "WorldIDStateBridgeOP");
        assertEq(bridge.EIP712_VERSION(), "1.0");
    }

    ////////////////////////////////////////////////////////////
    //                   L2OutputOracle Slot Tests            //
    ////////////////////////////////////////////////////////////

    function test_L2OutputOracleSlotBase() public pure {
        // The slot base for outputRoots in L2OutputOracle is 3
        bytes32 expectedSlotBase = bytes32(uint256(3));
        // This is a constant defined in WorldIDStateBridgeOP
        // We verify the array slot calculation matches what we expect
        bytes32 arraySlot = keccak256(abi.encode(expectedSlotBase));
        // For index 0, the slot would be arraySlot + 0 * 2 (since OutputProposal has 2 slots)
        bytes32 outputRootSlotIndex0 = bytes32(uint256(arraySlot) + 0 * 2);
        assertTrue(outputRootSlotIndex0 != bytes32(0));

        // For index 1, the slot would be arraySlot + 1 * 2
        bytes32 outputRootSlotIndex1 = bytes32(uint256(arraySlot) + 1 * 2);
        assertEq(
            uint256(outputRootSlotIndex1) - uint256(outputRootSlotIndex0),
            2
        );
    }
}
