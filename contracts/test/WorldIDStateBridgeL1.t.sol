// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {WorldIDStateBridgeL1} from "../src/WorldIDStateBridgeL1.sol";
import {IWorldIDStateBridge} from "../src/interfaces/IWorldIDStateBridge.sol";
import {WorldIDBase} from "../src/abstract/WorldIDBase.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @dev Mock L2OutputOracle for testing.
 */
contract MockL2OutputOracle {
    error L2OutputNotFound();

    struct OutputProposal {
        bytes32 outputRoot;
        uint128 timestamp;
        uint128 l2BlockNumber;
    }

    mapping(uint256 => OutputProposal) public outputs;
    mapping(uint256 => bool) public outputExists;
    uint256 public nextOutputIndex;

    function setOutput(
        uint256 index,
        bytes32 outputRoot,
        uint128 timestamp,
        uint128 l2BlockNumber
    ) external {
        outputs[index] = OutputProposal(outputRoot, timestamp, l2BlockNumber);
        outputExists[index] = true;
        if (index >= nextOutputIndex) {
            nextOutputIndex = index + 1;
        }
    }

    function getL2Output(
        uint256 _l2OutputIndex
    ) external view returns (OutputProposal memory) {
        if (!outputExists[_l2OutputIndex]) revert L2OutputNotFound();
        return outputs[_l2OutputIndex];
    }
}

/**
 * @dev Test harness to expose internal functions for testing.
 */
contract WorldIDStateBridgeL1Harness is WorldIDStateBridgeL1 {
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

    function exposed_getWorldChainStateRoot(
        uint256 l2OutputIndex
    ) external view returns (bytes32) {
        return _getWorldChainStateRoot(l2OutputIndex);
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
}

contract WorldIDStateBridgeL1Test is Test {
    WorldIDStateBridgeL1Harness public bridge;
    MockL2OutputOracle public mockOracle;

    address public owner;
    address public worldChainRegistry;
    address public worldChainIssuerRegistry;
    address public worldChainOprfRegistry;

    uint256 public constant ROOT_VALIDITY_WINDOW = 3600; // 1 hour
    uint256 public constant TREE_DEPTH = 30;

    function setUp() public {
        owner = address(this);
        worldChainRegistry = address(0x1111);
        worldChainIssuerRegistry = address(0x2222);
        worldChainOprfRegistry = address(0x3333);

        // Deploy mock L2OutputOracle
        mockOracle = new MockL2OutputOracle();

        // Deploy implementation
        WorldIDStateBridgeL1Harness implementation = new WorldIDStateBridgeL1Harness();

        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            WorldIDStateBridgeL1.initialize.selector,
            address(mockOracle),
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

        bridge = WorldIDStateBridgeL1Harness(address(proxy));
    }

    ////////////////////////////////////////////////////////////
    //                   Initialization Tests                 //
    ////////////////////////////////////////////////////////////

    function test_Initialize() public view {
        assertEq(bridge.getL2OutputOracle(), address(mockOracle));
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
        WorldIDStateBridgeL1Harness implementation = new WorldIDStateBridgeL1Harness();
        bytes memory initData = abi.encodeWithSelector(
            WorldIDStateBridgeL1.initialize.selector,
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
        WorldIDStateBridgeL1Harness implementation = new WorldIDStateBridgeL1Harness();
        bytes memory initData = abi.encodeWithSelector(
            WorldIDStateBridgeL1.initialize.selector,
            address(mockOracle),
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
        WorldIDStateBridgeL1Harness implementation = new WorldIDStateBridgeL1Harness();
        bytes memory initData = abi.encodeWithSelector(
            WorldIDStateBridgeL1.initialize.selector,
            address(mockOracle),
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
        WorldIDStateBridgeL1Harness implementation = new WorldIDStateBridgeL1Harness();
        bytes memory initData = abi.encodeWithSelector(
            WorldIDStateBridgeL1.initialize.selector,
            address(mockOracle),
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
    //                   L2OutputOracle Tests                 //
    ////////////////////////////////////////////////////////////

    function test_GetWorldChainStateRoot() public {
        bytes32 outputRoot = bytes32(uint256(0x5555555555555555));
        mockOracle.setOutput(
            1,
            outputRoot,
            uint128(block.timestamp),
            uint128(1000)
        );

        bytes32 stateRoot = bridge.exposed_getWorldChainStateRoot(1);
        // Currently _extractStateRoot returns the outputRoot directly
        assertEq(stateRoot, outputRoot);
    }

    function test_GetWorldChainStateRootRevertsOnInvalidIndex() public {
        // Index 0 has no output set (all zeros)
        vm.expectRevert(
            abi.encodeWithSelector(
                IWorldIDStateBridge.InvalidL2OutputIndex.selector
            )
        );
        bridge.exposed_getWorldChainStateRoot(999);
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
        address newAddress = address(0x4444);

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
        bridge.setWorldChainRegistryAddress(address(0x4444));
    }

    function test_SetWorldChainIssuerRegistryAddress() public {
        address newAddress = address(0x5555);

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
        address newAddress = address(0x6666);

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
        address newAddress = address(0x7777);

        vm.expectEmit(true, true, true, true);
        emit IWorldIDStateBridge.L2OutputOracleUpdated(
            address(mockOracle),
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
        bridge.setL2OutputOracle(address(0x7777));
    }

    ////////////////////////////////////////////////////////////
    //                   EIP-712 Constants Tests              //
    ////////////////////////////////////////////////////////////

    function test_EIP712Constants() public view {
        assertEq(bridge.EIP712_NAME(), "WorldIDStateBridgeL1");
        assertEq(bridge.EIP712_VERSION(), "1.0");
    }
}
