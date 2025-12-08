// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {WorldIDRegistry} from "../src/WorldIDRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployScript is Script {
    WorldIDRegistry public accountRegistry;
    ERC1967Proxy public proxy;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        uint256 treeDepth = uint256(vm.envOr("TREE_DEPTH", uint256(30)));

        // Deploy implementation
        WorldIDRegistry implementation = new WorldIDRegistry{salt: bytes32(uint256(0))}();

        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(WorldIDRegistry.initialize.selector, treeDepth);

        // Deploy proxy
        proxy = new ERC1967Proxy{salt: bytes32(uint256(0))}(address(implementation), initData);

        accountRegistry = WorldIDRegistry(address(proxy));

        vm.stopBroadcast();

        console.log("WorldIDRegistry implementation deployed to:", address(implementation));
        console.log("WorldIDRegistry deployed to:", address(proxy));
    }
}
