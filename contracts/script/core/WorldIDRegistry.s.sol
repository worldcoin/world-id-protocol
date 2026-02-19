// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {WorldIDRegistry} from "../../src/core/WorldIDRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployScript is Script {
    WorldIDRegistry public worldIDRegistry;
    ERC1967Proxy public proxy;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        uint256 treeDepth = uint256(vm.envOr("TREE_DEPTH", uint256(30)));
        address feeToken = vm.envAddress("FEE_TOKEN");
        address feeRecipient = vm.envAddress("FEE_RECIPIENT");
        uint256 registrationFee = vm.envUint("REGISTRATION_FEE");

        // Deploy implementation
        WorldIDRegistry implementation = new WorldIDRegistry{salt: bytes32(uint256(0))}();

        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            WorldIDRegistry.initialize.selector, treeDepth, feeRecipient, feeToken, registrationFee
        );

        // Deploy proxy
        proxy = new ERC1967Proxy{salt: bytes32(uint256(0))}(address(implementation), initData);

        worldIDRegistry = WorldIDRegistry(address(proxy));

        vm.stopBroadcast();

        console.log("WorldIDRegistry implementation deployed to:", address(implementation));
        console.log("WorldIDRegistry deployed to:", address(proxy));
    }
}
