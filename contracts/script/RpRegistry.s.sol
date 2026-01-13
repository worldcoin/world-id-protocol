// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {RpRegistry} from "../src/RpRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";

contract DeployScript is Script {
    RpRegistry public rpRegistry;
    ERC1967Proxy public proxy;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        address oprfKeyRegitryAddress = vm.envAddress("OPRF_KEY_REGISTRY_ADDRESS");

        // Deploy implementation
        RpRegistry implementation = new RpRegistry{salt: bytes32(uint256(0))}();

        // Deploy mock ERC20 token
        ERC20Mock feeToken = new ERC20Mock();

        // Dummy fee recipient
        address feeRecipient = vm.addr(0x9999);

        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            RpRegistry.initialize.selector, feeRecipient, address(feeToken), 0, oprfKeyRegitryAddress
        );

        // Deploy proxy
        proxy = new ERC1967Proxy{salt: bytes32(uint256(0))}(address(implementation), initData);

        rpRegistry = RpRegistry(address(proxy));

        vm.stopBroadcast();

        console.log("RpRegistry implementation deployed to:", address(implementation));
        console.log("RpRegistry deployed to:", address(proxy));
    }
}
