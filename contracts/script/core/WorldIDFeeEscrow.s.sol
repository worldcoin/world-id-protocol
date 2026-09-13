// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {WorldIDFeeEscrow} from "../../src/core/WorldIDFeeEscrow.sol";

/// Deploys the fee escrow behind an ERC1967 proxy, plus a mock fee token for development channels.
contract DeployScript is Script {
    WorldIDFeeEscrow public implementation;
    ERC1967Proxy public proxy;
    address public token;

    function setUp() public {}

    function run() public {
        address rpRegistry = vm.envAddress("RP_REGISTRY_ADDRESS");
        bool deployMockToken = vm.envOr("DEPLOY_MOCK_TOKEN", true);
        string memory outPath = vm.envOr("DEPLOYMENT_OUTPUT", string("deployments/core/fee-escrow-dev.json"));

        vm.startBroadcast();

        implementation = new WorldIDFeeEscrow();
        bytes memory initData = abi.encodeCall(WorldIDFeeEscrow.initialize, (rpRegistry));
        proxy = new ERC1967Proxy(address(implementation), initData);
        if (deployMockToken) token = address(new ERC20Mock());

        vm.stopBroadcast();

        console.log("WorldIDFeeEscrow implementation deployed to:", address(implementation));
        console.log("WorldIDFeeEscrow proxy deployed to:", address(proxy));
        if (deployMockToken) console.log("ERC20Mock fee token deployed to:", token);

        string memory json = "deployment";
        vm.serializeUint(json, "chainId", block.chainid);
        vm.serializeAddress(json, "deployer", msg.sender);
        vm.serializeAddress(json, "rpRegistry", rpRegistry);
        vm.serializeAddress(json, "implementation", address(implementation));
        vm.serializeAddress(json, "proxy", address(proxy));
        vm.serializeUint(json, "timestamp", block.timestamp);
        string memory out = vm.serializeAddress(json, "mockToken", token);
        vm.writeJson(out, outPath);
    }
}
