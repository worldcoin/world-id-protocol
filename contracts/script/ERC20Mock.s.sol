// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";

contract DeployScript is Script {
    ERC20Mock public erc20Mock;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        erc20Mock = new ERC20Mock();

        vm.stopBroadcast();

        console.log("ERC20Mock deployed to:", address(erc20Mock));
    }
}
