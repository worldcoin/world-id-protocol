// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {AccountRegistry} from "../src/AccountRegistry.sol";

contract CounterScript is Script {
    AccountRegistry public accountRegistry;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        accountRegistry = new AccountRegistry();

        vm.stopBroadcast();

        console.log("AccountRegistry deployed to:", address(accountRegistry));
    }
}
