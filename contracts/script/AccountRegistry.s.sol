// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {AccountRegistry} from "../src/AccountRegistry.sol";

contract CounterScript is Script {
    AuthenticatorRegistry public authenticatorRegistry;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        authenticatorRegistry = new AuthenticatorRegistry();

        vm.stopBroadcast();

        console.log("AccountRegistry deployed to:", address(accountRegistry));
    }
}
