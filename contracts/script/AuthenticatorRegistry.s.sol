// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {AuthenticatorRegistry} from "../src/AuthenticatorRegistry.sol";

contract CounterScript is Script {
    AuthenticatorRegistry public authenticatorRegistry;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        authenticatorRegistry = new AuthenticatorRegistry();

        vm.stopBroadcast();

        console.log("AuthenticatorRegistry deployed to:", address(authenticatorRegistry));
    }
}
