// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {AccountRegistry} from "../src/AccountRegistry.sol";

contract CounterScript is Script {
    AccountRegistry public accountRegistry;
    address public constant DEFAULT_RECOVERY_ADDRESS = address(0xDEADBEEF);

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        accountRegistry = new AccountRegistry(DEFAULT_RECOVERY_ADDRESS);

        vm.stopBroadcast();

        console.log("AccountRegistry deployed to:", address(accountRegistry));
    }
}
