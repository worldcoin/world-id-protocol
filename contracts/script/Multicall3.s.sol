// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {Multicall3} from "../src/Multicall3.sol";

contract CounterScript is Script {
    Multicall3 public multicall3;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        multicall3 = new Multicall3();

        vm.stopBroadcast();

        console.log("Multicall3 deployed to:", address(multicall3));
    }
}
