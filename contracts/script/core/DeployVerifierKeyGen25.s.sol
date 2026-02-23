// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {Verifier as VerifierKeyGen25} from "oprf-key-registry/src/VerifierKeyGen25.sol";

/// @title DeployVerifierKeyGen25Script
/// @notice Deploys the Groth16 verifier for the OPRF key-generation circuit (25 nodes).
contract DeployVerifierKeyGen25Script is Script {
    function run() public returns (address verifier) {
        vm.startBroadcast();
        verifier = address(new VerifierKeyGen25());
        vm.stopBroadcast();
        console2.log("VerifierKeyGen25 deployed to:", verifier);
    }
}
