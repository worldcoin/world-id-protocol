pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {AuthenticatorRegistry} from "../src/AuthenticatorRegistry.sol";

contract InsertAuthenticatorScript is Script {
    AuthenticatorRegistry public authenticatorRegistry;
    function setUp() public {
        authenticatorRegistry = AuthenticatorRegistry(
            vm.envAddress("AUTHENTICATOR_REGISTRY")
        );
    }

    function run() public {
        vm.startBroadcast();

        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = address(uint160(0xDEADBEEF2));

        authenticatorRegistry.createAccount(
            address(0),
            authenticatorAddresses,
            0xDEADBEEF2
        );

        vm.stopBroadcast();
    }
}
