pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {AccountRegistry} from "../src/AccountRegistry.sol";

contract InsertAuthenticatorScript is Script {
    AccountRegistry public accountRegistry;

    function setUp() public {
        accountRegistry = AccountRegistry(vm.envAddress("ACCOUNT_REGISTRY"));
    }

    function run() public {
        vm.startBroadcast();

        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = address(uint160(0x001a642f0e3c3af545e7acbd38b07251b3990914f1));
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;

        accountRegistry.createAccount(
            address(0xABCD),
            authenticatorAddresses,
            authenticatorPubkeys,
            4596139669427585175607039512742516429109067376192684501939126887078600807431
        );

        vm.stopBroadcast();
    }
}
