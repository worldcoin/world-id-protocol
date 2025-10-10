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
        authenticatorPubkeys[0] = 57915933778004089767388106625639599040044329507355901050367950978468818626307;

        accountRegistry.createAccount(
            address(0xABCD),
            authenticatorAddresses,
            authenticatorPubkeys,
            16908911131908466253201651729526298224917354283985919003033323496927029647192
        );

        vm.stopBroadcast();
    }
}
