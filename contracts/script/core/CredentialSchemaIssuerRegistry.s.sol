// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {CredentialSchemaIssuerRegistry} from "../../src/core/CredentialSchemaIssuerRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployCredentialSchemaIssuerRegistryScript is Script {
    CredentialSchemaIssuerRegistry public registry;
    ERC1967Proxy public proxy;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        // Deploy implementation
        CredentialSchemaIssuerRegistry implementation = new CredentialSchemaIssuerRegistry{salt: bytes32(uint256(0))}();

        address feeRecipient = vm.envAddress("FEE_RECIPIENT");
        address feeToken = vm.envAddress("FEE_TOKEN");
        uint256 registrationFee = vm.envUint("REGISTRATION_FEE");
        address oprfKeyRegistryAddress = vm.envAddress("OPRF_KEY_REGISTRY_ADDRESS");

        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            CredentialSchemaIssuerRegistry.initialize.selector,
            feeRecipient,
            feeToken,
            registrationFee,
            oprfKeyRegistryAddress
        );

        // Deploy proxy
        proxy = new ERC1967Proxy{salt: bytes32(uint256(0))}(address(implementation), initData);

        registry = CredentialSchemaIssuerRegistry(address(proxy));

        vm.stopBroadcast();

        console.log("CredentialSchemaIssuerRegistry implementation deployed to:", address(implementation));
        console.log("CredentialSchemaIssuerRegistry proxy deployed to:", address(proxy));
    }
}
