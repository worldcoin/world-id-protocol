// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import {WorldIDRegistry} from "../src/WorldIDRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {CredentialSchemaIssuerRegistry} from "../src/CredentialSchemaIssuerRegistry.sol";
import {RpRegistry} from "../src/RpRegistry.sol";
import {WorldIDVerifier} from "../src/WorldIDVerifier.sol";
import {Verifier} from "../src/Verifier.sol";

/// @title Deploy
/// @notice Bootstraps and deploys all World ID contracts for a given environment.
contract Deploy is Script {
    address public worldIDRegistryAddress;
    address public credentialSchemaIssuerRegistryAddress;
    address public rpRegistryAddress;
    address public worldIDVerifierAddress;
    address public verifierAddress;

    address public worldIDRegistryImplAddress;
    address public credentialSchemaIssuerRegistryImplAddress;
    address public rpRegistryImplAddress;
    address public worldIDVerifierImplAddress;

    /// @notice Deploy all contracts for the given environment.
    /// @dev Usage: forge script script/DeployBase.sol --sig "run(string)" "staging" --broadcast --private-key $PK
    /// @param env The environment name matching a file in script/config/ (e.g. "local", "staging", "production").
    function run(string calldata env) public {
        string memory config = _loadConfig(env);

        vm.startBroadcast();
        _run(config);
        vm.stopBroadcast();

        _writeDeployment(env);
    }

    function _run(string memory config) internal virtual {
        deployWorldIdRegistry(config);
        deployCredentialSchemaIssuerRegistry(config);
        deployWorldIdRegistry(config);
        deployWorldIdVerifier(config);
    }

    function deployWorldIdRegistry(string memory config) public {
        uint256 treeDepth = vm.parseJsonUint(config, ".worldIDRegistry.treeDepth");
        address feeRecipient = vm.parseJsonAddress(config, ".worldIDRegistry.feeRecipient");
        address feeToken = vm.parseJsonAddress(config, ".worldIDRegistry.feeToken");
        uint256 registrationFee = vm.parseJsonUint(config, ".worldIDRegistry.registrationFee");
        console2.log("--- Deploying WorldIDRegistry ---");
        console2.log("Deploying WorldIDRegistry with tree depth:", treeDepth);
        console2.log("Fee recipient:", feeRecipient);
        console2.log("Fee token:", feeToken);
        console2.log("Registration fee:", registrationFee);

        bytes32 salt = vm.parseJsonBytes32(config, ".salts.worldIDRegistry");

        // Deploy implementation
        WorldIDRegistry implementation = new WorldIDRegistry{salt: bytes32(uint256(0))}();
        worldIDRegistryImplAddress = address(implementation);

        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            WorldIDRegistry.initialize.selector, treeDepth, feeRecipient, feeToken, registrationFee
        );

        bytes memory initCode = abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(implementation, initData));

        worldIDRegistryAddress = deploy(salt, initCode);
    }

    function deployCredentialSchemaIssuerRegistry(string memory config) public {
        address feeRecipient = vm.parseJsonAddress(config, ".credentialSchemaIssuerRegistry.feeRecipient");
        address feeToken = vm.parseJsonAddress(config, ".credentialSchemaIssuerRegistry.feeToken");
        uint256 registrationFee = vm.parseJsonUint(config, ".credentialSchemaIssuerRegistry.registrationFee");
        address oprfKeyRegistryAddress = vm.parseJsonAddress(config, ".externalDependencies.oprfKeyRegistry");
        bytes32 salt = vm.parseJsonBytes32(config, ".salts.credentialSchemaIssuerRegistry");

        console2.log("--- Deploying CredentialSchemaIssuerRegistry ---");
        console2.log("Fee recipient:", feeRecipient);
        console2.log("Fee token:", feeToken);
        console2.log("Registration fee:", registrationFee);
        console2.log("OPRF Key Registry address:", oprfKeyRegistryAddress);
        console2.log("Salt:");
        console2.logBytes32(salt);
        // Deploy implementation
        CredentialSchemaIssuerRegistry implementation = new CredentialSchemaIssuerRegistry{salt: bytes32(uint256(0))}();
        credentialSchemaIssuerRegistryImplAddress = address(implementation);

        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            CredentialSchemaIssuerRegistry.initialize.selector,
            feeRecipient,
            feeToken,
            registrationFee,
            oprfKeyRegistryAddress
        );

        bytes memory initCode = abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(implementation, initData));

        credentialSchemaIssuerRegistryAddress = deploy(salt, initCode);
    }

    function deployRpRegistry(string memory config) public {
        address feeRecipient = vm.parseJsonAddress(config, ".rpRegistry.feeRecipient");
        address feeToken = vm.parseJsonAddress(config, ".rpRegistry.feeToken");
        uint256 registrationFee = vm.parseJsonUint(config, ".rpRegistry.registrationFee");
        address oprfKeyRegistryAddress = vm.parseJsonAddress(config, ".externalDependencies.oprfKeyRegistry");
        bytes32 salt = vm.parseJsonBytes32(config, ".salts.rpRegistry");

        // Deploy implementation
        RpRegistry implementation = new RpRegistry();
        rpRegistryImplAddress = address(implementation);

        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            RpRegistry.initialize.selector, feeRecipient, feeToken, registrationFee, oprfKeyRegistryAddress
        );

        bytes memory initCode = abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(implementation, initData));

        rpRegistryAddress = deploy(salt, initCode);
    }

    function deployWorldIdVerifier(string memory config) public {
        verifierAddress = address(new Verifier());

        bytes32 salt = vm.parseJsonBytes32(config, ".salts.worldIDVerifier");

        WorldIDVerifier implementation = new WorldIDVerifier();
        worldIDVerifierImplAddress = address(implementation);

        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            WorldIDVerifier.initialize.selector,
            credentialSchemaIssuerRegistryAddress,
            worldIDRegistryAddress,
            vm.parseJsonAddress(config, ".externalDependencies.oprfKeyRegistry"),
            verifierAddress,
            uint64(vm.parseJsonUint(config, ".worldIDVerifier.minExpirationThreshold"))
        );

        bytes memory initCode = abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(implementation, initData));

        worldIDVerifierAddress = deploy(salt, initCode);
    }

    /// @notice Loads a JSON config file for the given environment.
    /// @param env The environment name (e.g. "local", "staging", "production").
    /// @return json The raw JSON string contents of the config file.
    function _loadConfig(string memory env) internal view returns (string memory json) {
        string memory path = string.concat("script/config/", env, ".json");
        json = vm.readFile(path);
    }

    function _writeDeployment(string memory env) internal {
        // WorldIDRegistry
        string memory worldIdReg = "worldIDRegistry";
        vm.serializeAddress(worldIdReg, "implementation", worldIDRegistryImplAddress);
        string memory worldIdRegJson = vm.serializeAddress(worldIdReg, "proxy", worldIDRegistryAddress);

        // CredentialSchemaIssuerRegistry
        string memory csir = "credentialSchemaIssuerRegistry";
        vm.serializeAddress(csir, "implementation", credentialSchemaIssuerRegistryImplAddress);
        string memory csirJson = vm.serializeAddress(csir, "proxy", credentialSchemaIssuerRegistryAddress);

        // RpRegistry
        string memory rp = "rpRegistry";
        vm.serializeAddress(rp, "implementation", rpRegistryImplAddress);
        string memory rpJson = vm.serializeAddress(rp, "proxy", rpRegistryAddress);

        // WorldIDVerifier
        string memory wiv = "worldIDVerifier";
        vm.serializeAddress(wiv, "implementation", worldIDVerifierImplAddress);
        string memory wivJson = vm.serializeAddress(wiv, "proxy", worldIDVerifierAddress);

        // Root object
        string memory root = "root";
        vm.serializeUint(root, "chainId", block.chainid);
        vm.serializeAddress(root, "deployer", msg.sender);
        vm.serializeUint(root, "timestamp", block.timestamp);
        vm.serializeAddress(root, "verifier", verifierAddress);
        vm.serializeString(root, "worldIDRegistry", worldIdRegJson);
        vm.serializeString(root, "credentialSchemaIssuerRegistry", csirJson);
        vm.serializeString(root, "rpRegistry", rpJson);
        string memory json = vm.serializeString(root, "worldIDVerifier", wivJson);

        string memory path = string.concat("deployments/", env, ".json");
        vm.writeJson(json, path);
        console2.log("Deployment written to", path);
    }

    /// @notice Deploys a contract using CREATE2.
    /// @param salt The salt to use for the CREATE2 deployment.
    /// @param initCode The init code of the contract to deploy.
    function deploy(bytes32 salt, bytes memory initCode) public returns (address addr) {
        assembly {
            addr := create2(0, add(initCode, 0x20), mload(initCode), salt)
            if iszero(extcodesize(addr)) {
                mstore(0x00, 0x2f8f8019)
                revert(0x1c, 0x04)
            }
        }
    }
}
