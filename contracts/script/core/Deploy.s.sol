// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import {WorldIDRegistry} from "../../src/core/WorldIDRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {CredentialSchemaIssuerRegistry} from "../../src/core/CredentialSchemaIssuerRegistry.sol";
import {RpRegistry} from "../../src/core/RpRegistry.sol";
import {WorldIDVerifier} from "../../src/core/WorldIDVerifier.sol";
import {Verifier} from "../../src/core/Verifier.sol";

/// @title WorldIDDeployer
/// @notice Helper contract that deploys proxies via CREATE2 and transfers ownership to the caller.
contract WorldIDDeployer {
    /// @notice Deploys a contract using CREATE2 and initiates ownership transfer to msg.sender.
    /// @param salt The salt to use for the CREATE2 deployment.
    /// @param initCode The init code of the contract to deploy.
    /// @return addr The address of the deployed contract.
    function deploy(bytes32 salt, bytes memory initCode) external returns (address addr) {
        assembly {
            addr := create2(0, add(initCode, 0x20), mload(initCode), salt)
            if iszero(extcodesize(addr)) {
                mstore(0x00, 0x2f8f8019)
                revert(0x1c, 0x04)
            }
        }
        // The proxy's owner is this contract (msg.sender in initialize = address(this)).
        // Initiate 2-step transfer to the caller (the EOA).
        Ownable2StepUpgradeable(addr).transferOwnership(msg.sender);
    }
}

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

    WorldIDDeployer internal _deployer = WorldIDDeployer(0x7f170d4E2EB55F170fd67d247e03B2973Bf34085);

    /// @notice Deploy all contracts for the given environment.
    /// @dev Usage: forge script script/Deploy.s.sol --sig "run(string)" "staging" --broadcast --private-key $PK
    /// @param env The environment name matching a file in script/config/ (e.g. "local", "staging", "production").
    function run(string calldata env) public {
        string memory config = _loadConfig(env);

        vm.startBroadcast();

        if (address(_deployer).code.length == 0) {
            _deployer = new WorldIDDeployer{salt: bytes32(0)}();
            console2.log("Deployed WorldIDDeployer at:", address(_deployer));
        } else {
            console2.log("WorldIDDeployer found at:", address(_deployer));
        }

        _run(config);

        // Accept ownership on all proxies (completing the 2-step transfer)
        _acceptOwnership();

        vm.stopBroadcast();

        _writeDeployment(env);
    }

    function _run(string memory config) internal virtual {
        deployWorldIdRegistry(config);
        deployCredentialSchemaIssuerRegistry(config);
        deployRpRegistry(config);
        deployWorldIdVerifier(config);
    }

    /// @notice Accepts ownership on all deployed proxies, completing the 2-step transfer
    ///         from the WorldIDDeployer to the broadcaster (PRIVATE_KEY address).
    function _acceptOwnership() internal virtual {
        Ownable2StepUpgradeable(worldIDRegistryAddress).acceptOwnership();
        Ownable2StepUpgradeable(credentialSchemaIssuerRegistryAddress).acceptOwnership();
        Ownable2StepUpgradeable(rpRegistryAddress).acceptOwnership();
        Ownable2StepUpgradeable(worldIDVerifierAddress).acceptOwnership();
    }

    /// @notice Returns a salt, preferring the environment variable if set over the JSON config value.
    /// @param config The raw JSON config string.
    /// @param key    The key under `.salts` in the config (e.g. "worldIDRegistry").
    /// @param envVar The env var name to check first (e.g. "SALT_WORLD_ID_REGISTRY").
    function _getSalt(string memory config, string memory key, string memory envVar) internal view returns (bytes32) {
        return vm.envOr(envVar, vm.parseJsonBytes32(config, string.concat(".salts.", key)));
    }

    function deployWorldIdRegistry(string memory config) public {
        uint256 treeDepth = vm.parseJsonUint(config, ".worldIDRegistry.treeDepth");
        address feeRecipient = vm.parseJsonAddress(config, ".worldIDRegistry.feeRecipient");
        address feeToken = vm.parseJsonAddress(config, ".worldIDRegistry.feeToken");
        uint256 registrationFee = vm.parseJsonUint(config, ".worldIDRegistry.registrationFee");
        bytes32 salt = _getSalt(config, "worldIDRegistry", "SALT_WORLD_ID_REGISTRY");

        console2.log("--- WorldIDRegistry ---");
        console2.log("  tree depth:       ", treeDepth);
        console2.log("  fee recipient:    ", feeRecipient);
        console2.log("  fee token:        ", feeToken);
        console2.log("  registration fee: ", registrationFee);
        console2.log("  proxy salt:       ");
        console2.logBytes32(salt);

        WorldIDRegistry implementation = new WorldIDRegistry{salt: bytes32(uint256(3))}();
        worldIDRegistryImplAddress = address(implementation);
        console2.log("  implementation:   ", worldIDRegistryImplAddress);

        bytes memory initData = abi.encodeWithSelector(
            WorldIDRegistry.initialize.selector, treeDepth, feeRecipient, feeToken, registrationFee
        );
        bytes memory initCode = abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(implementation, initData));
        console2.log("  proxy init code hash:");
        console2.logBytes32(keccak256(initCode));

        worldIDRegistryAddress = deploy(salt, initCode);
        console2.log("  proxy:            ", worldIDRegistryAddress);
    }

    function deployCredentialSchemaIssuerRegistry(string memory config) public {
        address feeRecipient = vm.parseJsonAddress(config, ".credentialSchemaIssuerRegistry.feeRecipient");
        address feeToken = vm.parseJsonAddress(config, ".credentialSchemaIssuerRegistry.feeToken");
        uint256 registrationFee = vm.parseJsonUint(config, ".credentialSchemaIssuerRegistry.registrationFee");
        address oprfKeyRegistryAddress = vm.parseJsonAddress(config, ".externalDependencies.oprfKeyRegistry");
        bytes32 salt = _getSalt(config, "credentialSchemaIssuerRegistry", "SALT_CREDENTIAL_SCHEMA_ISSUER_REGISTRY");

        console2.log("--- CredentialSchemaIssuerRegistry ---");
        console2.log("  fee recipient:    ", feeRecipient);
        console2.log("  fee token:        ", feeToken);
        console2.log("  registration fee: ", registrationFee);
        console2.log("  oprf key registry:", oprfKeyRegistryAddress);
        console2.log("  proxy salt:       ");
        console2.logBytes32(salt);

        CredentialSchemaIssuerRegistry implementation = new CredentialSchemaIssuerRegistry{salt: bytes32(uint256(1))}();
        credentialSchemaIssuerRegistryImplAddress = address(implementation);
        console2.log("  implementation:   ", credentialSchemaIssuerRegistryImplAddress);

        bytes memory initData = abi.encodeWithSelector(
            CredentialSchemaIssuerRegistry.initialize.selector,
            feeRecipient,
            feeToken,
            registrationFee,
            oprfKeyRegistryAddress
        );
        bytes memory initCode = abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(implementation, initData));
        console2.log("  proxy init code hash:");
        console2.logBytes32(keccak256(initCode));

        credentialSchemaIssuerRegistryAddress = deploy(salt, initCode);
        console2.log("  proxy:            ", credentialSchemaIssuerRegistryAddress);
    }

    function deployRpRegistry(string memory config) public {
        address feeRecipient = vm.parseJsonAddress(config, ".rpRegistry.feeRecipient");
        address feeToken = vm.parseJsonAddress(config, ".rpRegistry.feeToken");
        uint256 registrationFee = vm.parseJsonUint(config, ".rpRegistry.registrationFee");
        address oprfKeyRegistryAddress = vm.parseJsonAddress(config, ".externalDependencies.oprfKeyRegistry");
        bytes32 salt = _getSalt(config, "rpRegistry", "SALT_RP_REGISTRY");

        console2.log("--- RpRegistry ---");
        console2.log("  fee recipient:    ", feeRecipient);
        console2.log("  fee token:        ", feeToken);
        console2.log("  registration fee: ", registrationFee);
        console2.log("  oprf key registry:", oprfKeyRegistryAddress);
        console2.log("  proxy salt:       ");
        console2.logBytes32(salt);

        RpRegistry implementation = new RpRegistry{salt: bytes32(uint256(1))}();
        rpRegistryImplAddress = address(implementation);
        console2.log("  implementation:   ", rpRegistryImplAddress);

        bytes memory initData = abi.encodeWithSelector(
            RpRegistry.initialize.selector, feeRecipient, feeToken, registrationFee, oprfKeyRegistryAddress
        );
        bytes memory initCode = abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(implementation, initData));
        console2.log("  proxy init code hash:");
        console2.logBytes32(keccak256(initCode));

        rpRegistryAddress = deploy(salt, initCode);
        console2.log("  proxy:            ", rpRegistryAddress);
    }

    function deployWorldIdVerifier(string memory config) public {
        address oprfKeyRegistryAddress = vm.parseJsonAddress(config, ".externalDependencies.oprfKeyRegistry");
        uint64 minExpirationThreshold = uint64(vm.parseJsonUint(config, ".worldIDVerifier.minExpirationThreshold"));
        bytes32 verifierSalt = _getSalt(config, "verifier", "SALT_VERIFIER");
        bytes32 salt = _getSalt(config, "worldIDVerifier", "SALT_WORLD_ID_VERIFIER");

        console2.log("--- Verifier ---");
        console2.log("  salt:             ");
        console2.logBytes32(verifierSalt);
        verifierAddress = address(new Verifier{salt: verifierSalt}());
        console2.log("  address:          ", verifierAddress);

        console2.log("--- WorldIDVerifier ---");
        console2.log("  credential schema issuer registry:", credentialSchemaIssuerRegistryAddress);
        console2.log("  world id registry:", worldIDRegistryAddress);
        console2.log("  oprf key registry:", oprfKeyRegistryAddress);
        console2.log("  verifier:         ", verifierAddress);
        console2.log("  min expiration threshold:", minExpirationThreshold);
        console2.log("  proxy salt:       ");
        console2.logBytes32(salt);

        WorldIDVerifier implementation = new WorldIDVerifier{salt: bytes32(uint256(1))}();
        worldIDVerifierImplAddress = address(implementation);
        console2.log("  implementation:   ", worldIDVerifierImplAddress);

        bytes memory initData = abi.encodeWithSelector(
            WorldIDVerifier.initialize.selector,
            credentialSchemaIssuerRegistryAddress,
            worldIDRegistryAddress,
            oprfKeyRegistryAddress,
            verifierAddress,
            minExpirationThreshold
        );
        bytes memory initCode = abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(implementation, initData));
        console2.log("  proxy init code hash:");
        console2.logBytes32(keccak256(initCode));

        worldIDVerifierAddress = deploy(salt, initCode);
        console2.log("  proxy:            ", worldIDVerifierAddress);
    }

    /// @notice Loads a JSON config file for the given environment.
    /// @param env The environment name (e.g. "local", "staging", "production").
    /// @return json The raw JSON string contents of the config file.
    function _loadConfig(string memory env) internal view returns (string memory json) {
        string memory path = string.concat("script/core/config/", env, ".json");
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
        vm.serializeString(root, "commitSha", vm.envOr("GIT_COMMIT", string("")));
        vm.serializeAddress(root, "verifier", verifierAddress);
        vm.serializeString(root, "worldIDRegistry", worldIdRegJson);
        vm.serializeString(root, "credentialSchemaIssuerRegistry", csirJson);
        vm.serializeString(root, "rpRegistry", rpJson);
        string memory json = vm.serializeString(root, "worldIDVerifier", wivJson);

        string memory path = string.concat("deployments/core/", env, ".json");
        vm.writeJson(json, path);
        console2.log("Deployment written to", path);
    }

    /// @notice Deploys a contract using CREATE2 via the WorldIDDeployer.
    /// @dev The deployer creates the proxy and initiates ownership transfer to the broadcaster.
    ///      Call `_acceptOwnership()` after all deploys to complete the transfer.
    /// @param salt The salt to use for the CREATE2 deployment.
    /// @param initCode The init code of the contract to deploy.
    function deploy(bytes32 salt, bytes memory initCode) public returns (address addr) {
        addr = _deployer.deploy(salt, initCode);
    }

    /// @notice Updates the WorldIDRegistry address on a deployed WorldIDVerifier proxy.
    /// @dev Usage: forge script script/core/Deploy.s.sol:Deploy --sig "updateWorldIDRegistry(address,address)" \
    ///     <VERIFIER_PROXY> <NEW_REGISTRY> --broadcast --private-key $PK --chain 480
    function updateWorldIDRegistry(address verifierProxy, address newWorldIDRegistry) public {
        console2.log("WorldIDVerifier proxy:", verifierProxy);
        console2.log("Current WorldIDRegistry:", WorldIDVerifier(verifierProxy).getWorldIDRegistry());
        console2.log("New WorldIDRegistry:", newWorldIDRegistry);

        vm.startBroadcast();
        WorldIDVerifier(verifierProxy).updateWorldIDRegistry(newWorldIDRegistry);
        vm.stopBroadcast();

        console2.log("Updated WorldIDRegistry to:", WorldIDVerifier(verifierProxy).getWorldIDRegistry());
    }
}
