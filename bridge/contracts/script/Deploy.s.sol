// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {Vm} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {WorldIDSource, WorldIDSatellite} from "../src/Core.sol";
import {IStateBridge} from "../src/core/interfaces/IStateBridge.sol";
import {PermissionedGatewayAdapter} from "../src/core/lib/adapters/PermissionedGatewayAdapter.sol";
import {EthereumMPTGatewayAdapter} from "../src/core/lib/adapters/EthereumMPTGatewayAdapter.sol";
import {LightClientGatewayAdapter} from "../src/core/lib/adapters/LightClientGatewayAdapter.sol";
import {Verifier} from "@world-id/Verifier.sol";

/// @title BridgeDeployer
/// @notice Helper contract for CREATE2 deploys and JSON parsing try/catch wrappers.
/// @dev Deployed as a separate contract to avoid Foundry's `address(this)` restriction in scripts.
contract BridgeDeployer {
    Vm private constant _vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// @notice Deploys a contract using CREATE2.
    function deploy(bytes32 salt, bytes memory initCode) external returns (address addr) {
        assembly {
            addr := create2(0, add(initCode, 0x20), mload(initCode), salt)
            if iszero(extcodesize(addr)) {
                mstore(0x00, 0x2f8f8019)
                revert(0x1c, 0x04)
            }
        }
    }

    /// @notice Try to parse a JSON address. Reverts if key doesn't exist.
    function parseAddress(string calldata json, string calldata key) external view returns (address) {
        return _vm.parseJsonAddress(json, key);
    }
}

/// @title DeployBridgeSDK
/// @notice Multi-chain deployment script for the World ID Bridge SDK.
///   All configuration is read from environment variables. Deployment addresses
///   are persisted to `deployments/{env}.json` for idempotent re-runs.
///
/// @dev Usage:
///   source .env && forge script script/Deploy.s.sol:DeployBridgeSDK \
///     --sig "run(string)" "staging" --multi --broadcast
contract DeployBridgeSDK is Script {
    // ─── Deployer helper (fresh instance per fork) ───
    BridgeDeployer internal _deployer;

    // ─── Cross-chain state carried between forks ───
    address internal _wcSourceProxy;
    uint256 internal _wcChainId;
    address internal _l1BridgeProxy;

    // ─── Per-network deployment results (reset per fork) ───
    address public verifierAddr;
    address public bridgeImpl;
    address public bridgeProxy;

    // Gateway tracking for post-deploy addGateway calls + serialization
    address[] internal _gwAddrs;
    string[] internal _gwTypes;

    ////////////////////////////////////////////////////////////
    //                       ENTRY POINT                      //
    ////////////////////////////////////////////////////////////

    /// @notice Deploy all bridge infrastructure across all configured networks.
    /// @param env Used only for the deployment output file path (`deployments/{env}.json`).
    function run(string calldata env) public {
        string memory deployments = _loadDeployments(env);
        uint256 pk = vm.envUint("PRIVATE_KEY");

        // ── Phase 1: World Chain (source) ──
        _wcChainId = vm.envUint("WC_CHAIN_ID");

        vm.createSelectFork(vm.envString("WC_RPC_URL"));

        vm.startBroadcast(pk);
        _deployer = new BridgeDeployer();
        _deployWorldChain(deployments);
        vm.stopBroadcast();

        _writeWorldChainDeployment(env);
        deployments = _loadDeployments(env);

        // ── Phase 2: Destination networks (in order) ──
        string[] memory networks = vm.envString("NETWORKS", ",");

        for (uint256 i; i < networks.length; i++) {
            _resetNetworkState();

            string memory name = networks[i];
            string memory prefix = _upperCase(name);
            string memory rpc = vm.envString(string.concat(prefix, "_RPC_URL"));

            console2.log("");
            console2.log("========================================");
            console2.log("Deploying network:", name);
            console2.log("========================================");

            vm.createSelectFork(rpc);

            vm.startBroadcast(pk);
            _deployer = new BridgeDeployer();
            _deployCrossDomain(deployments, name, prefix);
            vm.stopBroadcast();

            _writeNetworkDeployment(env, name);
            deployments = _loadDeployments(env);
        }

        console2.log("");
        console2.log("All networks deployed successfully.");
    }

    ////////////////////////////////////////////////////////////
    //                     WORLD CHAIN                        //
    ////////////////////////////////////////////////////////////

    function _deployWorldChain(string memory deployments) internal {
        address existingProxy = _tryLoadAddress(deployments, ".worldchain.worldIDSource.proxy");
        if (existingProxy != address(0)) {
            console2.log("WorldIDSource already deployed at", existingProxy);
            bridgeProxy = existingProxy;
            bridgeImpl = _tryLoadAddress(deployments, ".worldchain.worldIDSource.implementation");
            _wcSourceProxy = existingProxy;
            return;
        }

        address registry = vm.envAddress("WC_REGISTRY");
        address issuerRegistry = vm.envAddress("WC_ISSUER_REGISTRY");
        address oprfRegistry = vm.envAddress("WC_OPRF_REGISTRY");

        console2.log("--- Deploying WorldIDSource ---");
        console2.log("  Registry:", registry);
        console2.log("  IssuerRegistry:", issuerRegistry);
        console2.log("  OprfRegistry:", oprfRegistry);

        bytes32 implSalt = vm.envBytes32("SALT_WORLD_ID_SOURCE");
        bytes memory implInitCode =
            abi.encodePacked(type(WorldIDSource).creationCode, abi.encode(registry, issuerRegistry, oprfRegistry));
        bridgeImpl = _deployer.deploy(implSalt, implInitCode);
        console2.log("  Implementation:", bridgeImpl);

        address owner = vm.envAddress("OWNER");
        address[] memory emptyGateways = new address[](0);

        IStateBridge.InitConfig memory initCfg = IStateBridge.InitConfig({
            name: vm.envString("BRIDGE_NAME"),
            version: vm.envString("BRIDGE_VERSION"),
            owner: owner,
            authorizedGateways: emptyGateways
        });

        bytes memory initData = abi.encodeCall(WorldIDSource.initialize, (initCfg));
        bytes memory proxyInitCode = abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(bridgeImpl, initData));

        bytes32 proxySalt = keccak256(abi.encodePacked(implSalt, "proxy"));
        bridgeProxy = _deployer.deploy(proxySalt, proxyInitCode);
        console2.log("  Proxy:", bridgeProxy);

        _wcSourceProxy = bridgeProxy;
    }

    ////////////////////////////////////////////////////////////
    //                   CROSS-DOMAIN (L1 + L2s)              //
    ////////////////////////////////////////////////////////////

    function _deployCrossDomain(string memory deployments, string memory network, string memory prefix) internal {
        verifierAddr = _deployVerifier(deployments, network, prefix);

        _deployCrossDomainWorldID(deployments, network, prefix);

        _deployGateways(deployments, network, prefix);

        for (uint256 i; i < _gwAddrs.length; i++) {
            console2.log("  Authorizing gateway:", _gwAddrs[i]);
            WorldIDSatellite(bridgeProxy).addGateway(_gwAddrs[i]);
        }
    }

    function _deployVerifier(string memory deployments, string memory network, string memory prefix)
        internal
        returns (address)
    {
        // Check if env specifies an existing verifier address
        address configVerifier = vm.envOr(string.concat(prefix, "_VERIFIER"), address(0));
        if (configVerifier != address(0)) {
            console2.log("  Using existing verifier:", configVerifier);
            return configVerifier;
        }

        // Check deployments for previously deployed verifier
        address existingVerifier = _tryLoadAddress(deployments, string.concat(".", network, ".verifier"));
        if (existingVerifier != address(0)) {
            console2.log("  Reusing deployed verifier:", existingVerifier);
            return existingVerifier;
        }

        // Deploy fresh Verifier
        console2.log("--- Deploying Verifier ---");
        bytes32 salt = keccak256(abi.encodePacked(vm.envBytes32("SALT_VERIFIER"), network));
        bytes memory initCode = abi.encodePacked(type(Verifier).creationCode);
        address v = _deployer.deploy(salt, initCode);
        console2.log("  Verifier:", v);
        return v;
    }

    function _deployCrossDomainWorldID(string memory deployments, string memory network, string memory) internal {
        string memory np = string.concat(".", network);

        address existingProxy = _tryLoadAddress(deployments, string.concat(np, ".worldIDSatellite.proxy"));
        if (existingProxy != address(0)) {
            console2.log("  WorldIDSatellite already deployed at", existingProxy);
            bridgeProxy = existingProxy;
            bridgeImpl = _tryLoadAddress(deployments, string.concat(np, ".worldIDSatellite.implementation"));
            return;
        }

        console2.log("--- Deploying WorldIDSatellite ---");

        uint256 rootValidityWindow = vm.envUint("ROOT_VALIDITY_WINDOW");
        uint256 treeDepth = vm.envUint("TREE_DEPTH");
        uint64 minExpThreshold = uint64(vm.envUint("MIN_EXPIRATION_THRESHOLD"));

        bytes32 baseSalt = vm.envBytes32("SALT_CROSS_DOMAIN_WORLD_ID");
        bytes32 implSalt = keccak256(abi.encodePacked(baseSalt, network));
        bytes memory implInitCode = abi.encodePacked(
            type(WorldIDSatellite).creationCode,
            abi.encode(verifierAddr, rootValidityWindow, treeDepth, minExpThreshold)
        );
        bridgeImpl = _deployer.deploy(implSalt, implInitCode);
        console2.log("  Implementation:", bridgeImpl);

        address owner = vm.envAddress("OWNER");
        address[] memory emptyGateways = new address[](0);

        IStateBridge.InitConfig memory initCfg = IStateBridge.InitConfig({
            name: vm.envString("BRIDGE_NAME"),
            version: vm.envString("BRIDGE_VERSION"),
            owner: owner,
            authorizedGateways: emptyGateways
        });

        bytes memory initData = abi.encodeCall(WorldIDSatellite.initialize, (initCfg));
        bytes memory proxyInitCode = abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(bridgeImpl, initData));

        bytes32 proxySalt = keccak256(abi.encodePacked(implSalt, "proxy"));
        bridgeProxy = _deployer.deploy(proxySalt, proxyInitCode);
        console2.log("  Proxy:", bridgeProxy);

        // Track L1 bridge address for ZK gateways on downstream networks
        string memory prefix = _upperCase(network);
        if (vm.envOr(string.concat(prefix, "_DEPLOY_L1_GATEWAY"), false)) {
            _l1BridgeProxy = bridgeProxy;
        }
    }

    ////////////////////////////////////////////////////////////
    //                       GATEWAYS                         //
    ////////////////////////////////////////////////////////////

    function _deployGateways(string memory deployments, string memory network, string memory prefix) internal {
        address owner = vm.envAddress("OWNER");

        require(_wcSourceProxy != address(0), "WorldIDSource not deployed - run worldchain first");

        if (vm.envOr(string.concat(prefix, "_DEPLOY_OWNED_GATEWAY"), false)) {
            _deployPermissionedGateway(deployments, network, owner);
        }

        if (vm.envOr(string.concat(prefix, "_DEPLOY_L1_GATEWAY"), false)) {
            _deployEthereumMPTGateway(deployments, network, prefix, owner);
        }

        if (vm.envOr(string.concat(prefix, "_DEPLOY_ZK_GATEWAY"), false)) {
            _deployLightClientGateway(deployments, network, prefix, owner);
        }
    }

    function _deployPermissionedGateway(string memory deployments, string memory network, address owner) internal {
        string memory deployKey = string.concat(".", network, ".gateways.ownedGateway");

        address existing = _tryLoadAddress(deployments, deployKey);
        if (existing != address(0)) {
            console2.log("  PermissionedGateway already deployed at", existing);
            return;
        }

        console2.log("--- Deploying PermissionedGateway ---");

        bytes32 salt = keccak256(abi.encodePacked(vm.envBytes32("SALT_OWNED_GATEWAY"), network));
        bytes memory initCode = abi.encodePacked(
            type(PermissionedGatewayAdapter).creationCode, abi.encode(owner, bridgeProxy, _wcSourceProxy, _wcChainId)
        );

        address addr = _deployer.deploy(salt, initCode);
        console2.log("  PermissionedGateway:", addr);

        _gwAddrs.push(addr);
        _gwTypes.push("permissionedGateway");
    }

    function _deployEthereumMPTGateway(
        string memory deployments,
        string memory network,
        string memory prefix,
        address owner
    ) internal {
        string memory deployKey = string.concat(".", network, ".gateways.l1Gateway");

        address existing = _tryLoadAddress(deployments, deployKey);
        if (existing != address(0)) {
            console2.log("  EthereumMPTGateway already deployed at", existing);
            return;
        }

        console2.log("--- Deploying EthereumMPTGateway ---");

        address dgf = vm.envAddress(string.concat(prefix, "_L1_DISPUTE_GAME_FACTORY"));
        bool reqFinalized = vm.envOr(string.concat(prefix, "_L1_REQUIRE_FINALIZED"), false);

        bytes32 salt = keccak256(abi.encodePacked(vm.envBytes32("SALT_L1_GATEWAY"), network));
        bytes memory initCode = abi.encodePacked(
            type(EthereumMPTGatewayAdapter).creationCode,
            abi.encode(owner, dgf, reqFinalized, bridgeProxy, _wcSourceProxy, _wcChainId)
        );

        address addr = _deployer.deploy(salt, initCode);
        console2.log("  EthereumMPTGateway:", addr);

        _gwAddrs.push(addr);
        _gwTypes.push("ethereumMPTGateway");
    }

    function _deployLightClientGateway(
        string memory deployments,
        string memory network,
        string memory prefix,
        address owner
    ) internal {
        string memory deployKey = string.concat(".", network, ".gateways.zkGateway");

        address existing = _tryLoadAddress(deployments, deployKey);
        if (existing != address(0)) {
            console2.log("  LightClientGateway already deployed at", existing);
            return;
        }

        require(_l1BridgeProxy != address(0), "L1 bridge not deployed - deploy L1 network first");

        console2.log("--- Deploying LightClientGateway ---");

        address sp1Verifier = vm.envAddress(string.concat(prefix, "_ZK_SP1_VERIFIER"));
        bytes32 programVKey = vm.envBytes32(string.concat(prefix, "_ZK_PROGRAM_VKEY"));
        uint256 initialHead = vm.envUint(string.concat(prefix, "_ZK_INITIAL_HEAD"));
        bytes32 initialHeader = vm.envBytes32(string.concat(prefix, "_ZK_INITIAL_HEADER"));
        bytes32 initialSCHash = vm.envBytes32(string.concat(prefix, "_ZK_INITIAL_SYNC_COMMITTEE_HASH"));

        uint256 l1ChainId = _findL1ChainId();

        bytes32 salt = keccak256(abi.encodePacked(vm.envBytes32("SALT_ZK_GATEWAY"), network));
        bytes memory initCode = abi.encodePacked(
            type(LightClientGatewayAdapter).creationCode,
            abi.encode(
                owner,
                sp1Verifier,
                programVKey,
                initialHead,
                initialHeader,
                initialSCHash,
                bridgeProxy,
                _l1BridgeProxy,
                l1ChainId
            )
        );

        address addr = _deployer.deploy(salt, initCode);
        console2.log("  LightClientGateway:", addr);

        _gwAddrs.push(addr);
        _gwTypes.push("lightClientGateway");
    }

    ////////////////////////////////////////////////////////////
    //                     PERSISTENCE                        //
    ////////////////////////////////////////////////////////////

    function _writeWorldChainDeployment(string memory env) internal {
        string memory net = "wc";

        vm.serializeUint(net, "chainId", _wcChainId);
        vm.serializeAddress(net, "deployer", msg.sender);
        vm.serializeUint(net, "timestamp", block.timestamp);

        string memory src = "worldIDSource";
        vm.serializeAddress(src, "implementation", bridgeImpl);
        string memory srcJson = vm.serializeAddress(src, "proxy", bridgeProxy);

        string memory networkJson = vm.serializeString(net, "worldIDSource", srcJson);

        string memory deployPath = string.concat("deployments/", env, ".json");
        _ensureDeploymentFileExists(deployPath);
        vm.writeJson(networkJson, deployPath, ".worldchain");
        console2.log("  Written to", deployPath, "[worldchain]");
    }

    function _writeNetworkDeployment(string memory env, string memory network) internal {
        string memory net = network;

        vm.serializeUint(net, "chainId", block.chainid);
        vm.serializeAddress(net, "deployer", msg.sender);
        vm.serializeUint(net, "timestamp", block.timestamp);
        vm.serializeAddress(net, "verifier", verifierAddr);

        string memory cdwid = string.concat(network, "_cdwid");
        vm.serializeAddress(cdwid, "implementation", bridgeImpl);
        string memory cdwidJson = vm.serializeAddress(cdwid, "proxy", bridgeProxy);
        vm.serializeString(net, "worldIDSatellite", cdwidJson);

        string memory networkJson;
        if (_gwAddrs.length > 0) {
            string memory gw = string.concat(network, "_gw");
            string memory gwJson;
            for (uint256 i; i < _gwAddrs.length; i++) {
                gwJson = vm.serializeAddress(gw, _gwTypes[i], _gwAddrs[i]);
            }
            networkJson = vm.serializeString(net, "gateways", gwJson);
        } else {
            networkJson = vm.serializeString(net, "worldIDSatellite", cdwidJson);
        }

        string memory deployPath = string.concat("deployments/", env, ".json");
        vm.writeJson(networkJson, deployPath, string.concat(".", network));
        console2.log("  Written to", deployPath, string.concat("[", network, "]"));
    }

    ////////////////////////////////////////////////////////////
    //                       HELPERS                          //
    ////////////////////////////////////////////////////////////

    function _loadDeployments(string memory env) internal returns (string memory) {
        string memory path = string.concat("deployments/", env, ".json");
        try vm.readFile(path) returns (string memory content) {
            if (bytes(content).length > 0) return content;
        } catch {}
        return "{}";
    }

    function _ensureDeploymentFileExists(string memory path) internal {
        try vm.readFile(path) returns (string memory content) {
            if (bytes(content).length > 0) return;
        } catch {}
        vm.writeJson("{}", path);
    }

    /// @dev Tries to load an address from a JSON string at the given path.
    ///   Returns address(0) if the key doesn't exist or the JSON is empty.
    function _tryLoadAddress(string memory json, string memory key) internal returns (address) {
        if (bytes(json).length <= 2) return address(0);
        try _deployer.parseAddress(json, key) returns (address a) {
            return a;
        } catch {
            return address(0);
        }
    }

    /// @dev Finds the chain ID of the L1 network (the network with _DEPLOY_L1_GATEWAY=true).
    function _findL1ChainId() internal view returns (uint256) {
        string[] memory networks = vm.envString("NETWORKS", ",");
        for (uint256 i; i < networks.length; i++) {
            string memory prefix = _upperCase(networks[i]);
            if (vm.envOr(string.concat(prefix, "_DEPLOY_L1_GATEWAY"), false)) {
                return vm.envUint(string.concat(prefix, "_CHAIN_ID"));
            }
        }
        revert("No L1 network found (no network has _DEPLOY_L1_GATEWAY=true)");
    }

    /// @dev Resets per-network state between fork deployments.
    function _resetNetworkState() internal {
        verifierAddr = address(0);
        bridgeImpl = address(0);
        bridgeProxy = address(0);
        delete _gwAddrs;
        delete _gwTypes;
    }

    /// @dev Returns an uppercase copy of an ASCII string (does not mutate the input).
    function _upperCase(string memory s) internal pure returns (string memory) {
        bytes memory src = bytes(s);
        bytes memory out = new bytes(src.length);
        for (uint256 i; i < src.length; i++) {
            out[i] = (src[i] >= 0x61 && src[i] <= 0x7a) ? bytes1(uint8(src[i]) - 32) : src[i];
        }
        return string(out);
    }
}
