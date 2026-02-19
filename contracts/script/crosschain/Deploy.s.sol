// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {Vm} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {WorldIDSource} from "../../src/crosschain/WorldIDSource.sol";
import {WorldIDSatellite} from "../../src/crosschain/WorldIDSatellite.sol";
import {IStateBridge} from "../../src/crosschain/interfaces/IStateBridge.sol";
import {PermissionedGatewayAdapter} from "../../src/crosschain/adapters/PermissionedGatewayAdapter.sol";
import {EthereumMPTGatewayAdapter} from "../../src/crosschain/adapters/EthereumMPTGatewayAdapter.sol";
import {LightClientGatewayAdapter} from "../../src/crosschain/adapters/LightClientGatewayAdapter.sol";
import {Verifier} from "../../src/core/Verifier.sol";

/// @title BridgeDeployer
/// @notice Helper contract for CREATE2 deploys and JSON parsing try/catch wrappers.
/// @dev Deployed as a separate contract so try/catch works on external calls.
contract BridgeDeployer {
    Vm private constant _vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function deploy(bytes32 salt, bytes memory initCode) external returns (address addr) {
        assembly {
            addr := create2(0, add(initCode, 0x20), mload(initCode), salt)
            if iszero(extcodesize(addr)) {
                mstore(0x00, 0x2f8f8019)
                revert(0x1c, 0x04)
            }
        }
    }

    function parseAddress(string calldata json, string calldata key) external pure returns (address) {
        return _vm.parseJsonAddress(json, key);
    }

    function parseBool(string calldata json, string calldata key) external pure returns (bool) {
        return _vm.parseJsonBool(json, key);
    }

    function parseKeys(string calldata json, string calldata key) external pure returns (string[] memory) {
        return _vm.parseJsonKeys(json, key);
    }
}

/// @title Deploy
/// @notice Multi-chain deployment script for the World ID Bridge SDK.
///
///   All configuration is read from `script/crosschain/config/{env}.json`. Deployment
///   addresses are persisted to `deployments/{env}.json` for idempotent re-runs.
///   Git commit SHA and tag are recorded in every deployment artifact.
///
/// @dev Usage:
///   forge script script/Deploy.s.sol:Deploy \
///     --sig "run(string)" "staging" --multi --broadcast
///
///   Required env vars: PRIVATE_KEY, ALCHEMY_API_KEY (or add "rpc" to config).
///   Optional: DEPLOY_CHAINS=ethereum,base (filter which networks to deploy).
contract Deploy is Script {
    // ─── Deployer helper (re-deployed per fork) ───
    BridgeDeployer internal _deployer;

    // ─── Config (loaded once from JSON) ───
    string internal _config;

    // ─── Git metadata ───
    string internal _commitSha;
    string internal _gitTag;

    // ─── Cross-chain state (persists across forks) ───
    address internal _wcSourceProxy;
    uint256 internal _wcChainId;
    address internal _l1BridgeProxy;
    uint256 internal _l1ChainId;
    address internal _broadcaster;
    string[] internal _deployFilter;

    // ─── Per-network deployment results (reset per fork) ───
    address public verifierAddr;
    address public bridgeImpl;
    address public bridgeProxy;
    address[] internal _gwAddrs;
    string[] internal _gwTypes;

    ////////////////////////////////////////////////////////////
    //                       ENTRY POINT                      //
    ////////////////////////////////////////////////////////////

    /// @notice Deploy all bridge infrastructure across configured networks.
    /// @param env Environment name — maps to `script/crosschain/config/{env}.json`.
    function run(string calldata env) public {
        _config = vm.readFile(string.concat("script/crosschain/config/", env, ".json"));
        _loadGitInfo();
        _deployFilter = vm.envOr("DEPLOY_CHAINS", ",", new string[](0));

        string memory deployments = _loadDeployments(env);
        uint256 pk = vm.envUint("PRIVATE_KEY");
        _broadcaster = vm.addr(pk);

        // ── Phase 1: World Chain (source) ──
        _wcChainId = vm.parseJsonUint(_config, ".worldchain.chainId");

        vm.createSelectFork(_resolveRpc("worldchain"));

        vm.startBroadcast(pk);
        _deployer = new BridgeDeployer();
        _deployWorldChain(deployments);
        vm.stopBroadcast();

        _writeWorldChainDeployment(env);
        deployments = _loadDeployments(env);

        // ── Phase 2: Destination networks ──
        string[] memory networks = vm.parseJsonStringArray(_config, ".networks");

        for (uint256 i; i < networks.length; i++) {
            string memory name = networks[i];
            if (!_shouldDeploy(name)) continue;

            _resetNetworkState();

            console2.log("");
            console2.log("========================================");
            console2.log("Deploying network:", name);
            console2.log("========================================");

            vm.createSelectFork(_resolveRpc(name));

            vm.startBroadcast(pk);
            _deployer = new BridgeDeployer();
            _deployCrossDomain(deployments, name);
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

        address registry = vm.parseJsonAddress(_config, ".worldchain.registry");
        address issuerRegistry = vm.parseJsonAddress(_config, ".worldchain.issuerRegistry");
        address oprfRegistry = vm.parseJsonAddress(_config, ".worldchain.oprfRegistry");

        console2.log("--- Deploying WorldIDSource ---");
        console2.log("  Registry:", registry);
        console2.log("  IssuerRegistry:", issuerRegistry);
        console2.log("  OprfRegistry:", oprfRegistry);

        bytes32 implSalt = vm.parseJsonBytes32(_config, ".salts.worldIDSource");
        bytes memory implInitCode =
            abi.encodePacked(type(WorldIDSource).creationCode, abi.encode(registry, issuerRegistry, oprfRegistry));
        bridgeImpl = _deployer.deploy(implSalt, implInitCode);
        console2.log("  Implementation:", bridgeImpl);

        address owner = vm.parseJsonAddress(_config, ".owner");
        address[] memory emptyGateways = new address[](0);

        IStateBridge.InitConfig memory initCfg = IStateBridge.InitConfig({
            name: vm.parseJsonString(_config, ".bridgeName"),
            version: vm.parseJsonString(_config, ".bridgeVersion"),
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

    function _deployCrossDomain(string memory deployments, string memory network) internal {
        verifierAddr = _deployVerifier(deployments, network);
        _deployCrossDomainWorldID(deployments, network);
        _deployGateways(deployments, network);

        for (uint256 i; i < _gwAddrs.length; i++) {
            console2.log("  Authorizing gateway:", _gwAddrs[i]);
            WorldIDSatellite(bridgeProxy).addGateway(_gwAddrs[i]);
        }

        address owner = vm.parseJsonAddress(_config, ".owner");
        if (owner != _broadcaster) {
            WorldIDSatellite(bridgeProxy).transferOwnership(owner);
            console2.log("  Ownership transferred to:", owner);
        }
    }

    function _deployVerifier(string memory deployments, string memory network) internal returns (address) {
        address configVerifier = _tryLoadAddress(_config, string.concat(".", network, ".verifier"));
        if (configVerifier != address(0)) {
            console2.log("  Using existing verifier:", configVerifier);
            return configVerifier;
        }

        address existingVerifier = _tryLoadAddress(deployments, string.concat(".", network, ".verifier"));
        if (existingVerifier != address(0)) {
            console2.log("  Reusing deployed verifier:", existingVerifier);
            return existingVerifier;
        }

        console2.log("--- Deploying Verifier ---");
        bytes32 salt = keccak256(abi.encodePacked(vm.parseJsonBytes32(_config, ".salts.verifier"), network));
        address v = _deployer.deploy(salt, abi.encodePacked(type(Verifier).creationCode));
        console2.log("  Verifier:", v);
        return v;
    }

    function _deployCrossDomainWorldID(string memory deployments, string memory network) internal {
        string memory np = string.concat(".", network);

        address existingProxy = _tryLoadAddress(deployments, string.concat(np, ".worldIDSatellite.proxy"));
        if (existingProxy != address(0)) {
            console2.log("  WorldIDSatellite already deployed at", existingProxy);
            bridgeProxy = existingProxy;
            bridgeImpl = _tryLoadAddress(deployments, string.concat(np, ".worldIDSatellite.implementation"));
            if (_hasKey(_config, string.concat(np, ".l1Gateway"))) {
                _l1BridgeProxy = existingProxy;
                _l1ChainId = block.chainid;
            }
            return;
        }

        console2.log("--- Deploying WorldIDSatellite ---");

        bytes32 baseSalt;
        {
            uint256 rootValidityWindow = vm.parseJsonUint(_config, ".rootValidityWindow");
            uint256 treeDepth = vm.parseJsonUint(_config, ".treeDepth");
            uint64 minExpThreshold = uint64(vm.parseJsonUint(_config, ".minExpirationThreshold"));

            baseSalt = vm.parseJsonBytes32(_config, ".salts.worldIDSatellite");
            bytes32 implSalt = keccak256(abi.encodePacked(baseSalt, network));
            bytes memory implInitCode = abi.encodePacked(
                type(WorldIDSatellite).creationCode,
                abi.encode(verifierAddr, rootValidityWindow, treeDepth, minExpThreshold)
            );
            bridgeImpl = _deployer.deploy(implSalt, implInitCode);
            console2.log("  Implementation:", bridgeImpl);
        }

        {
            address[] memory emptyGateways = new address[](0);
            IStateBridge.InitConfig memory initCfg = IStateBridge.InitConfig({
                name: vm.parseJsonString(_config, ".bridgeName"),
                version: vm.parseJsonString(_config, ".bridgeVersion"),
                owner: _broadcaster,
                authorizedGateways: emptyGateways
            });

            bytes memory initData = abi.encodeCall(WorldIDSatellite.initialize, (initCfg));
            bytes memory proxyInitCode =
                abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(bridgeImpl, initData));

            bytes32 implSalt = keccak256(abi.encodePacked(baseSalt, network));
            bytes32 proxySalt = keccak256(abi.encodePacked(implSalt, "proxy"));
            bridgeProxy = _deployer.deploy(proxySalt, proxyInitCode);
            console2.log("  Proxy:", bridgeProxy);
        }

        if (_hasKey(_config, string.concat(np, ".l1Gateway"))) {
            _l1BridgeProxy = bridgeProxy;
            _l1ChainId = block.chainid;
        }
    }

    ////////////////////////////////////////////////////////////
    //                       GATEWAYS                         //
    ////////////////////////////////////////////////////////////

    function _deployGateways(string memory deployments, string memory network) internal {
        address owner = vm.parseJsonAddress(_config, ".owner");
        string memory np = string.concat(".", network);

        require(_wcSourceProxy != address(0), "WorldIDSource not deployed - run worldchain first");

        if (_hasKey(_config, string.concat(np, ".ownedGateway"))) {
            _deployPermissionedGateway(deployments, network, owner);
        }

        if (_hasKey(_config, string.concat(np, ".l1Gateway"))) {
            _deployEthereumMPTGateway(deployments, network, owner);
        }

        if (_hasKey(_config, string.concat(np, ".zkGateway"))) {
            _deployLightClientGateway(deployments, network, owner);
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

        bytes32 salt = keccak256(abi.encodePacked(vm.parseJsonBytes32(_config, ".salts.ownedGateway"), network));
        bytes memory initCode = abi.encodePacked(
            type(PermissionedGatewayAdapter).creationCode, abi.encode(owner, bridgeProxy, _wcSourceProxy, _wcChainId)
        );

        address addr = _deployer.deploy(salt, initCode);
        console2.log("  PermissionedGateway:", addr);

        _gwAddrs.push(addr);
        _gwTypes.push("permissionedGateway");
    }

    function _deployEthereumMPTGateway(string memory deployments, string memory network, address owner) internal {
        string memory deployKey = string.concat(".", network, ".gateways.l1Gateway");

        address existing = _tryLoadAddress(deployments, deployKey);
        if (existing != address(0)) {
            console2.log("  EthereumMPTGateway already deployed at", existing);
            return;
        }

        console2.log("--- Deploying EthereumMPTGateway ---");

        string memory gp = string.concat(".", network, ".l1Gateway");
        address dgf = vm.parseJsonAddress(_config, string.concat(gp, ".disputeGameFactory"));
        bool reqFinalized = _tryParseBool(string.concat(gp, ".requireFinalized"));

        bytes32 salt = keccak256(abi.encodePacked(vm.parseJsonBytes32(_config, ".salts.l1Gateway"), network));
        bytes memory initCode = abi.encodePacked(
            type(EthereumMPTGatewayAdapter).creationCode,
            abi.encode(owner, dgf, reqFinalized, bridgeProxy, _wcSourceProxy, _wcChainId)
        );

        address addr = _deployer.deploy(salt, initCode);
        console2.log("  EthereumMPTGateway:", addr);

        _gwAddrs.push(addr);
        _gwTypes.push("ethereumMPTGateway");
    }

    function _deployLightClientGateway(string memory deployments, string memory network, address owner) internal {
        string memory deployKey = string.concat(".", network, ".gateways.zkGateway");

        address existing = _tryLoadAddress(deployments, deployKey);
        if (existing != address(0)) {
            console2.log("  LightClientGateway already deployed at", existing);
            return;
        }

        require(_l1BridgeProxy != address(0), "L1 bridge not deployed - deploy L1 network first");

        string memory gp = string.concat(".", network, ".zkGateway");
        address sp1Verifier = vm.parseJsonAddress(_config, string.concat(gp, ".sp1Verifier"));
        if (sp1Verifier == address(0)) {
            console2.log("  Skipping LightClientGateway: sp1Verifier not configured");
            return;
        }

        console2.log("--- Deploying LightClientGateway ---");

        bytes32 programVKey = vm.parseJsonBytes32(_config, string.concat(gp, ".programVKey"));
        uint256 initialHead = vm.parseJsonUint(_config, string.concat(gp, ".initialHead"));
        bytes32 initialHeader = vm.parseJsonBytes32(_config, string.concat(gp, ".initialHeader"));
        bytes32 initialSCHash = vm.parseJsonBytes32(_config, string.concat(gp, ".initialSyncCommitteeHash"));

        bytes32 salt = keccak256(abi.encodePacked(vm.parseJsonBytes32(_config, ".salts.zkGateway"), network));
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
                _l1ChainId
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
        vm.serializeAddress(net, "deployer", _broadcaster);
        vm.serializeUint(net, "timestamp", block.timestamp);
        vm.serializeString(net, "commit", _commitSha);
        vm.serializeString(net, "tag", _gitTag);

        string memory src = "worldIDSource";
        vm.serializeAddress(src, "implementation", bridgeImpl);
        string memory srcJson = vm.serializeAddress(src, "proxy", bridgeProxy);

        string memory networkJson = vm.serializeString(net, "worldIDSource", srcJson);

        string memory deployPath = string.concat("deployments/crosschain/", env, ".json");
        _ensureDeploymentFileExists(deployPath);
        vm.writeJson(networkJson, deployPath, ".worldchain");
        console2.log("  Written to", deployPath, "[worldchain]");
    }

    function _writeNetworkDeployment(string memory env, string memory network) internal {
        string memory net = network;

        vm.serializeUint(net, "chainId", block.chainid);
        vm.serializeAddress(net, "deployer", _broadcaster);
        vm.serializeUint(net, "timestamp", block.timestamp);
        vm.serializeString(net, "commit", _commitSha);
        vm.serializeString(net, "tag", _gitTag);
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

        string memory deployPath = string.concat("deployments/crosschain/", env, ".json");
        vm.writeJson(networkJson, deployPath, string.concat(".", network));
        console2.log("  Written to", deployPath, string.concat("[", network, "]"));
    }

    ////////////////////////////////////////////////////////////
    //                       HELPERS                          //
    ////////////////////////////////////////////////////////////

    /// @dev Captures git commit SHA and tag via FFI for deployment artifacts.
    function _loadGitInfo() internal {
        {
            string[] memory cmd = new string[](3);
            cmd[0] = "git";
            cmd[1] = "rev-parse";
            cmd[2] = "HEAD";
            _commitSha = string(vm.ffi(cmd));
        }
        {
            string[] memory cmd = new string[](4);
            cmd[0] = "git";
            cmd[1] = "describe";
            cmd[2] = "--tags";
            cmd[3] = "--always";
            _gitTag = string(vm.ffi(cmd));
        }
    }

    /// @dev Resolves an RPC URL for a chain from config.
    ///   Prefers Alchemy (slug + API key), falls back to explicit "rpc" field.
    function _resolveRpc(string memory chain) internal returns (string memory) {
        string memory np = string.concat(".", chain);
        string memory slug = vm.parseJsonString(_config, string.concat(np, ".alchemySlug"));
        string memory apiKey = vm.envOr("ALCHEMY_API_KEY", string(""));

        if (bytes(slug).length > 0 && bytes(apiKey).length > 0) {
            return string.concat("https://", slug, ".g.alchemy.com/v2/", apiKey);
        }

        return vm.parseJsonString(_config, string.concat(np, ".rpc"));
    }

    /// @dev Returns true if the network passes the optional DEPLOY_CHAINS filter.
    function _shouldDeploy(string memory network) internal view returns (bool) {
        if (_deployFilter.length == 0) return true;
        bytes32 h = keccak256(bytes(network));
        for (uint256 i; i < _deployFilter.length; i++) {
            if (keccak256(bytes(_deployFilter[i])) == h) return true;
        }
        return false;
    }

    /// @dev Returns true if a JSON object key exists at the given path.
    function _hasKey(string memory json, string memory key) internal returns (bool) {
        try _deployer.parseKeys(json, key) {
            return true;
        } catch {
            return false;
        }
    }

    /// @dev Tries to parse a bool from JSON. Returns false if key doesn't exist.
    function _tryParseBool(string memory key) internal returns (bool) {
        try _deployer.parseBool(_config, key) returns (bool v) {
            return v;
        } catch {
            return false;
        }
    }

    /// @dev Tries to load an address from JSON. Returns address(0) on failure.
    function _tryLoadAddress(string memory json, string memory key) internal returns (address) {
        if (bytes(json).length <= 2) return address(0);
        try _deployer.parseAddress(json, key) returns (address a) {
            return a;
        } catch {
            return address(0);
        }
    }

    function _loadDeployments(string memory env) internal returns (string memory) {
        string memory path = string.concat("deployments/crosschain/", env, ".json");
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

    function _resetNetworkState() internal {
        verifierAddr = address(0);
        bridgeImpl = address(0);
        bridgeProxy = address(0);
        delete _gwAddrs;
        delete _gwTypes;
    }
}
