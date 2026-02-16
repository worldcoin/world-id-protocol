// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {WorldIDSource} from "../src/core/WorldIDSource.sol";
import {CrossDomainWorldID} from "../src/core/CrossDomainWorldID.sol";
import {OwnedGateway} from "../src/core/gateways/OwnedGateway.sol";
import {StateBridge} from "../src/core/lib/StateBridge.sol";

/// @title DeployBridgeSDK
/// @notice Deploys bridge SDK contracts across chains.
///
/// @dev Usage:
///
///   # 1. Deploy WorldIDSource on World Chain
///   forge script script/DeployBridgeSDK.s.sol --sig "deployWorldChain(string)" "staging" \
///     --rpc-url $WORLD_CHAIN_RPC --broadcast --private-key $PK
///
///   # 2. Deploy CrossDomainWorldID on a destination chain
///   forge script script/DeployBridgeSDK.s.sol \
///     --sig "deployDestination(string)" "staging" \
///     --rpc-url $DEST_RPC --broadcast --private-key $PK
///
///   # 3. Deploy OwnedGateway on the destination chain and authorize it
///   forge script script/DeployBridgeSDK.s.sol \
///     --sig "deployOwnedGateway(address,address,uint256)" \
///     $DEST_BRIDGE $WC_SOURCE 480 \
///     --rpc-url $DEST_RPC --broadcast --private-key $PK
contract DeployBridgeSDK is Script {
    ////////////////////////////////////////////////////////////
    //              1. WORLD CHAIN (SOURCE)                    //
    ////////////////////////////////////////////////////////////

    /// @notice Deploys WorldIDSource on World Chain behind an ERC1967 proxy.
    function deployWorldChain(string calldata env) public returns (address proxy) {
        string memory cfg = _loadConfig(env);

        address registry = vm.parseJsonAddress(cfg, ".worldchain.registry");
        address issuerRegistry = vm.parseJsonAddress(cfg, ".worldchain.issuerRegistry");
        address oprfRegistry = vm.parseJsonAddress(cfg, ".worldchain.oprfRegistry");
        address owner = vm.parseJsonAddress(cfg, ".owner");
        string memory name = vm.parseJsonString(cfg, ".bridgeName");
        string memory version = vm.parseJsonString(cfg, ".bridgeVersion");

        console2.log("=== Deploying WorldIDSource ===");
        console2.log("Registry:", registry);
        console2.log("IssuerRegistry:", issuerRegistry);
        console2.log("OprfRegistry:", oprfRegistry);
        console2.log("Owner:", owner);

        vm.startBroadcast();

        WorldIDSource impl = new WorldIDSource(registry, issuerRegistry, oprfRegistry);

        address[] memory gateways = new address[](0);
        StateBridge.InitConfig memory initCfg =
            StateBridge.InitConfig({name: name, version: version, owner: owner, authorizedGateways: gateways});
        bytes memory initData = abi.encodeWithSelector(StateBridge.initialize.selector, initCfg);

        proxy = address(new ERC1967Proxy(address(impl), initData));

        vm.stopBroadcast();

        console2.log("WorldIDSource impl:", address(impl));
        console2.log("WorldIDSource proxy:", proxy);
    }

    ////////////////////////////////////////////////////////////
    //           2. DESTINATION CHAIN (BRIDGED)                //
    ////////////////////////////////////////////////////////////

    /// @notice Deploys CrossDomainWorldID (destination verifier) behind an ERC1967 proxy.
    function deployDestination(string calldata env) public returns (address proxy) {
        string memory cfg = _loadConfig(env);

        address verifier = vm.parseJsonAddress(cfg, ".destination.verifier");
        address owner = vm.parseJsonAddress(cfg, ".owner");
        string memory name = vm.parseJsonString(cfg, ".bridgeName");
        string memory version = vm.parseJsonString(cfg, ".bridgeVersion");
        uint256 rootValidityWindow = vm.parseJsonUint(cfg, ".rootValidityWindow");
        uint256 treeDepth_ = vm.parseJsonUint(cfg, ".treeDepth");
        uint64 minExpirationThreshold = uint64(vm.parseJsonUint(cfg, ".minExpirationThreshold"));

        console2.log("=== Deploying CrossDomainWorldID ===");
        console2.log("Owner:", owner);

        vm.startBroadcast();

        CrossDomainWorldID impl =
            new CrossDomainWorldID(verifier, rootValidityWindow, treeDepth_, minExpirationThreshold);

        proxy = address(new ERC1967Proxy(address(impl), ""));

        vm.stopBroadcast();

        console2.log("CrossDomainWorldID impl:", address(impl));
        console2.log("CrossDomainWorldID proxy:", proxy);
    }

    ////////////////////////////////////////////////////////////
    //        4. OWNED GATEWAY (DESTINATION — DAY 1)           //
    ////////////////////////////////////////////////////////////

    /// @notice Deploys an OwnedGateway on a destination chain and authorizes it on the bridge.
    /// @param destBridge The CrossDomainWorldID proxy on this chain.
    /// @param wcSource The WorldIDSource proxy on World Chain.
    /// @param wcChainId The World Chain chain ID (e.g. 480).
    function deployOwnedGateway(address destBridge, address wcSource, uint256 wcChainId)
        public
        returns (address deployed)
    {
        address owner = msg.sender;

        console2.log("=== Deploying OwnedGateway ===");
        console2.log("CrossDomainWorldID:", destBridge);
        console2.log("WC Source:", wcSource);

        vm.startBroadcast();

        OwnedGateway gw = new OwnedGateway(owner, destBridge, wcSource, wcChainId);
        deployed = address(gw);

        CrossDomainWorldID(payable(destBridge)).addGateway(deployed);

        vm.stopBroadcast();

        console2.log("OwnedGateway:", deployed);
    }

    ////////////////////////////////////////////////////////////
    //        5. GATEWAY AUTHORIZATION (DESTINATION)           //
    ////////////////////////////////////////////////////////////

    /// @notice Authorizes a gateway on a CrossDomainWorldID instance.
    /// @param bridge_ The CrossDomainWorldID proxy address.
    /// @param gateway The gateway address to authorize.
    function authorizeGateway(address bridge_, address gateway) public {
        console2.log("=== Authorizing Gateway ===");
        console2.log("Bridge:", bridge_);
        console2.log("Gateway:", gateway);

        vm.startBroadcast();
        CrossDomainWorldID(payable(bridge_)).addGateway(gateway);
        vm.stopBroadcast();
    }

    ////////////////////////////////////////////////////////////
    //                      HELPERS                            //
    ////////////////////////////////////////////////////////////

    function _loadConfig(string memory env) internal view returns (string memory) {
        string memory path = string.concat("script/config/", env, ".json");
        return vm.readFile(path);
    }
}
