// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {WorldChainBridge} from "../src/core/bridges/WorldChainBridge.sol";
import {WorldIDBridge} from "../src/core/bridges/WorldIDBridge.sol";
import {CrossDomainWorldID} from "../src/core/CrossDomainWorldIdVerifier.sol";
import {WorldIDGateway} from "../src/core/SequencerGateway.sol";

/// @title DeployBridgeSDK
/// @notice Deploys bridge SDK contracts across chains.
///
/// @dev Usage:
///
///   # 1. Deploy WorldChainBridge on World Chain
///   forge script script/DeployBridgeSDK.s.sol --sig "deployWorldChain(string)" "staging" \
///     --rpc-url $WORLD_CHAIN_RPC --broadcast --private-key $PK
///
///   # 2. Deploy WorldIDBridge on a destination chain
///   forge script script/DeployBridgeSDK.s.sol \
///     --sig "deployDestination(string)" "staging" \
///     --rpc-url $DEST_RPC --broadcast --private-key $PK
///
///   # 3. Deploy WorldIDGateway on the destination chain and authorize it
///   forge script script/DeployBridgeSDK.s.sol \
///     --sig "deployWorldIDGateway(address,address,address,uint256)" \
///     $SEQUENCER_KEY $DEST_BRIDGE $WC_BRIDGE 480 \
///     --rpc-url $DEST_RPC --broadcast --private-key $PK
contract DeployBridgeSDK is Script {
    ////////////////////////////////////////////////////////////
    //              1. WORLD CHAIN (SOURCE)                    //
    ////////////////////////////////////////////////////////////

    /// @notice Deploys WorldChainBridge on World Chain behind an ERC1967 proxy.
    function deployWorldChain(string calldata env) public returns (address proxy) {
        string memory cfg = _loadConfig(env);

        address registry = vm.parseJsonAddress(cfg, ".worldchain.registry");
        address issuerRegistry = vm.parseJsonAddress(cfg, ".worldchain.issuerRegistry");
        address oprfRegistry = vm.parseJsonAddress(cfg, ".worldchain.oprfRegistry");
        address owner = vm.parseJsonAddress(cfg, ".owner");
        string memory name = vm.parseJsonString(cfg, ".bridgeName");
        string memory version = vm.parseJsonString(cfg, ".bridgeVersion");

        console2.log("=== Deploying WorldChainBridge ===");
        console2.log("Registry:", registry);
        console2.log("IssuerRegistry:", issuerRegistry);
        console2.log("OprfRegistry:", oprfRegistry);
        console2.log("Owner:", owner);

        vm.startBroadcast();

        WorldChainBridge impl = new WorldChainBridge(registry, issuerRegistry, oprfRegistry);

        address[] memory gateways = new address[](0);
        bytes memory initData = abi.encodeCall(WorldChainBridge.initialize, (name, version, owner, gateways));

        proxy = address(new ERC1967Proxy(address(impl), initData));

        vm.stopBroadcast();

        console2.log("WorldChainBridge impl:", address(impl));
        console2.log("WorldChainBridge proxy:", proxy);
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

        CrossDomainWorldID impl = new CrossDomainWorldID();

        address[] memory gateways = new address[](0);
        bytes memory initData = abi.encodeCall(
            CrossDomainWorldID.initialize,
            (name, version, owner, gateways, verifier, rootValidityWindow, treeDepth_, minExpirationThreshold)
        );

        proxy = address(new ERC1967Proxy(address(impl), initData));

        vm.stopBroadcast();

        console2.log("CrossDomainWorldID impl:", address(impl));
        console2.log("CrossDomainWorldID proxy:", proxy);
    }

    ////////////////////////////////////////////////////////////
    //        3. SEQUENCER GATEWAY (DESTINATION)               //
    ////////////////////////////////////////////////////////////

    /// @notice Deploys a WorldIDGateway on a destination chain and authorizes it on the bridge.
    /// @param sequencerKey The WC sequencer's signing address.
    /// @param destBridge The WorldIDBridge proxy on this chain.
    /// @param wcBridge The WorldChainBridge proxy on World Chain.
    /// @param wcChainId The World Chain chain ID (e.g. 480).
    function deployWorldIDGateway(address sequencerKey, address destBridge, address wcBridge, uint256 wcChainId)
        public
        returns (address deployed)
    {
        address owner = msg.sender;

        console2.log("=== Deploying WorldIDGateway ===");
        console2.log("Sequencer:", sequencerKey);
        console2.log("WorldIDBridge:", destBridge);
        console2.log("WC Bridge:", wcBridge);

        vm.startBroadcast();

        WorldIDGateway gw = new WorldIDGateway(owner, sequencerKey, destBridge, wcBridge, wcChainId);
        deployed = address(gw);

        // Authorize the gateway on WorldIDBridge
        WorldIDBridge(payable(destBridge)).addGateway(deployed);

        vm.stopBroadcast();

        console2.log("WorldIDGateway:", deployed);
    }

    ////////////////////////////////////////////////////////////
    //        4. GATEWAY AUTHORIZATION (DESTINATION)           //
    ////////////////////////////////////////////////////////////

    /// @notice Authorizes a gateway on a WorldIDBridge instance.
    /// @param bridge_ The WorldIDBridge proxy address.
    /// @param gateway The gateway address to authorize.
    function authorizeGateway(address bridge_, address gateway) public {
        console2.log("=== Authorizing Gateway ===");
        console2.log("Bridge:", bridge_);
        console2.log("Gateway:", gateway);

        vm.startBroadcast();
        WorldIDBridge(payable(bridge_)).addGateway(gateway);
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
