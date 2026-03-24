// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {WorldIDSatellite} from "../../src/crosschain/WorldIDSatellite.sol";
import {IStateBridge} from "../../src/crosschain/interfaces/IStateBridge.sol";
import {PermissionedGatewayAdapter} from "../../src/crosschain/adapters/PermissionedGatewayAdapter.sol";
import {Verifier} from "../../src/core/Verifier.sol";

/// @title DeployTempo
/// @notice Single-chain deployment script for World ID Bridge on Tempo.
///   Reads existing WorldIDSource address from env vars.
contract DeployTempo is Script {
    function run() public {
        // ── Config from staging.json (hardcoded for Tempo) ──
        address owner = 0x6348A4a4dF173F68eB28A452Ca6c13493e447aF1;
        address wcSourceProxy = 0xf2B281c1D115A0d3D19a4efCCDDe83dbB4DD23be;
        uint256 wcChainId = 480;
        uint256 rootValidityWindow = 3600;
        uint256 treeDepth = 30;
        uint64 minExpThreshold = 18000;

        uint256 pk = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(pk);

        // 1. Deploy Verifier
        console2.log("--- Deploying Verifier ---");
        Verifier verifier = new Verifier();
        console2.log("  Verifier:", address(verifier));

        // 2. Deploy WorldIDSatellite implementation
        console2.log("--- Deploying WorldIDSatellite ---");
        WorldIDSatellite satImpl =
            new WorldIDSatellite(address(verifier), rootValidityWindow, treeDepth, minExpThreshold);
        console2.log("  Implementation:", address(satImpl));

        // 3. Deploy proxy
        address[] memory emptyGws = new address[](0);
        IStateBridge.InitConfig memory cfg = IStateBridge.InitConfig({
            name: "WorldID Bridge", version: "1.0.0", owner: owner, authorizedGateways: emptyGws
        });

        ERC1967Proxy proxy = new ERC1967Proxy(address(satImpl), abi.encodeCall(WorldIDSatellite.initialize, (cfg)));
        console2.log("  Proxy:", address(proxy));

        // 4. Deploy PermissionedGatewayAdapter
        console2.log("--- Deploying PermissionedGateway ---");
        PermissionedGatewayAdapter gateway =
            new PermissionedGatewayAdapter(owner, address(proxy), wcSourceProxy, wcChainId);
        console2.log("  PermissionedGateway:", address(gateway));

        // 5. Authorize gateway
        console2.log("  Authorizing gateway...");
        WorldIDSatellite(address(proxy)).addGateway(address(gateway));

        vm.stopBroadcast();

        console2.log("");
        console2.log("=== Deployment Complete ===");
        console2.log("  Verifier:", address(verifier));
        console2.log("  WorldIDSatellite impl:", address(satImpl));
        console2.log("  WorldIDSatellite proxy:", address(proxy));
        console2.log("  PermissionedGateway:", address(gateway));
    }
}
