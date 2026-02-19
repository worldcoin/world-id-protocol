// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {WorldIDSource} from "../../src/crosschain/WorldIDSource.sol";
import {WorldIDSatellite} from "../../src/crosschain/WorldIDSatellite.sol";
import {IStateBridge} from "../../src/crosschain/interfaces/IStateBridge.sol";
import {EthereumMPTGatewayAdapter} from "../../src/crosschain/adapters/EthereumMPTGatewayAdapter.sol";
import {PermissionedGatewayAdapter} from "../../src/crosschain/adapters/PermissionedGatewayAdapter.sol";
import {Verifier} from "../../src/core/Verifier.sol";

import {MockRegistry, MockIssuerRegistry, MockOprfRegistry} from "../../test/crosschain/helpers/Mocks.sol";

// ────────────────────────────────────────────────────────────────────────────
//  Mocks for relay E2E (full DisputeGame interface for the relay binary)
// ────────────────────────────────────────────────────────────────────────────

/// @dev Mutable mock that exposes all getters the relay needs.
contract RelayMockDisputeGame {
    uint8 public status;
    bytes32 public rootClaim;
    uint256 public l2BlockNumber;
    bytes public extraData;

    function setStatus(uint8 s) external {
        status = s;
    }

    function setRootClaim(bytes32 rc) external {
        rootClaim = rc;
    }

    function setL2BlockNumber(uint256 bn) external {
        l2BlockNumber = bn;
    }

    function setExtraData(bytes calldata ed) external {
        extraData = ed;
    }
}

/// @dev Factory that supports gameCount() + gameAtIndex() for the relay scanner,
///   plus games() for the on-chain gateway verification lookup.
contract RelayMockDisputeGameFactory {
    struct GameEntry {
        uint32 gameType;
        uint256 timestamp;
        address proxy;
    }

    GameEntry[] internal _games;
    mapping(bytes32 => address) internal _gamesLookup;

    function addGame(uint32 gameType_, address proxy_) external {
        _games.push(GameEntry({gameType: gameType_, timestamp: block.timestamp, proxy: proxy_}));

        // Register for games() lookup — read rootClaim and extraData from the game.
        bytes32 rootClaim = RelayMockDisputeGame(proxy_).rootClaim();
        bytes memory extraData = RelayMockDisputeGame(proxy_).extraData();
        bytes32 key = keccak256(abi.encode(gameType_, rootClaim, extraData));
        _gamesLookup[key] = proxy_;
    }

    function gameCount() external view returns (uint256) {
        return _games.length;
    }

    function gameAtIndex(uint256 index) external view returns (uint32, uint256, address) {
        GameEntry storage g = _games[index];
        return (g.gameType, g.timestamp, g.proxy);
    }

    /// @dev Lookup by (gameType, rootClaim, extraData) — called by the EthereumMPTGatewayAdapter.
    function games(uint32 gameType_, bytes32 rootClaim_, bytes memory extraData_)
        external
        view
        returns (address proxy_, uint64 timestamp_)
    {
        bytes32 key = keccak256(abi.encode(gameType_, rootClaim_, extraData_));
        proxy_ = _gamesLookup[key];
        timestamp_ = uint64(block.timestamp);
    }
}

// ────────────────────────────────────────────────────────────────────────────
//  Phase 1: Deploy World Chain source contracts + seed mock registries
// ────────────────────────────────────────────────────────────────────────────

contract DeploySourceRelayE2E is Script {
    function run() public {
        vm.startBroadcast();

        MockRegistry registry = new MockRegistry();
        MockIssuerRegistry issuerRegistry = new MockIssuerRegistry();
        MockOprfRegistry oprfRegistry = new MockOprfRegistry();

        registry.setLatestRoot(1000);
        issuerRegistry.setPubkey(1, 11, 12);
        oprfRegistry.setKey(1, 13, 14);

        WorldIDSource sourceImpl = new WorldIDSource(address(registry), address(issuerRegistry), address(oprfRegistry));

        address[] memory emptyGws = new address[](0);
        IStateBridge.InitConfig memory cfg = IStateBridge.InitConfig({
            name: "World ID Source", version: "1", owner: msg.sender, authorizedGateways: emptyGws
        });

        ERC1967Proxy proxy = new ERC1967Proxy(address(sourceImpl), abi.encodeCall(WorldIDSource.initialize, (cfg)));

        vm.stopBroadcast();

        string memory json = "wc";
        vm.serializeAddress(json, "registry", address(registry));
        vm.serializeAddress(json, "issuerRegistry", address(issuerRegistry));
        vm.serializeAddress(json, "oprfRegistry", address(oprfRegistry));
        vm.serializeAddress(json, "sourceProxy", address(proxy));
        string memory out = vm.serializeAddress(json, "owner", msg.sender);
        vm.writeJson(out, "test/crosschain/fixtures/e2e_relay/wc_addrs.json");

        console2.log("WorldIDSource proxy:", address(proxy));
    }
}

// ────────────────────────────────────────────────────────────────────────────
//  Phase 2a: Deploy L1 contracts (Satellite + EthereumMPTGateway + mock DGF)
// ────────────────────────────────────────────────────────────────────────────

contract DeployEthRelayE2E is Script {
    function run() public {
        address wcSourceProxy = vm.envAddress("WC_SOURCE_PROXY");

        vm.startBroadcast();

        // Deploy satellite
        Verifier verifier = new Verifier();
        WorldIDSatellite satImpl = new WorldIDSatellite(address(verifier), 3600, 30, 7200);

        address[] memory emptyGws = new address[](0);
        IStateBridge.InitConfig memory cfg = IStateBridge.InitConfig({
            name: "World ID Bridge", version: "1", owner: msg.sender, authorizedGateways: emptyGws
        });

        ERC1967Proxy satProxy = new ERC1967Proxy(address(satImpl), abi.encodeCall(WorldIDSatellite.initialize, (cfg)));

        // Deploy mock dispute game infrastructure
        RelayMockDisputeGameFactory dgf = new RelayMockDisputeGameFactory();
        RelayMockDisputeGame game = new RelayMockDisputeGame();

        // Deploy EthereumMPTGatewayAdapter
        EthereumMPTGatewayAdapter gateway = new EthereumMPTGatewayAdapter(
            msg.sender,
            address(dgf), // dispute game factory
            false, // requireFinalized
            address(satProxy), // bridge on this chain
            wcSourceProxy, // anchor source on WC
            480 // WC chain ID
        );

        WorldIDSatellite(address(satProxy)).addGateway(address(gateway));

        vm.stopBroadcast();

        string memory json = "eth";
        vm.serializeAddress(json, "satelliteProxy", address(satProxy));
        vm.serializeAddress(json, "gateway", address(gateway));
        vm.serializeAddress(json, "disputeGameFactory", address(dgf));
        string memory out = vm.serializeAddress(json, "disputeGame", address(game));
        vm.writeJson(out, "test/crosschain/fixtures/e2e_relay/eth_addrs.json");

        console2.log("ETH Satellite:", address(satProxy));
        console2.log("ETH Gateway (MPT):", address(gateway));
        console2.log("Mock DGF:", address(dgf));
        console2.log("Mock Game:", address(game));
    }
}

// ────────────────────────────────────────────────────────────────────────────
//  Phase 2b: Deploy destination contracts (Satellite + PermissionedGateway)
// ────────────────────────────────────────────────────────────────────────────

contract DeployDestRelayE2E is Script {
    function run() public {
        address wcSourceProxy = vm.envAddress("WC_SOURCE_PROXY");

        vm.startBroadcast();

        Verifier verifier = new Verifier();
        WorldIDSatellite satImpl = new WorldIDSatellite(address(verifier), 3600, 30, 7200);

        address[] memory emptyGws = new address[](0);
        IStateBridge.InitConfig memory cfg = IStateBridge.InitConfig({
            name: "World ID Bridge", version: "1", owner: msg.sender, authorizedGateways: emptyGws
        });

        ERC1967Proxy satProxy = new ERC1967Proxy(address(satImpl), abi.encodeCall(WorldIDSatellite.initialize, (cfg)));

        PermissionedGatewayAdapter gateway =
            new PermissionedGatewayAdapter(msg.sender, address(satProxy), wcSourceProxy, 480);

        WorldIDSatellite(address(satProxy)).addGateway(address(gateway));

        vm.stopBroadcast();

        string memory json = "dest";
        vm.serializeAddress(json, "satelliteProxy", address(satProxy));
        string memory out = vm.serializeAddress(json, "gateway", address(gateway));
        vm.writeJson(out, "test/crosschain/fixtures/e2e_relay/dest_addrs.json");

        console2.log("DEST Satellite:", address(satProxy));
        console2.log("DEST Gateway (Permissioned):", address(gateway));
    }
}
