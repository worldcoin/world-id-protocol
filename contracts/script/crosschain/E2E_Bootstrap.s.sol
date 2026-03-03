// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {Vm} from "forge-std/Vm.sol";

import {OprfKeyRegistry} from "oprf-key-registry/src/OprfKeyRegistry.sol";
import {WorldIDRegistry} from "../../src/core/WorldIDRegistry.sol";
import {CredentialSchemaIssuerRegistry} from "../../src/core/CredentialSchemaIssuerRegistry.sol";
import {WorldIDSource} from "../../src/crosschain/WorldIDSource.sol";
import {WorldIDSatellite} from "../../src/crosschain/WorldIDSatellite.sol";
import {IStateBridge} from "../../src/crosschain/interfaces/IStateBridge.sol";
import {EthereumMPTGatewayAdapter} from "../../src/crosschain/adapters/EthereumMPTGatewayAdapter.sol";
import {Verifier} from "../../src/core/Verifier.sol";

import {RelayMockDisputeGame, RelayMockDisputeGameFactory} from "./E2E_Relay.s.sol";

// ─────────────────────────────────────────────────────────────────────────────
//  Shared constants
// ─────────────────────────────────────────────────────────────────────────────

/// @dev EIP-1967 implementation slot.
bytes32 constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

/// @dev EIP-1967 admin slot.
bytes32 constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

/// @dev Anvil default account #0.
address constant DEPLOYER = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;

// ── World Chain predeploy addresses ──────────────────────────────────────
address constant WC_OPRF_REGISTRY = address(0xB001);
address constant WC_REGISTRY = address(0xB002);
address constant WC_ISSUER_REGISTRY = address(0xB003);
address constant WC_SOURCE = address(0xB004);

// ── Ethereum predeploy addresses ─────────────────────────────────────────
address constant ETH_SATELLITE = address(0xC001);
address constant ETH_GATEWAY = address(0xC002);
address constant ETH_DGF = address(0xC003);
address constant ETH_GAME = address(0xC004);

// ─────────────────────────────────────────────────────────────────────────────
//  GenAllocsWc — World Chain genesis
// ─────────────────────────────────────────────────────────────────────────────

/// @notice Builds World Chain genesis allocs with real contracts at fixed addresses.
///
/// @dev Usage:
///   cd contracts && forge script script/crosschain/E2E_Bootstrap.s.sol:GenAllocsWc
contract GenAllocsWc is Script {
    // ── Default test seed values ─────────────────────────────────────────
    uint256 constant SEEDED_ROOT = 1000;
    uint64 constant ISSUER_ID = 1;
    uint256 constant ISSUER_X = 11;
    uint256 constant ISSUER_Y = 12;
    uint160 constant OPRF_KEY_ID = 1;
    uint256 constant OPRF_X = 13;
    uint256 constant OPRF_Y = 14;
    uint256 constant OPRF_EPOCH = 1;

    // ── Registry storage layout ──────────────────────────────────────────
    uint256 constant LATEST_ROOT_SLOT = 0x11;
    uint256 constant ISSUER_PUBKEY_BASE = 0x03;
    uint256 constant OPRF_KEY_BASE = 0x07;

    function run() public {
        // 1. Deploy implementations (forge links libraries automatically).
        OprfKeyRegistry oprfImpl = new OprfKeyRegistry();
        WorldIDRegistry regImpl = new WorldIDRegistry();
        CredentialSchemaIssuerRegistry issImpl = new CredentialSchemaIssuerRegistry();
        WorldIDSource srcImpl = new WorldIDSource(WC_REGISTRY, WC_ISSUER_REGISTRY, WC_OPRF_REGISTRY);

        // Pin all deployed bytecode into the state dump. vm.dumpState only
        // captures accounts with non-zero state (balance/storage/nonce).
        // Implementation contracts and auto-linked libraries may have zero
        // storage and would be silently dropped. Give each 1 wei.
        vm.deal(address(oprfImpl), 1);
        vm.deal(address(regImpl), 1);
        vm.deal(address(issImpl), 1);
        vm.deal(address(srcImpl), 1);
        _pinLibraries(address(oprfImpl), address(regImpl));

        // 2. Etch ERC1967 proxy bytecode at fixed addresses.
        bytes memory proxyRuntime = vm.getDeployedCode("ERC1967Proxy.sol:ERC1967Proxy");
        _etchProxy(WC_OPRF_REGISTRY, address(oprfImpl), proxyRuntime);
        _etchProxy(WC_REGISTRY, address(regImpl), proxyRuntime);
        _etchProxy(WC_ISSUER_REGISTRY, address(issImpl), proxyRuntime);
        _etchProxy(WC_SOURCE, address(srcImpl), proxyRuntime);

        // 3. Initialize contracts through the proxies.
        //    Prank as DEPLOYER so owner-restricted calls succeed (without --broadcast,
        //    msg.sender is the script contract, not the EOA).
        vm.startPrank(DEPLOYER);

        OprfKeyRegistry(WC_OPRF_REGISTRY).initialize(DEPLOYER, DEPLOYER, address(0), 1, 1);
        address[] memory peers = new address[](1);
        peers[0] = DEPLOYER;
        OprfKeyRegistry(WC_OPRF_REGISTRY).registerOprfPeers(peers);

        WorldIDRegistry(WC_REGISTRY).initialize(30, address(0), address(0), 0);

        CredentialSchemaIssuerRegistry(WC_ISSUER_REGISTRY).initialize(address(0), address(0), 0, WC_OPRF_REGISTRY);

        address[] memory emptyGws = new address[](0);
        WorldIDSource(WC_SOURCE).initialize(IStateBridge.InitConfig("WorldIDSource", "1", DEPLOYER, emptyGws));

        vm.stopPrank();

        // 4. Seed test state.
        vm.store(WC_REGISTRY, bytes32(LATEST_ROOT_SLOT), bytes32(SEEDED_ROOT));

        bytes32 issSlot = keccak256(abi.encode(uint256(ISSUER_ID), ISSUER_PUBKEY_BASE));
        vm.store(WC_ISSUER_REGISTRY, issSlot, bytes32(ISSUER_X));
        vm.store(WC_ISSUER_REGISTRY, bytes32(uint256(issSlot) + 1), bytes32(ISSUER_Y));

        bytes32 oprfSlot = keccak256(abi.encode(uint256(OPRF_KEY_ID), OPRF_KEY_BASE));
        vm.store(WC_OPRF_REGISTRY, oprfSlot, bytes32(OPRF_X));
        vm.store(WC_OPRF_REGISTRY, bytes32(uint256(oprfSlot) + 1), bytes32(OPRF_Y));
        vm.store(WC_OPRF_REGISTRY, bytes32(uint256(oprfSlot) + 2), bytes32(OPRF_EPOCH));

        // 5. Dump genesis.
        vm.dumpState("test/crosschain/fixtures/e2e_relay/wc_genesis.json");

        // 6. Write addresses.
        string memory json = "wc";
        vm.serializeAddress(json, "registry", WC_REGISTRY);
        vm.serializeAddress(json, "issuerRegistry", WC_ISSUER_REGISTRY);
        vm.serializeAddress(json, "oprfRegistry", WC_OPRF_REGISTRY);
        string memory out = vm.serializeAddress(json, "source", WC_SOURCE);
        vm.writeJson(out, "test/crosschain/fixtures/e2e_relay/wc_addrs.json");

        console2.log("OprfKeyRegistry:", WC_OPRF_REGISTRY);
        console2.log("WorldIDRegistry:", WC_REGISTRY);
        console2.log("IssuerRegistry:", WC_ISSUER_REGISTRY);
        console2.log("WorldIDSource:", WC_SOURCE);
    }

    function _etchProxy(address where_, address impl, bytes memory proxyRuntime) internal {
        vm.etch(where_, proxyRuntime);
        vm.store(where_, IMPL_SLOT, bytes32(uint256(uint160(impl))));
        vm.store(where_, ADMIN_SLOT, bytes32(uint256(uint160(DEPLOYER))));
    }

    /// @dev Ensure ALL deployed bytecode survives vm.dumpState.
    ///      vm.dumpState drops accounts with zero balance+storage+nonce.
    ///      Libraries and the Create2Deployer fall into this category.
    ///      We scan nonce-derived addresses from both tx.origin (which
    ///      deploys the Create2Deployer) and the Create2Deployer itself,
    ///      then deal 1 wei to every address that has code.
    /// @dev Pin all auto-linked library code into the state dump.
    ///      We etch the library runtime code at well-known fixed addresses
    ///      and then patch the implementation bytecodes in-place to reference
    ///      these fixed addresses instead of the Create2Deployer's addresses.
    ///      This ensures vm.dumpState captures them and the proxies can
    ///      delegatecall through to working implementation code.
    function _pinLibraries(address oprfImpl, address regImpl) internal {
        // Fixed library addresses (must not collide with predeploys).
        address LIB_BABYJUBJUB = address(0xA001);
        address LIB_POSEIDON = address(0xA002);
        address LIB_PACKED = address(0xA003);

        // Etch library runtime code at fixed addresses.
        vm.etch(LIB_BABYJUBJUB, vm.getDeployedCode("BabyJubJub.sol:BabyJubJub"));
        vm.etch(LIB_POSEIDON, vm.getDeployedCode("Poseidon2.sol:Poseidon2T2"));
        vm.etch(LIB_PACKED, vm.getDeployedCode("PackedAccountData.sol:PackedAccountData"));
        vm.deal(LIB_BABYJUBJUB, 1);
        vm.deal(LIB_POSEIDON, 1);
        vm.deal(LIB_PACKED, 1);

        // Patch implementation bytecodes to reference the fixed library addresses.
        // DELEGATECALL targets are embedded as 20-byte addresses preceded by PUSH20 (0x73).
        // We replace the auto-linked addresses with our fixed ones.
        _relinkImpl(oprfImpl, "BabyJubJub.sol:BabyJubJub", LIB_BABYJUBJUB);
        _relinkImpl(regImpl, "Poseidon2.sol:Poseidon2T2", LIB_POSEIDON);
        _relinkImpl(regImpl, "PackedAccountData.sol:PackedAccountData", LIB_PACKED);
    }

    /// @dev Replace a linked library address in an implementation's deployed bytecode.
    function _relinkImpl(address impl, string memory libArtifact, address newAddr) internal {
        bytes memory implCode = impl.code;
        bytes memory libCode = vm.getDeployedCode(libArtifact);

        // Find the original library address by deploying it temporarily.
        // The Create2Deployer already deployed it; `create` gives a NEW address
        // but we need the OLD one. Instead, compute it from the codehash:
        // the original address is embedded in implCode as a PUSH20 argument.
        //
        // Scan for the library codehash pattern is complex. Instead, we deploy
        // the library fresh and compare codehashes to find the old address.
        //
        // Simpler: deploy library at a temp address, get its codehash, then
        // scan implCode for any 20-byte sequence that has matching codehash.
        // But that requires eth_getCode calls for each candidate.
        //
        // Simplest: use vm.getDeployedCode to get the library's runtime code,
        // compute its codehash, then search the EVM state for an address with
        // that codehash. Forge doesn't expose this directly.
        //
        // ACTUALLY simplest: don't scan. The library addresses are deterministic
        // within a single forge script run. We can find them by deploying the
        // library again — if Create2 dedup returns the same address.
        // But create/create2 behavior in scripts is tricky.
        //
        // PRAGMATIC: just search the bytecode for PUSH20 patterns and test each
        // candidate by checking if it has the library's codehash.
        bytes32 libHash = keccak256(libCode);
        for (uint256 i = 0; i + 20 < implCode.length; i++) {
            if (implCode[i] == 0x73) {
                // PUSH20 opcode
                address candidate;
                assembly {
                    candidate := shr(96, mload(add(add(implCode, 0x21), i)))
                }
                if (candidate.code.length > 0 && keccak256(candidate.code) == libHash) {
                    // Found the old library address. Replace it with the new one.
                    bytes20 newAddrBytes = bytes20(newAddr);
                    for (uint256 j = 0; j < 20; j++) {
                        implCode[i + 1 + j] = newAddrBytes[j];
                    }
                    // Re-etch the patched bytecode.
                    vm.etch(impl, implCode);
                    return;
                }
            }
        }
        // Library reference not found — may not be linked in this impl.
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  GenAllocsEth — Ethereum genesis
// ─────────────────────────────────────────────────────────────────────────────

/// @notice Builds Ethereum genesis allocs with satellite + gateway at fixed addresses.
///
/// @dev Usage:
///   cd contracts && forge script script/crosschain/E2E_Bootstrap.s.sol:GenAllocsEth
contract GenAllocsEth is Script {
    function run() public {
        // 1. Deploy implementations.
        Verifier verifier = new Verifier();
        WorldIDSatellite satImpl = new WorldIDSatellite(
            address(verifier),
            type(uint256).max, // rootValidityWindow — never expires in tests
            30, // treeDepth
            1 // minExpirationThreshold (must be > 0)
        );

        EthereumMPTGatewayAdapter gwImpl = new EthereumMPTGatewayAdapter(
            DEPLOYER, // owner
            ETH_DGF, // dispute game factory
            false, // requireFinalized
            ETH_SATELLITE, // bridge (satellite proxy on this chain)
            WC_SOURCE, // anchor source on WC
            480 // WC chain ID
        );

        // 2. Etch at fixed addresses BEFORE initialization so storage writes
        //    land on the etched addresses, not the temporary `new` addresses.
        bytes memory proxyRuntime = vm.getDeployedCode("ERC1967Proxy.sol:ERC1967Proxy");
        _etchProxy(ETH_SATELLITE, address(satImpl), proxyRuntime);

        // Gateway: etch code + set Ownable._owner (OZ v5 stores at slot 0).
        vm.etch(ETH_GATEWAY, address(gwImpl).code);
        vm.store(ETH_GATEWAY, bytes32(0), bytes32(uint256(uint160(DEPLOYER))));

        // DGF + Game: etch empty instances, then initialize via calls below.
        vm.etch(ETH_DGF, vm.getDeployedCode("E2E_Relay.s.sol:RelayMockDisputeGameFactory"));
        vm.etch(ETH_GAME, vm.getDeployedCode("E2E_Relay.s.sol:RelayMockDisputeGame"));

        // 3. Initialize + configure (prank as DEPLOYER for owner-restricted calls).
        vm.startPrank(DEPLOYER);

        address[] memory emptyGws = new address[](0);
        WorldIDSatellite(ETH_SATELLITE).initialize(IStateBridge.InitConfig("WorldIDSatellite", "1", DEPLOYER, emptyGws));
        WorldIDSatellite(ETH_SATELLITE).addGateway(ETH_GATEWAY);

        // 4. Configure mock game.
        RelayMockDisputeGame(ETH_GAME).setStatus(2); // DEFENDER_WINS
        RelayMockDisputeGame(ETH_GAME).setL2BlockNumber(1_000_000); // high enough to cover any test block

        // 5. Register game in factory.
        RelayMockDisputeGameFactory(ETH_DGF).addGame(0, ETH_GAME);

        vm.stopPrank();

        // 6. Pin implementation contracts so they survive vm.dumpState.
        vm.deal(address(verifier), 1);
        vm.deal(address(satImpl), 1);

        // 7. Dump genesis.
        vm.dumpState("test/crosschain/fixtures/e2e_relay/eth_genesis.json");

        // 7. Write addresses.
        string memory json = "eth";
        vm.serializeAddress(json, "satelliteProxy", ETH_SATELLITE);
        vm.serializeAddress(json, "gateway", ETH_GATEWAY);
        vm.serializeAddress(json, "disputeGameFactory", ETH_DGF);
        string memory out = vm.serializeAddress(json, "disputeGame", ETH_GAME);
        vm.writeJson(out, "test/crosschain/fixtures/e2e_relay/eth_addrs.json");

        console2.log("Satellite:", ETH_SATELLITE);
        console2.log("Gateway:", ETH_GATEWAY);
        console2.log("DGF:", ETH_DGF);
        console2.log("Game:", ETH_GAME);
    }

    function _etchProxy(address where_, address impl, bytes memory proxyRuntime) internal {
        vm.etch(where_, proxyRuntime);
        vm.store(where_, IMPL_SLOT, bytes32(uint256(uint160(impl))));
        vm.store(where_, ADMIN_SLOT, bytes32(uint256(uint160(DEPLOYER))));
    }
}
