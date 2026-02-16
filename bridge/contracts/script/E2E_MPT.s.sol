// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {InteroperableAddress} from "openzeppelin-contracts/contracts/utils/draft-InteroperableAddress.sol";

import {WorldIDSource} from "@core/Source.sol";
import {WorldIDSatellite} from "@core/Satellite.sol";
import {IStateBridge} from "@core/types/IStateBridge.sol";
import {EthereumMPTGatewayAdapter} from "@core/adapters/EthereumMPTGatewayAdapter.sol";
import {Lib} from "@lib-core/Lib.sol";
import {WorldIDGateway} from "@lib-core/Gateway.sol";
import {Verifier} from "@world-id/Verifier.sol";
import {GameStatus, Claim, GameType} from "@optimism-bedrock/src/dispute/lib/Types.sol";

import {
    MockRegistry,
    MockIssuerRegistry,
    MockOprfRegistry,
    MockDisputeGame,
    MockDisputeGameFactory
} from "../test/helpers/Mocks.sol";

// ────────────────────────────────────────────────────────────────────────────
//  Phase 1: Deploy World Chain contracts + seed registries
// ────────────────────────────────────────────────────────────────────────────

/// @notice Deploys mock registries, seeds initial data, and deploys WorldIDSource
///   behind an ERC1967Proxy on the World Chain anvil.
///
/// @dev Reads BATCH_SIZE env var to seed N issuer keys + N OPRF keys.
///   Key formulas: issuer#i = (i*10+1, i*10+2), oprf#i = (i*10+3, i*10+4).
contract DeployE2E is Script {
    function run() public {
        uint256 batch = vm.envOr("BATCH_SIZE", uint256(1));

        vm.startBroadcast();

        MockRegistry registry = new MockRegistry();
        MockIssuerRegistry issuerRegistry = new MockIssuerRegistry();
        MockOprfRegistry oprfRegistry = new MockOprfRegistry();

        registry.setLatestRoot(1000);
        for (uint256 i = 1; i <= batch; i++) {
            issuerRegistry.setPubkey(uint64(i), i * 10 + 1, i * 10 + 2);
            oprfRegistry.setKey(uint160(i), i * 10 + 3, i * 10 + 4);
        }

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
        vm.serializeAddress(json, "sourceImpl", address(sourceImpl));
        vm.serializeAddress(json, "sourceProxy", address(proxy));
        string memory out = vm.serializeAddress(json, "owner", msg.sender);
        vm.writeJson(out, "test/fixtures/e2e_mpt/wc_addrs.json");

        console2.log("WorldIDSource proxy:", address(proxy));
        console2.log("Batch size:", batch);
    }
}

// ────────────────────────────────────────────────────────────────────────────
//  Phase 2: Propagate state through two rounds with registry updates
// ────────────────────────────────────────────────────────────────────────────
contract PropagateE2E is Script {
    function run() public {
        uint256 batch = vm.envOr("BATCH_SIZE", uint256(1));

        string memory wcAddrs = vm.readFile("test/fixtures/e2e_mpt/wc_addrs.json");
        address sourceProxy = vm.parseJsonAddress(wcAddrs, ".sourceProxy");
        address registry = vm.parseJsonAddress(wcAddrs, ".registry");
        address issuerRegistry = vm.parseJsonAddress(wcAddrs, ".issuerRegistry");

        // Build ID arrays [1, 2, ..., batch]
        uint64[] memory issuerIds = new uint64[](batch);
        uint160[] memory oprfIds = new uint160[](batch);
        for (uint256 i; i < batch; i++) {
            issuerIds[i] = uint64(i + 1);
            oprfIds[i] = uint160(i + 1);
        }

        vm.startBroadcast();

        // Round 1: propagate initial state
        WorldIDSource(sourceProxy).propagateState(issuerIds, oprfIds);

        // Update registries (root + issuer#1 only)
        MockRegistry(registry).setLatestRoot(2000);
        MockIssuerRegistry(issuerRegistry).setPubkey(1, 55, 66);

        // Round 2: propagate updated state (2 commitments: root + issuer#1)
        WorldIDSource(sourceProxy).propagateState(issuerIds, oprfIds);

        vm.stopBroadcast();

        // Read actual on-chain state
        Lib.Chain memory chain = WorldIDSource(sourceProxy).KECCAK_CHAIN();
        console2.log("Chain head:", vm.toString(chain.head));
        console2.log("Chain length:", chain.length);
        console2.log("Total commitments:", 3 + 2 * batch);
    }
}

// ────────────────────────────────────────────────────────────────────────────
//  Phase 4: Deploy Ethereum contracts + relay with real MPT proofs
// ────────────────────────────────────────────────────────────────────────────

contract DeployAndRelayE2E is Script {
    using InteroperableAddress for bytes;

    function run() public {
        string memory wcAddrs = vm.readFile("test/fixtures/e2e_mpt/wc_addrs.json");
        string memory round1Json = vm.readFile("test/fixtures/e2e_mpt/round1.json");
        string memory round2Json = vm.readFile("test/fixtures/e2e_mpt/round2.json");
        string memory proofJson = vm.readFile("test/fixtures/e2e_mpt/proof.json");

        address sourceProxy = vm.parseJsonAddress(wcAddrs, ".sourceProxy");

        bytes32 stateRoot = vm.parseJsonBytes32(proofJson, ".stateRoot");
        bytes[] memory accountProof = vm.parseJsonBytesArray(proofJson, ".accountProof");
        bytes[] memory storageProof = vm.parseJsonBytesArray(proofJson, ".storageProof");

        vm.startBroadcast();

        address satelliteProxy;
        address gatewayAddr;

        // ── Deploy L1 contracts ──
        {
            Verifier verifier = new Verifier();
            WorldIDSatellite satImpl = new WorldIDSatellite(address(verifier), 3600, 30, 7200);

            address[] memory emptyGws = new address[](0);
            IStateBridge.InitConfig memory dstCfg = IStateBridge.InitConfig({
                name: "World ID Bridge", version: "1", owner: msg.sender, authorizedGateways: emptyGws
            });

            satelliteProxy =
                address(new ERC1967Proxy(address(satImpl), abi.encodeCall(WorldIDSatellite.initialize, (dstCfg))));
        }

        // ── Deploy DisputeGameFactory + Game + Gateway ──
        {
            MockDisputeGameFactory dgf = new MockDisputeGameFactory();
            bytes32 outputRoot = keccak256(abi.encodePacked(bytes32(0), stateRoot, bytes32(0), bytes32(0)));
            MockDisputeGame game = new MockDisputeGame(GameStatus.IN_PROGRESS);
            dgf.registerGame(GameType.wrap(0), Claim.wrap(outputRoot), bytes(""), address(game));

            EthereumMPTGatewayAdapter gateway =
                new EthereumMPTGatewayAdapter(msg.sender, address(dgf), false, satelliteProxy, sourceProxy, 480);

            WorldIDSatellite(satelliteProxy).addGateway(address(gateway));
            gatewayAddr = address(gateway);
        }

        // ── Concatenate round1 + round2 commitments and relay ──
        {
            // eventData = abi.encode(bytes commitment) from the ChainCommitted event
            bytes memory commitData1 = abi.decode(vm.parseJsonBytes(round1Json, ".eventData"), (bytes));
            bytes memory commitData2 = abi.decode(vm.parseJsonBytes(round2Json, ".eventData"), (bytes));

            Lib.Commitment[] memory c1 = abi.decode(commitData1, (Lib.Commitment[]));
            Lib.Commitment[] memory c2 = abi.decode(commitData2, (Lib.Commitment[]));

            Lib.Commitment[] memory allCommits = new Lib.Commitment[](c1.length + c2.length);
            for (uint256 i; i < c1.length; i++) {
                allCommits[i] = c1[i];
            }
            for (uint256 i; i < c2.length; i++) {
                allCommits[c1.length + i] = c2[i];
            }

            bytes memory recipient = InteroperableAddress.formatEvmV1(block.chainid, satelliteProxy);
            bytes4 attrSelector = bytes4(keccak256("l1ProofAttributes(uint32,bytes,bytes32[4],bytes[],bytes[])"));
            bytes32[4] memory outputRootPreimage = [bytes32(0), stateRoot, bytes32(0), bytes32(0)];

            bytes[] memory attributes = new bytes[](1);
            attributes[0] = abi.encodePacked(
                attrSelector, abi.encode(uint32(0), bytes(""), outputRootPreimage, accountProof, storageProof)
            );

            EthereumMPTGatewayAdapter(gatewayAddr).sendMessage(recipient, abi.encode(allCommits), attributes);
        }

        vm.stopBroadcast();

        string memory json = "eth";
        vm.serializeAddress(json, "satelliteProxy", satelliteProxy);
        string memory out = vm.serializeAddress(json, "gateway", gatewayAddr);
        vm.writeJson(out, "test/fixtures/e2e_mpt/eth_addrs.json");

        console2.log("WorldIDSatellite proxy:", satelliteProxy);
        console2.log("EthereumMPTGateway:", gatewayAddr);
    }
}

// ────────────────────────────────────────────────────────────────────────────
//  Phase 5: Verify relayed state on Ethereum satellite
// ────────────────────────────────────────────────────────────────────────────

contract VerifyE2E is Script {
    function run() public view {
        uint256 batch = vm.envOr("BATCH_SIZE", uint256(1));

        string memory ethAddrs = vm.readFile("test/fixtures/e2e_mpt/eth_addrs.json");
        address satProxy = vm.parseJsonAddress(ethAddrs, ".satelliteProxy");

        string memory round2Json = vm.readFile("test/fixtures/e2e_mpt/round2.json");
        bytes32 expectedHead = vm.parseJsonBytes32(round2Json, ".chainHead");

        WorldIDSatellite sat = WorldIDSatellite(satProxy);

        // ── Root checks ──
        _assert(sat.LATEST_ROOT() == 2000, "LATEST_ROOT should be 2000");
        _assert(sat.isValidRoot(1000), "root 1000 should be valid within window");
        _assert(sat.isValidRoot(2000), "root 2000 should be valid");

        // ── Chain integrity ──
        uint256 expectedLength = 3 + 2 * batch;
        Lib.Chain memory chain = sat.KECCAK_CHAIN();
        _assert(chain.length == expectedLength, "wrong chain length");
        _assert(chain.head == expectedHead, "chain head should match round 2");

        // ── Issuer key #1: updated to (55, 66) in round 2 ──
        IStateBridge.ProvenPubKeyInfo memory issuer1 = sat.issuerSchemaIdToPubkeyAndProofId(1);
        _assert(issuer1.pubKey.x == 55, "issuer#1 pubkey.x should be 55");
        _assert(issuer1.pubKey.y == 66, "issuer#1 pubkey.y should be 66");

        // ── OPRF key #1: unchanged at (13, 14) from initial seed ──
        IStateBridge.ProvenPubKeyInfo memory oprf1 = sat.oprfKeyIdToPubkeyAndProofId(1);
        _assert(oprf1.pubKey.x == 13, "oprf#1 pubkey.x should be 13");
        _assert(oprf1.pubKey.y == 14, "oprf#1 pubkey.y should be 14");

        // ── Spot-check last keys (batch > 1) ──
        if (batch > 1) {
            IStateBridge.ProvenPubKeyInfo memory issuerN = sat.issuerSchemaIdToPubkeyAndProofId(uint64(batch));
            _assert(issuerN.pubKey.x == batch * 10 + 1, "last issuer pubkey.x mismatch");
            _assert(issuerN.pubKey.y == batch * 10 + 2, "last issuer pubkey.y mismatch");

            IStateBridge.ProvenPubKeyInfo memory oprfN = sat.oprfKeyIdToPubkeyAndProofId(uint160(batch));
            _assert(oprfN.pubKey.x == batch * 10 + 3, "last oprf pubkey.x mismatch");
            _assert(oprfN.pubKey.y == batch * 10 + 4, "last oprf pubkey.y mismatch");
        }

        console2.log("=== ALL ASSERTIONS PASSED ===");
        console2.log("  batch:", batch);
        console2.log("  chain length:", chain.length);
    }

    function _assert(bool condition, string memory message) internal pure {
        require(condition, message);
    }
}
