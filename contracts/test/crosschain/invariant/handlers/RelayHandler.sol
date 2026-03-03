// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {InteroperableAddress} from "openzeppelin-contracts/contracts/utils/draft-InteroperableAddress.sol";

import {WorldIDSource} from "../../../../src/crosschain/WorldIDSource.sol";
import {WorldIDSatellite} from "../../../../src/crosschain/WorldIDSatellite.sol";
import {PermissionedGatewayAdapter} from "../../../../src/crosschain/adapters/PermissionedGatewayAdapter.sol";
import {IStateBridge} from "../../../../src/crosschain/interfaces/IStateBridge.sol";
import {Lib} from "../../../../src/crosschain/lib/Lib.sol";
import {MockRegistry, MockIssuerRegistry, MockOprfRegistry} from "../../helpers/Mocks.sol";
import {RegistryHandler} from "./RegistryHandler.sol";

/// @title RelayHandler
/// @notice Invariant-test handler that drives the propagate-and-relay cycle.
///   Mirrors the `_buildPayload` / `_propagate` / `_relay` helpers from E2E.t.sol.
contract RelayHandler {
    Vm private constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    bytes4 constant UPDATE_ROOT_SELECTOR = bytes4(keccak256("updateRoot(uint256,uint256,bytes32)"));
    bytes4 constant SET_ISSUER_PUBKEY_SELECTOR = bytes4(keccak256("setIssuerPubkey(uint64,uint256,uint256,bytes32)"));
    bytes4 constant SET_OPRF_KEY_SELECTOR = bytes4(keccak256("setOprfKey(uint160,uint256,uint256,bytes32)"));

    address public sourceProxy;
    address public satelliteProxy;
    address public gateway;
    address public owner;
    MockRegistry public registry;
    MockIssuerRegistry public issuerRegistry;
    MockOprfRegistry public oprfRegistry;
    RegistryHandler public registryHandler;

    /// @dev Total successful relays (propagate + gateway delivery).
    uint256 public totalRelays;
    /// @dev Total successful propagations (source chain extended).
    uint256 public totalPropagations;
    /// @dev True when the source has been propagated since the last relay.
    ///   Used by invariant checks to know whether source/satellite should be in sync.
    bool public sourceDirty;

    constructor(
        address sourceProxy_,
        address satelliteProxy_,
        address gateway_,
        address owner_,
        MockRegistry registry_,
        MockIssuerRegistry issuerRegistry_,
        MockOprfRegistry oprfRegistry_,
        RegistryHandler registryHandler_
    ) {
        sourceProxy = sourceProxy_;
        satelliteProxy = satelliteProxy_;
        gateway = gateway_;
        owner = owner_;
        registry = registry_;
        issuerRegistry = issuerRegistry_;
        oprfRegistry = oprfRegistry_;
        registryHandler = registryHandler_;
    }

    // ─── Fuzz targets ────────────────────────────────────────────────────────

    /// @notice Full cycle: build payload, propagate on source, relay through gateway to satellite.
    ///   `issuerCount` and `oprfCount` are bounded to registered IDs from the RegistryHandler.
    function propagateAndRelay(uint8 issuerCount, uint8 oprfCount) external {
        // Advance block so `blockhash(block.number - 1)` produces a unique value
        vm.roll(block.number + 1);

        (uint64[] memory issuerIds, uint160[] memory oprfIds) = _pickIds(issuerCount, oprfCount);

        // Build payload BEFORE propagation (detects diffs vs current source state)
        bytes memory payload = _buildPayload(issuerIds, oprfIds);

        // Propagate — may revert with NothingChanged if registries match source
        try WorldIDSource(sourceProxy).propagateState(issuerIds, oprfIds) {
            totalPropagations++;
        } catch {
            return;
        }

        // Read new chain head after propagation
        bytes32 chainHead = WorldIDSource(sourceProxy).KECCAK_CHAIN().head;

        // Relay through permissioned gateway
        _relay(chainHead, payload);

        totalRelays++;
        sourceDirty = false;
    }

    /// @notice Propagate without relaying. Useful for testing diverged source/satellite state.
    function propagateOnly(uint8 issuerCount, uint8 oprfCount) external {
        vm.roll(block.number + 1);

        (uint64[] memory issuerIds, uint160[] memory oprfIds) = _pickIds(issuerCount, oprfCount);

        try WorldIDSource(sourceProxy).propagateState(issuerIds, oprfIds) {
            totalPropagations++;
            sourceDirty = true;
        } catch {}
    }

    // ─── Internal helpers ────────────────────────────────────────────────────

    /// @dev Selects the first N registered IDs from the RegistryHandler's ghost arrays.
    function _pickIds(uint8 issuerCount, uint8 oprfCount)
        internal
        view
        returns (uint64[] memory issuerIds, uint160[] memory oprfIds)
    {
        uint64[] memory allIssuers = registryHandler.getRegisteredIssuerIds();
        uint160[] memory allOprfs = registryHandler.getRegisteredOprfIds();

        uint256 iLen = uint256(issuerCount) > allIssuers.length ? allIssuers.length : uint256(issuerCount);
        uint256 oLen = uint256(oprfCount) > allOprfs.length ? allOprfs.length : uint256(oprfCount);

        issuerIds = new uint64[](iLen);
        for (uint256 i; i < iLen; i++) {
            issuerIds[i] = allIssuers[i];
        }

        oprfIds = new uint160[](oLen);
        for (uint256 i; i < oLen; i++) {
            oprfIds[i] = allOprfs[i];
        }
    }

    /// @dev Builds the commitment payload by diffing registry state against source state.
    ///   This must be called BEFORE propagation so we see the same diffs the source will see.
    ///   Mirrors E2E.t.sol `_buildPayload` exactly.
    function _buildPayload(uint64[] memory issuerIds_, uint160[] memory oprfIds_)
        internal
        view
        returns (bytes memory)
    {
        bytes32 blockHash = blockhash(block.number - 1);
        bytes32 proofId = bytes32(block.number);

        uint256 count = 0;
        uint256 maxLen = 1 + issuerIds_.length + oprfIds_.length;
        Lib.Commitment[] memory commits = new Lib.Commitment[](maxLen);

        // Root diff
        uint256 root = registry.latestRoot();
        if (root != WorldIDSource(sourceProxy).LATEST_ROOT()) {
            commits[count++] = Lib.Commitment({
                blockHash: blockHash,
                data: abi.encodeWithSelector(UPDATE_ROOT_SELECTOR, root, block.timestamp, proofId)
            });
        }

        // Issuer diffs
        for (uint256 i; i < issuerIds_.length; i++) {
            IStateBridge.ProvenPubKeyInfo memory stored =
                WorldIDSource(sourceProxy).issuerSchemaIdToPubkeyAndProofId(issuerIds_[i]);
            MockIssuerRegistry.Pubkey memory key = issuerRegistry.issuerSchemaIdToPubkey(issuerIds_[i]);
            if (key.x != stored.pubKey.x || key.y != stored.pubKey.y) {
                commits[count++] = Lib.Commitment({
                    blockHash: blockHash,
                    data: abi.encodeWithSelector(SET_ISSUER_PUBKEY_SELECTOR, issuerIds_[i], key.x, key.y, proofId)
                });
            }
        }

        // OPRF diffs
        for (uint256 i; i < oprfIds_.length; i++) {
            IStateBridge.ProvenPubKeyInfo memory stored =
                WorldIDSource(sourceProxy).oprfKeyIdToPubkeyAndProofId(oprfIds_[i]);
            MockOprfRegistry.RegisteredOprfPublicKey memory key = oprfRegistry.getOprfPublicKeyAndEpoch(oprfIds_[i]);
            if (key.key.x != stored.pubKey.x || key.key.y != stored.pubKey.y) {
                commits[count++] = Lib.Commitment({
                    blockHash: blockHash,
                    data: abi.encodeWithSelector(SET_OPRF_KEY_SELECTOR, oprfIds_[i], key.key.x, key.key.y, proofId)
                });
            }
        }

        // Trim array to actual count
        assembly ("memory-safe") {
            mstore(commits, count)
        }

        return abi.encode(commits);
    }

    /// @dev Relays commitments through the permissioned gateway to the satellite.
    ///   Mirrors E2E.t.sol `_relay` exactly.
    function _relay(bytes32 chainHead, bytes memory commitPayload) internal {
        bytes4 attrSelector = bytes4(keccak256("chainHead(bytes32)"));
        bytes[] memory attributes = new bytes[](1);
        attributes[0] = abi.encodePacked(attrSelector, abi.encode(chainHead));

        bytes memory recipient = InteroperableAddress.formatEvmV1(block.chainid, satelliteProxy);

        vm.prank(owner);
        PermissionedGatewayAdapter(gateway).sendMessage(recipient, commitPayload, attributes);
    }
}
