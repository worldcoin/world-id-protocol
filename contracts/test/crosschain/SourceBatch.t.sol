// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm, VmSafe} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import {WorldIDSource} from "../../src/crosschain/WorldIDSource.sol";
import {WorldIDSourceV2} from "../../src/crosschain/WorldIDSourceV2.sol";
import {NothingChanged} from "../../src/crosschain/Error.sol";
import {WorldIDSatellite} from "../../src/crosschain/WorldIDSatellite.sol";
import {PermissionedGatewayAdapter} from "../../src/crosschain/adapters/PermissionedGatewayAdapter.sol";
import {IStateBridge} from "../../src/crosschain/interfaces/IStateBridge.sol";
import {Lib} from "../../src/crosschain/lib/Lib.sol";
import {Verifier} from "../../src/core/Verifier.sol";
import {MockRegistry, MockIssuerRegistry, MockOprfRegistry} from "./helpers/Mocks.sol";

contract SourceBatchTest is Test {
    MockRegistry internal registry;
    MockIssuerRegistry internal issuerRegistry;
    MockOprfRegistry internal oprfRegistry;
    WorldIDSource internal source;
    WorldIDSatellite internal satellite;
    PermissionedGatewayAdapter internal gateway;

    function setUp() public {
        registry = new MockRegistry();
        issuerRegistry = new MockIssuerRegistry();
        oprfRegistry = new MockOprfRegistry();
        issuerRegistry.setPubkey(1, 11, 22);
        oprfRegistry.setKey(1, 33, 44);

        IStateBridge.InitConfig memory config = IStateBridge.InitConfig({
            name: "World ID Bridge", version: "1", owner: address(this), authorizedGateways: new address[](0)
        });
        WorldIDSource implementation =
            new WorldIDSource(address(registry), address(issuerRegistry), address(oprfRegistry));
        source = WorldIDSource(
            address(new ERC1967Proxy(address(implementation), abi.encodeCall(WorldIDSource.initialize, (config))))
        );
        WorldIDSatellite satelliteImplementation = new WorldIDSatellite(address(new Verifier()), 3600, 30, 7200);
        satellite = WorldIDSatellite(
            address(
                new ERC1967Proxy(
                    address(satelliteImplementation), abi.encodeCall(WorldIDSatellite.initialize, (config))
                )
            )
        );
        gateway = new PermissionedGatewayAdapter(address(this), address(satellite), address(source), 480);
        satellite.addGateway(address(gateway));
    }

    function test_v1DuplicateOprfKeysAmplifySingleEvent() public {
        uint160[] memory ids = new uint160[](1000);
        for (uint256 index; index < ids.length; ++index) {
            ids[index] = 1;
        }
        vm.recordLogs();
        uint256 sourceGasBefore = gasleft();
        source.propagateState(new uint64[](0), ids);
        uint256 sourceGas = sourceGasBefore - gasleft();
        bytes memory payload = _sourcePayload();
        Lib.Commitment[] memory commits = abi.decode(payload, (Lib.Commitment[]));
        assertEq(commits.length, ids.length + 1);
        assertEq(commits[1].data, commits[ids.length].data);

        uint256 destinationGasBefore = gasleft();
        _relay(source.KECCAK_CHAIN().head, payload);
        uint256 destinationGas = destinationGasBefore - gasleft();
        emit log_named_uint("source execution gas", sourceGas);
        emit log_named_uint("destination execution gas", destinationGas);
        bytes memory sourceCalldata = abi.encodeCall(WorldIDSource.propagateState, (new uint64[](0), ids));
        if (!vm.isContext(VmSafe.ForgeContext.Coverage)) {
            assertLt(sourceGas + 21_000 + _calldataGas(sourceCalldata), 16_777_216);
            assertGt(destinationGas, 16_777_216);
        }
    }

    function test_v2RejectsRepeatedPendingKeys() public {
        _upgrade();
        uint64[] memory issuerIds = new uint64[](32);
        uint160[] memory oprfIds = new uint160[](32);
        for (uint256 index; index < 32; ++index) {
            issuerIds[index] = 1;
            oprfIds[index] = 1;
        }
        vm.recordLogs();
        vm.expectRevert(WorldIDSourceV2.TooManyKeyUpdates.selector);
        source.propagateState(issuerIds, oprfIds);
        assertEq(vm.getRecordedLogs().length, 0);
        assertEq(source.KECCAK_CHAIN().length, 0);
        assertEq(source.LATEST_ROOT(), 0);
        assertEq(source.issuerSchemaIdToPubkeyAndProofId(1).pubKey.x, 0);
        assertEq(source.oprfKeyIdToPubkeyAndProofId(1).pubKey.x, 0);
    }

    function testFuzz_v2RejectsOversizedInput(uint8 issuerCount, uint8 oprfCount) public {
        vm.assume(uint256(issuerCount) + uint256(oprfCount) > 63);
        _upgrade();
        vm.expectRevert(WorldIDSourceV2.TooManyKeyUpdates.selector);
        source.propagateState(new uint64[](issuerCount), new uint160[](oprfCount));
    }

    function testFuzz_v2MaximumBatchFitsDestination(uint8 issuerCount) public {
        issuerCount = uint8(bound(issuerCount, 0, 63));
        _upgrade();
        uint64[] memory issuerIds = new uint64[](issuerCount);
        uint160[] memory oprfIds = new uint160[](63 - issuerCount);
        for (uint256 index; index < issuerIds.length; ++index) {
            issuerIds[index] = uint64(index + 1);
            issuerRegistry.setPubkey(issuerIds[index], type(uint256).max, type(uint256).max);
        }
        for (uint256 index; index < oprfIds.length; ++index) {
            oprfIds[index] = uint160(index + 1);
            oprfRegistry.setKey(oprfIds[index], type(uint256).max, type(uint256).max);
        }
        vm.recordLogs();
        vm.prank(makeAddr("permissionlessCaller"));
        source.propagateState(issuerIds, oprfIds);
        bytes memory payload = _sourcePayload();
        assertEq(abi.decode(payload, (Lib.Commitment[])).length, 64);
        uint256 gasBefore = gasleft();
        _relay(source.KECCAK_CHAIN().head, payload);
        uint256 deliveryGas = gasBefore - gasleft();
        assertLt(deliveryGas + 21_000 + 16 * (payload.length + 1024), 8_000_000);
        assertEq(satellite.KECCAK_CHAIN().head, source.KECCAK_CHAIN().head);
        assertEq(satellite.KECCAK_CHAIN().length, 64);
        vm.expectRevert(NothingChanged.selector);
        source.propagateState(issuerIds, oprfIds);
    }

    function test_v2RepeatedIdsStayWithinLimit() public {
        _upgrade();
        uint160[] memory oprfIds = new uint160[](63);
        for (uint256 index; index < oprfIds.length; ++index) {
            oprfIds[index] = 1;
        }
        vm.recordLogs();
        source.propagateState(new uint64[](0), oprfIds);
        bytes memory payload = _sourcePayload();
        assertEq(abi.decode(payload, (Lib.Commitment[])).length, 64);
        _relay(source.KECCAK_CHAIN().head, payload);
        assertEq(satellite.KECCAK_CHAIN().head, source.KECCAK_CHAIN().head);
    }

    function test_v2UpgradePreservesStateAndExtendsChain() public {
        uint64[] memory issuerIds = new uint64[](1);
        issuerIds[0] = 1;
        uint160[] memory oprfIds = new uint160[](1);
        oprfIds[0] = 1;
        vm.recordLogs();
        source.propagateState(issuerIds, oprfIds);
        _relay(source.KECCAK_CHAIN().head, _sourcePayload());
        bytes32 head = source.KECCAK_CHAIN().head;
        _upgrade();
        assertEq(source.VERSION(), 2);
        assertEq(source.KECCAK_CHAIN().head, head);
        assertEq(source.KECCAK_CHAIN().length, 3);
        assertEq(source.owner(), address(this));
        assertEq(source.LATEST_ROOT(), registry.latestRoot());
        assertEq(source.issuerSchemaIdToPubkeyAndProofId(1).pubKey.x, 11);
        assertEq(source.oprfKeyIdToPubkeyAndProofId(1).pubKey.x, 33);
        registry.setLatestRoot(999);
        vm.recordLogs();
        source.propagateState(new uint64[](0), new uint160[](0));
        _relay(source.KECCAK_CHAIN().head, _sourcePayload());
        assertEq(satellite.KECCAK_CHAIN().length, 4);
        assertEq(satellite.LATEST_ROOT(), 999);
        vm.warp(block.timestamp + 7200);
        assertTrue(satellite.isValidRoot(999));
    }

    function _upgrade() internal {
        WorldIDSourceV2 implementation =
            new WorldIDSourceV2(address(registry), address(issuerRegistry), address(oprfRegistry));
        source.upgradeToAndCall(address(implementation), "");
    }

    function _sourcePayload() internal returns (bytes memory) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].emitter, address(source));
        return abi.decode(logs[0].data, (bytes));
    }

    function _relay(bytes32 head, bytes memory payload) internal {
        bytes[] memory attributes = new bytes[](1);
        attributes[0] = abi.encodeWithSelector(gateway.ATTRIBUTE(), head);
        gateway.sendMessage(InteroperableAddress.formatEvmV1(block.chainid, address(satellite)), payload, attributes);
    }

    function _calldataGas(bytes memory data) internal pure returns (uint256 gasCost) {
        for (uint256 index; index < data.length; ++index) {
            gasCost += data[index] == 0 ? 4 : 16;
        }
    }
}
