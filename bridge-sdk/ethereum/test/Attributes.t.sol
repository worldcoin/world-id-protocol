// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Attributes} from "../src/core/gateways/Attributes.sol";

contract AttributesTest is Test {
    // ── Test-only selectors used as splitMem fixtures ────────
    bytes4 constant CHAIN_HEAD = bytes4(keccak256("chainHead(bytes32)"));
    bytes4 constant DISPUTE_GAME = bytes4(keccak256("disputeGame(uint32,bytes,bytes32[4])"));
    bytes4 constant WC_MPT_PROOF = bytes4(keccak256("wcMptProof(bytes[],bytes[])"));
    bytes4 constant ZK_PROOF = bytes4(keccak256("zkProof(bytes,bytes)"));
    bytes4 constant L1_MPT_PROOF = bytes4(keccak256("l1MptProof(bytes[],bytes[])"));

    // ── split: basic round-trip ────────────────────────────

    function test_split_bytes32() public pure {
        bytes32 value = keccak256("hello");
        bytes memory raw = abi.encodePacked(CHAIN_HEAD, abi.encode(value));

        (bytes4 sel, bytes memory data) = Attributes.splitMem(raw);

        assertEq(sel, CHAIN_HEAD);
        bytes32 decoded = abi.decode(data, (bytes32));
        assertEq(decoded, value);
    }

    function test_split_disputeGame() public pure {
        uint32 gameType = 1;
        bytes memory extraData = abi.encodePacked(uint256(12345));
        bytes32[4] memory preimage =
            [bytes32(uint256(1)), keccak256("state"), keccak256("msgPasser"), keccak256("blockHash")];

        bytes memory raw = abi.encodePacked(DISPUTE_GAME, abi.encode(gameType, extraData, preimage));

        (bytes4 sel, bytes memory data) = Attributes.splitMem(raw);

        assertEq(sel, DISPUTE_GAME);
        (uint32 gt, bytes memory ed, bytes32[4] memory decoded) = abi.decode(data, (uint32, bytes, bytes32[4]));
        assertEq(gt, gameType);
        assertEq(ed, extraData);
        assertEq(decoded[0], preimage[0]);
        assertEq(decoded[1], preimage[1]);
        assertEq(decoded[2], preimage[2]);
        assertEq(decoded[3], preimage[3]);
    }

    function test_split_dynamicBytesArrays() public pure {
        bytes[] memory acct = new bytes[](2);
        acct[0] = hex"aabbccdd";
        acct[1] = hex"11223344556677889900";

        bytes[] memory stor = new bytes[](1);
        stor[0] = hex"ff";

        bytes memory raw = abi.encodePacked(WC_MPT_PROOF, abi.encode(acct, stor));

        (bytes4 sel, bytes memory data) = Attributes.splitMem(raw);

        assertEq(sel, WC_MPT_PROOF);
        (bytes[] memory dAcct, bytes[] memory dStor) = abi.decode(data, (bytes[], bytes[]));
        assertEq(dAcct.length, 2);
        assertEq(dAcct[0], acct[0]);
        assertEq(dAcct[1], acct[1]);
        assertEq(dStor.length, 1);
        assertEq(dStor[0], stor[0]);
    }

    function test_split_twoDynamicBytes() public pure {
        bytes memory proof = hex"deadbeef";
        bytes memory pubvals = abi.encode(uint256(1), uint256(2));

        bytes memory raw = abi.encodePacked(ZK_PROOF, abi.encode(proof, pubvals));

        (bytes4 sel, bytes memory data) = Attributes.splitMem(raw);

        assertEq(sel, ZK_PROOF);
        (bytes memory dProof, bytes memory dPubvals) = abi.decode(data, (bytes, bytes));
        assertEq(dProof, proof);
        assertEq(dPubvals, pubvals);
    }

    function test_split_l1MptProof() public pure {
        bytes[] memory factoryAcct = new bytes[](3);
        factoryAcct[0] = hex"01";
        factoryAcct[1] = hex"0203";
        factoryAcct[2] = hex"040506";

        bytes[] memory factoryStor = new bytes[](1);
        factoryStor[0] = hex"aabb";

        bytes memory raw = abi.encodePacked(L1_MPT_PROOF, abi.encode(factoryAcct, factoryStor));

        (bytes4 sel, bytes memory data) = Attributes.splitMem(raw);

        assertEq(sel, L1_MPT_PROOF);
        (bytes[] memory dAcct, bytes[] memory dStor) = abi.decode(data, (bytes[], bytes[]));
        assertEq(dAcct.length, 3);
        assertEq(dAcct[0], factoryAcct[0]);
        assertEq(dAcct[1], factoryAcct[1]);
        assertEq(dAcct[2], factoryAcct[2]);
        assertEq(dStor.length, 1);
        assertEq(dStor[0], factoryStor[0]);
    }

    // ── split: edge cases ──────────────────────────────────

    function test_split_exactlyFourBytes() public pure {
        bytes memory raw = abi.encodePacked(CHAIN_HEAD);

        (bytes4 sel, bytes memory data) = Attributes.splitMem(raw);

        assertEq(sel, CHAIN_HEAD);
        assertEq(data.length, 0);
    }

    function test_split_revertsTooShort() public {
        bytes memory raw = hex"aabb";
        vm.expectRevert("Attribute too short");
        this.splitExternal(raw);
    }

    function test_split_revertsEmpty() public {
        bytes memory raw = hex"";
        vm.expectRevert("Attribute too short");
        this.splitExternal(raw);
    }

    // ── fuzz: round-trip for arbitrary payloads ────────────

    function testFuzz_split_roundTrip(bytes4 sel, bytes memory payload) public pure {
        bytes memory raw = abi.encodePacked(sel, payload);

        (bytes4 gotSel, bytes memory gotData) = Attributes.splitMem(raw);

        assertEq(gotSel, sel);
        assertEq(gotData, payload);
    }

    function testFuzz_split_selectorPreserved(bytes4 sel) public pure {
        bytes memory raw = abi.encodePacked(sel, abi.encode(uint256(999)));

        (bytes4 gotSel,) = Attributes.splitMem(raw);

        assertEq(gotSel, sel);
    }

    // ── compound gateway selectors match expected values ───

    function test_compoundSelectorValues() public pure {
        assertEq(Attributes.OWNED_GATEWAY_ATTRIBUTES, bytes4(keccak256("chainHead(bytes32)")));
        assertEq(
            Attributes.L1_GATEWAY_ATTRIBUTES,
            bytes4(keccak256("l1ProofAttributes(uint32,bytes,bytes32[4],bytes[],bytes[])"))
        );
        assertEq(
            Attributes.ZK_GATEWAY_ATTRIBUTES, bytes4(keccak256("zkProofGatewayAttributes(bytes,bytes,bytes[],bytes[])"))
        );
    }

    function test_compoundSelectorsAreDistinct() public pure {
        bytes4[3] memory sels =
            [Attributes.OWNED_GATEWAY_ATTRIBUTES, Attributes.L1_GATEWAY_ATTRIBUTES, Attributes.ZK_GATEWAY_ATTRIBUTES];

        for (uint256 i; i < sels.length; ++i) {
            for (uint256 j = i + 1; j < sels.length; ++j) {
                assertTrue(sels[i] != sels[j], "Selectors collide");
            }
        }
    }

    // ── helper for vm.expectRevert on library calls ────────

    function splitExternal(bytes memory attr) external pure returns (bytes4, bytes memory) {
        return Attributes.splitMem(attr);
    }
}
