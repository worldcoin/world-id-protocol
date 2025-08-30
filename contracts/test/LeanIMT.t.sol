// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {LeanIMT, LeanIMTData} from "../src/tree/LeanIMT.sol";
import {InternalLeanIMT} from "../src/tree/InternalLeanIMT.sol";
import {console} from "forge-std/console.sol";
import {TreeHelper} from "../src/TreeHelper.sol";

contract LeanIMTBench {
    using InternalLeanIMT for *;

    LeanIMTData internal t;

    function buildTree(uint256[] calldata leaves) external {
        InternalLeanIMT._insertMany(t, leaves);
    }

    function benchUpdate(uint256 index, uint256 oldLeaf, uint256 newLeaf, uint256[] calldata proof)
        external
        returns (uint256 gasUsed)
    {
        uint256 startGas = gasleft();
        InternalLeanIMT._update(t, index, oldLeaf, newLeaf, proof);
        gasUsed = startGas - gasleft();
    }
}

contract LeanIMTTest is Test {
    using LeanIMT for LeanIMTData;
    // Allow calling internal library directly to avoid external-call ABI costs in benchmarks
    using InternalLeanIMT for *;

    LeanIMTData public tree;
    LeanIMTData public tree10;

    function _fakeTree(LeanIMTData storage t, uint256 depth) internal {
        uint256[] memory sideNodes = new uint256[](depth);
        sideNodes[depth - 1] = TreeHelper.emptyNode(depth);
        t.initialize(depth, 1 << (depth - 1) + 1, sideNodes);
    }

    function setUp() public {
        _fakeTree(tree10, 30);
    }

    function test_InsertTree() public {
        uint256 leavesToInsert = 1000;
        uint256 gasStart = gasleft();
        for (uint256 i = 0; i < leavesToInsert; i++) {
            tree.insert(1337 + i);
        }
        uint256 gasEnd = gasleft();
        console.log("Gas used: %s", (gasStart - gasEnd) / leavesToInsert);
    }

    function test_InsertTree10() public {
        uint256 leavesToInsert = 1000;
        uint256 gasStart = gasleft();
        for (uint256 i = 0; i < leavesToInsert; i++) {
            tree10.insert(1337 + i);
        }
        uint256 gasEnd = gasleft();
        console.log("Gas used: %s", (gasStart - gasEnd) / leavesToInsert);
    }

    function test_InsertManyTree() public {
        uint256 leavesToInsert = 1000;
        uint256[] memory leaves = new uint256[](leavesToInsert);
        for (uint256 i = 0; i < leavesToInsert; i++) {
            leaves[i] = 1337 + i;
        }
        uint256 gasStart = gasleft();
        tree.insertMany(leaves);
        uint256 gasEnd = gasleft();
        console.log("Gas used: %s", (gasStart - gasEnd) / leavesToInsert);
    }

    function test_InsertManyTree10() public {
        uint256 leavesToInsert = 1000;
        uint256[] memory leaves = new uint256[](leavesToInsert);
        for (uint256 i = 0; i < leavesToInsert; i++) {
            leaves[i] = 1337 + i;
        }
        uint256 gasStart = gasleft();
        tree10.insertMany(leaves);
        uint256 gasEnd = gasleft();
        console.log("Gas used: %s", (gasStart - gasEnd) / leavesToInsert);
    }

    function test_UpdateTreeLarge() public {
        uint256 nLeaves = 2 ** 12;
        uint256[] memory leaves = new uint256[](nLeaves);
        for (uint256 i = 0; i < nLeaves; i++) {
            leaves[i] = i;
        }

        LeanIMTBench bench = new LeanIMTBench();
        bench.buildTree(leaves);

        uint256 totalGas = 0;
        uint256 nUpdates = 100;
        for (uint256 i = 0; i < nUpdates; i++) {
            uint256[] memory proof = TreeHelper.leanInclusionProof(leaves, i);
            uint256 g = bench.benchUpdate(i, leaves[i], 1337, proof);
            leaves[i] = 1337;
            totalGas += g;
        }
        console.log("Gas used per update (internal, 2^12): %s", totalGas / nUpdates);
    }
}
