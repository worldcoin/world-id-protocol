// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {BinaryIMT, BinaryIMTData} from "../src/libraries/BinaryIMT.sol";
import {FullStorageBinaryIMT, FullBinaryIMTData} from "../src/libraries/FullStorageBinaryIMT.sol";

/// @title Gas benchmark for the current (proof-based) BinaryIMT implementation.
contract GasBenchmarkCurrent is Test {
    using BinaryIMT for BinaryIMTData;
    using FullStorageBinaryIMT for FullBinaryIMTData;

    BinaryIMTData public tree;
    FullBinaryIMTData public fullStorageTree;

    function setUp() public {
        tree.initWithDefaultZeroes(30);
        fullStorageTree.initWithDefaultZeroes(30);
    }

    // ---------------------------------------------------------------
    //  Single insert benchmarks
    // ---------------------------------------------------------------

    function test_current_insert_first() public {
        uint256 g0 = gasleft();
        tree.insert(1337);
        uint256 g1 = gasleft();
        console.log("[CURRENT] insert first leaf: %s gas", g0 - g1);
    }

    function test_current_insert_after100() public {
        for (uint256 i = 0; i < 100; i++) {
            tree.insert(1000 + i);
        }
        uint256 g0 = gasleft();
        tree.insert(9999);
        uint256 g1 = gasleft();
        console.log("[CURRENT] insert leaf #101: %s gas", g0 - g1);
    }

    function test_current_insert_1000_avg() public {
        uint256 g0 = gasleft();
        for (uint256 i = 0; i < 1000; i++) {
            tree.insert(1337 + i);
        }
        uint256 g1 = gasleft();
        console.log("[CURRENT] insert 1000 avg: %s gas/leaf", (g0 - g1) / 1000);
    }

    // ---------------------------------------------------------------
    //  insertMany benchmarks
    // ---------------------------------------------------------------

    function test_current_insertMany_10() public {
        uint256[] memory leaves = new uint256[](10);
        for (uint256 i = 0; i < 10; i++) {
            leaves[i] = 1337 + i;
        }
        uint256 g0 = gasleft();
        tree.insertMany(leaves);
        uint256 g1 = gasleft();
        console.log("[CURRENT] insertMany(10) avg: %s gas/leaf", (g0 - g1) / 10);
    }

    function test_current_insertMany_100() public {
        uint256[] memory leaves = new uint256[](100);
        for (uint256 i = 0; i < 100; i++) {
            leaves[i] = 1337 + i;
        }
        uint256 g0 = gasleft();
        tree.insertMany(leaves);
        uint256 g1 = gasleft();
        console.log("[CURRENT] insertMany(100) avg: %s gas/leaf", (g0 - g1) / 100);
    }

    function test_current_insertMany_1000() public {
        uint256[] memory leaves = new uint256[](1000);
        for (uint256 i = 0; i < 1000; i++) {
            leaves[i] = 1337 + i;
        }
        uint256 g0 = gasleft();
        tree.insertMany(leaves);
        uint256 g1 = gasleft();
        console.log("[CURRENT] insertMany(1000) avg: %s gas/leaf", (g0 - g1) / 1000);
    }

    // ---------------------------------------------------------------
    //  Update benchmarks
    // ---------------------------------------------------------------

    function _emptyProof() private pure returns (uint256[] memory) {
        uint256[] memory proof = new uint256[](30);
        for (uint256 i = 0; i < 30; i++) {
            proof[i] = BinaryIMT.defaultZero(i);
        }
        return proof;
    }

    function test_current_update_leaf0_singleLeafTree() public {
        tree.insert(1337);
        uint256[] memory proof = _emptyProof();
        uint256 g0 = gasleft();
        tree.update(0, 1337, 1338, proof);
        uint256 g1 = gasleft();
        console.log("[CURRENT] update leaf 0 (1 leaf tree): %s gas", g0 - g1);
    }

    function test_current_update_leaf0_after100() public {
        // Use full-storage tree only to derive a valid proof for the current tree.
        for (uint256 i = 0; i < 100; i++) {
            uint256 leaf = 1000 + i;
            tree.insert(leaf);
            fullStorageTree.insert(leaf);
        }

        uint256[] memory proof = fullStorageTree.getProof(0);
        uint256 g0 = gasleft();
        tree.update(0, 1000, 9999, proof);
        uint256 g1 = gasleft();
        console.log("[CURRENT] update leaf 0 (100-leaf tree): %s gas", g0 - g1);
    }

    function test_current_update_2leaf_tree() public {
        tree.insert(1337);
        tree.insert(1338);
        // In a 2-leaf tree, leaf 0 sibling at level 0 is leaf 1 (1338)
        // All other siblings are default zeros
        uint256[] memory proof = _emptyProof();
        proof[0] = 1338; // sibling at level 0
        uint256 g0 = gasleft();
        tree.update(0, 1337, 9999, proof);
        uint256 g1 = gasleft();
        console.log("[CURRENT] update leaf 0 (2-leaf tree): %s gas", g0 - g1);
    }
}
