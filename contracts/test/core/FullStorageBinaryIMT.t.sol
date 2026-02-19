// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {BinaryIMT, BinaryIMTData} from "../../src/core/libraries/BinaryIMT.sol";
import {FullStorageBinaryIMT, FullBinaryIMTData} from "../../src/core/libraries/FullStorageBinaryIMT.sol";

/// @title Correctness tests: the full-storage tree must produce identical roots
///        to the original proof-based tree for the same sequence of operations.
contract FullStorageBinaryIMTCorrectnessTest is Test {
    using BinaryIMT for BinaryIMTData;
    using FullStorageBinaryIMT for FullBinaryIMTData;

    BinaryIMTData public refTree;
    FullBinaryIMTData public fsTree;

    function setUp() public {
        refTree.initWithDefaultZeroes(30);
        fsTree.initWithDefaultZeroes(30);
    }

    function test_roots_match_after_single_insert() public {
        refTree.insert(1337);
        fsTree.insert(1337);
        assertEq(refTree.root, fsTree.root, "roots differ after single insert");
    }

    function test_roots_match_after_10_inserts() public {
        for (uint256 i = 0; i < 10; i++) {
            refTree.insert(1000 + i);
            fsTree.insert(1000 + i);
            assertEq(refTree.root, fsTree.root, "roots differ");
        }
    }

    function test_roots_match_after_100_inserts() public {
        for (uint256 i = 0; i < 100; i++) {
            refTree.insert(1000 + i);
            fsTree.insert(1000 + i);
        }
        assertEq(refTree.root, fsTree.root, "roots differ after 100 inserts");
    }

    function test_roots_match_insertMany_10() public {
        uint256[] memory leaves = new uint256[](10);
        for (uint256 i = 0; i < 10; i++) {
            leaves[i] = 1337 + i;
            refTree.insert(leaves[i]);
        }
        fsTree.insertMany(leaves);
        assertEq(refTree.root, fsTree.root, "roots differ after insertMany(10)");
    }

    function test_roots_match_insertMany_100() public {
        uint256[] memory leaves = new uint256[](100);
        for (uint256 i = 0; i < 100; i++) {
            leaves[i] = 1337 + i;
            refTree.insert(leaves[i]);
        }
        fsTree.insertMany(leaves);
        assertEq(refTree.root, fsTree.root, "roots differ after insertMany(100)");
    }

    function test_roots_match_insertMany_1000() public {
        uint256[] memory leaves = new uint256[](1000);
        for (uint256 i = 0; i < 1000; i++) {
            leaves[i] = 1337 + i;
            refTree.insert(leaves[i]);
        }
        fsTree.insertMany(leaves);
        assertEq(refTree.root, fsTree.root, "roots differ after insertMany(1000)");
    }

    function test_update_matches_reference() public {
        // Insert two leaves
        refTree.insert(1337);
        refTree.insert(1338);
        fsTree.insert(1337);
        fsTree.insert(1338);
        assertEq(refTree.root, fsTree.root, "roots differ before update");

        // Update leaf 0: reference needs a proof, full-storage does not
        uint256[] memory proof = new uint256[](30);
        proof[0] = 1338; // sibling at level 0
        for (uint256 i = 1; i < 30; i++) {
            proof[i] = BinaryIMT.defaultZero(i);
        }
        refTree.update(0, 1337, 9999, proof);
        fsTree.update(0, 1337, 9999);
        assertEq(refTree.root, fsTree.root, "roots differ after update");
    }

    function test_update_leaf1_matches_reference() public {
        refTree.insert(1337);
        refTree.insert(1338);
        fsTree.insert(1337);
        fsTree.insert(1338);

        // Update leaf 1: proof sibling at level 0 is leaf 0
        uint256[] memory proof = new uint256[](30);
        proof[0] = 1337;
        for (uint256 i = 1; i < 30; i++) {
            proof[i] = BinaryIMT.defaultZero(i);
        }
        refTree.update(1, 1338, 7777, proof);
        fsTree.update(1, 1338, 7777);
        assertEq(refTree.root, fsTree.root, "roots differ after update leaf 1");
    }

    function test_getProof_returns_correct_siblings() public {
        fsTree.insert(1337);
        fsTree.insert(1338);

        uint256[] memory proof = fsTree.getProof(0);
        assertEq(proof.length, 30);
        assertEq(proof[0], 1338, "sibling of leaf 0 at level 0 should be leaf 1");
        for (uint256 i = 1; i < 30; i++) {
            assertEq(proof[i], BinaryIMT.defaultZero(i), "higher siblings should be default zeros");
        }
    }

    function test_multiple_updates_correctness() public {
        // Insert 4 leaves
        fsTree.insert(100);
        fsTree.insert(200);
        fsTree.insert(300);
        fsTree.insert(400);

        refTree.insert(100);
        refTree.insert(200);
        refTree.insert(300);
        refTree.insert(400);

        assertEq(refTree.root, fsTree.root, "roots differ before updates");

        // Update leaf 2 (300 -> 350)
        {
            uint256[] memory proof = fsTree.getProof(2);
            refTree.update(2, 300, 350, proof);
        }
        fsTree.update(2, 300, 350);
        assertEq(refTree.root, fsTree.root, "roots differ after update leaf 2");

        // Update leaf 0 (100 -> 150)
        {
            uint256[] memory proof = fsTree.getProof(0);
            refTree.update(0, 100, 150, proof);
        }
        fsTree.update(0, 100, 150);
        assertEq(refTree.root, fsTree.root, "roots differ after update leaf 0");
    }

    function test_insert_after_update() public {
        fsTree.insert(100);
        fsTree.insert(200);
        refTree.insert(100);
        refTree.insert(200);

        // Update leaf 0
        {
            uint256[] memory proof = fsTree.getProof(0);
            refTree.update(0, 100, 150, proof);
        }
        fsTree.update(0, 100, 150);
        assertEq(refTree.root, fsTree.root, "roots differ after update");

        // Insert a new leaf
        refTree.insert(300);
        fsTree.insert(300);
        assertEq(refTree.root, fsTree.root, "roots differ after insert post-update");
    }
}

/// @title Gas benchmarks for the full-storage implementation.
contract GasBenchmarkFullStorage is Test {
    using FullStorageBinaryIMT for FullBinaryIMTData;

    FullBinaryIMTData public tree;

    function setUp() public {
        tree.initWithDefaultZeroes(30);
    }

    // ---------------------------------------------------------------
    //  Single insert benchmarks
    // ---------------------------------------------------------------

    function test_fs_insert_first() public {
        uint256 g0 = gasleft();
        tree.insert(1337);
        uint256 g1 = gasleft();
        console.log("[FULL-STORAGE] insert first leaf: %s gas", g0 - g1);
    }

    function test_fs_insert_after100() public {
        for (uint256 i = 0; i < 100; i++) {
            tree.insert(1000 + i);
        }
        uint256 g0 = gasleft();
        tree.insert(9999);
        uint256 g1 = gasleft();
        console.log("[FULL-STORAGE] insert leaf #101: %s gas", g0 - g1);
    }

    function test_fs_insert_1000_avg() public {
        uint256 g0 = gasleft();
        for (uint256 i = 0; i < 1000; i++) {
            tree.insert(1337 + i);
        }
        uint256 g1 = gasleft();
        console.log("[FULL-STORAGE] insert 1000 avg: %s gas/leaf", (g0 - g1) / 1000);
    }

    // ---------------------------------------------------------------
    //  insertMany benchmarks
    // ---------------------------------------------------------------

    function test_fs_insertMany_10() public {
        uint256[] memory leaves = new uint256[](10);
        for (uint256 i = 0; i < 10; i++) {
            leaves[i] = 1337 + i;
        }
        uint256 g0 = gasleft();
        tree.insertMany(leaves);
        uint256 g1 = gasleft();
        console.log("[FULL-STORAGE] insertMany(10) avg: %s gas/leaf", (g0 - g1) / 10);
    }

    function test_fs_insertMany_100() public {
        uint256[] memory leaves = new uint256[](100);
        for (uint256 i = 0; i < 100; i++) {
            leaves[i] = 1337 + i;
        }
        uint256 g0 = gasleft();
        tree.insertMany(leaves);
        uint256 g1 = gasleft();
        console.log("[FULL-STORAGE] insertMany(100) avg: %s gas/leaf", (g0 - g1) / 100);
    }

    function test_fs_insertMany_1000() public {
        uint256[] memory leaves = new uint256[](1000);
        for (uint256 i = 0; i < 1000; i++) {
            leaves[i] = 1337 + i;
        }
        uint256 g0 = gasleft();
        tree.insertMany(leaves);
        uint256 g1 = gasleft();
        console.log("[FULL-STORAGE] insertMany(1000) avg: %s gas/leaf", (g0 - g1) / 1000);
    }

    // ---------------------------------------------------------------
    //  Update benchmarks (NO proof needed!)
    // ---------------------------------------------------------------

    function test_fs_update_leaf0_singleLeafTree() public {
        tree.insert(1337);
        uint256 g0 = gasleft();
        tree.update(0, 1337, 1338);
        uint256 g1 = gasleft();
        console.log("[FULL-STORAGE] update leaf 0 (1-leaf tree): %s gas", g0 - g1);
    }

    function test_fs_update_2leaf_tree() public {
        tree.insert(1337);
        tree.insert(1338);
        uint256 g0 = gasleft();
        tree.update(0, 1337, 9999);
        uint256 g1 = gasleft();
        console.log("[FULL-STORAGE] update leaf 0 (2-leaf tree): %s gas", g0 - g1);
    }

    function test_fs_update_after100_leaf0() public {
        for (uint256 i = 0; i < 100; i++) {
            tree.insert(1000 + i);
        }
        uint256 g0 = gasleft();
        tree.update(0, 1000, 9999);
        uint256 g1 = gasleft();
        console.log("[FULL-STORAGE] update leaf 0 (100-leaf tree): %s gas", g0 - g1);
    }

    function test_fs_update_after100_leaf50() public {
        for (uint256 i = 0; i < 100; i++) {
            tree.insert(1000 + i);
        }
        uint256 g0 = gasleft();
        tree.update(50, 1050, 9999);
        uint256 g1 = gasleft();
        console.log("[FULL-STORAGE] update leaf 50 (100-leaf tree): %s gas", g0 - g1);
    }

    function test_fs_update_after100_leaf99() public {
        for (uint256 i = 0; i < 100; i++) {
            tree.insert(1000 + i);
        }
        uint256 g0 = gasleft();
        tree.update(99, 1099, 9999);
        uint256 g1 = gasleft();
        console.log("[FULL-STORAGE] update leaf 99 (100-leaf tree): %s gas", g0 - g1);
    }

    // ---------------------------------------------------------------
    //  Sequential updates (simulating batched ops in a multicall)
    // ---------------------------------------------------------------

    function test_fs_sequential_updates_3() public {
        tree.insert(100);
        tree.insert(200);
        tree.insert(300);

        uint256 g0 = gasleft();
        tree.update(0, 100, 101);
        tree.update(1, 200, 201);
        tree.update(2, 300, 301);
        uint256 g1 = gasleft();
        console.log("[FULL-STORAGE] 3 sequential updates: %s gas total, %s avg", g0 - g1, (g0 - g1) / 3);
    }
}
