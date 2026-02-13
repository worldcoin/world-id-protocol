// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {BinaryIMT, BinaryIMTData} from "../src/libraries/BinaryIMT.sol";
import {FullStorageBinaryIMT, FullBinaryIMTData} from "../src/libraries/FullStorageBinaryIMT.sol";

/// @title Cold-context gas benchmarks.
///
/// setUp() performs tree population so that every test_* function begins
/// with a FRESH EVM execution context (all storage slots are cold).
/// This simulates the realistic cost of a standalone transaction.
///
/// NOTE on calling conventions:
///   - BinaryIMT is a `public` library → called via delegatecall
///   - FullStorageBinaryIMT is an `internal` library → inlined
///   The delegatecall overhead is ~2600 gas. We report raw numbers and
///   note the difference.

// =====================================================================
// Cold single-insert benchmarks (tree already has 100 leaves)
// =====================================================================

contract ColdInsertBench is Test {
    using BinaryIMT for BinaryIMTData;
    using FullStorageBinaryIMT for FullBinaryIMTData;

    BinaryIMTData public currentTree;
    FullBinaryIMTData public fsTree;

    function setUp() public {
        currentTree.initWithDefaultZeroes(30);
        fsTree.initWithDefaultZeroes(30);
        for (uint256 i = 0; i < 100; i++) {
            currentTree.insert(1000 + i);
            fsTree.insert(1000 + i);
        }
    }

    function test_cold_current_insert() public {
        uint256 g0 = gasleft();
        currentTree.insert(9999);
        uint256 g1 = gasleft();
        console.log("[COLD] current insert (after 100 leaves): %s gas", g0 - g1);
    }

    function test_cold_fs_insert() public {
        uint256 g0 = gasleft();
        fsTree.insert(9999);
        uint256 g1 = gasleft();
        console.log("[COLD] full-storage insert (after 100 leaves): %s gas", g0 - g1);
    }
}

// =====================================================================
// Cold insertMany benchmarks (empty tree)
// =====================================================================

contract ColdInsertManyBench is Test {
    using BinaryIMT for BinaryIMTData;
    using FullStorageBinaryIMT for FullBinaryIMTData;

    BinaryIMTData public currentTree;
    FullBinaryIMTData public fsTree;

    function setUp() public {
        currentTree.initWithDefaultZeroes(30);
        fsTree.initWithDefaultZeroes(30);
    }

    // --- insertMany(10) ---

    function test_cold_current_insertMany_10() public {
        uint256[] memory leaves = new uint256[](10);
        for (uint256 i = 0; i < 10; i++) {
            leaves[i] = 1337 + i;
        }
        uint256 g0 = gasleft();
        currentTree.insertMany(leaves);
        uint256 g1 = gasleft();
        console.log("[COLD] current insertMany(10) total: %s gas, avg: %s gas/leaf", g0 - g1, (g0 - g1) / 10);
    }

    function test_cold_fs_insertMany_10() public {
        uint256[] memory leaves = new uint256[](10);
        for (uint256 i = 0; i < 10; i++) {
            leaves[i] = 1337 + i;
        }
        uint256 g0 = gasleft();
        fsTree.insertMany(leaves);
        uint256 g1 = gasleft();
        console.log("[COLD] fs insertMany(10) total: %s gas, avg: %s gas/leaf", g0 - g1, (g0 - g1) / 10);
    }

    // --- insertMany(100) ---

    function test_cold_current_insertMany_100() public {
        uint256[] memory leaves = new uint256[](100);
        for (uint256 i = 0; i < 100; i++) {
            leaves[i] = 1337 + i;
        }
        uint256 g0 = gasleft();
        currentTree.insertMany(leaves);
        uint256 g1 = gasleft();
        console.log("[COLD] current insertMany(100) total: %s gas, avg: %s gas/leaf", g0 - g1, (g0 - g1) / 100);
    }

    function test_cold_fs_insertMany_100() public {
        uint256[] memory leaves = new uint256[](100);
        for (uint256 i = 0; i < 100; i++) {
            leaves[i] = 1337 + i;
        }
        uint256 g0 = gasleft();
        fsTree.insertMany(leaves);
        uint256 g1 = gasleft();
        console.log("[COLD] fs insertMany(100) total: %s gas, avg: %s gas/leaf", g0 - g1, (g0 - g1) / 100);
    }

    // --- insertMany(1000) ---

    function test_cold_current_insertMany_1000() public {
        uint256[] memory leaves = new uint256[](1000);
        for (uint256 i = 0; i < 1000; i++) {
            leaves[i] = 1337 + i;
        }
        uint256 g0 = gasleft();
        currentTree.insertMany(leaves);
        uint256 g1 = gasleft();
        console.log("[COLD] current insertMany(1000) total: %s gas, avg: %s gas/leaf", g0 - g1, (g0 - g1) / 1000);
    }

    function test_cold_fs_insertMany_1000() public {
        uint256[] memory leaves = new uint256[](1000);
        for (uint256 i = 0; i < 1000; i++) {
            leaves[i] = 1337 + i;
        }
        uint256 g0 = gasleft();
        fsTree.insertMany(leaves);
        uint256 g1 = gasleft();
        console.log("[COLD] fs insertMany(1000) total: %s gas, avg: %s gas/leaf", g0 - g1, (g0 - g1) / 1000);
    }
}

// =====================================================================
// Cold update benchmarks (tree has 100 leaves, populated in setUp)
// =====================================================================

contract ColdUpdateBench is Test {
    using BinaryIMT for BinaryIMTData;
    using FullStorageBinaryIMT for FullBinaryIMTData;

    BinaryIMTData public currentTree;
    FullBinaryIMTData public fsTree;

    // Store the proof for leaf 0 in setUp so test can load it
    uint256[30] public storedProof;

    function setUp() public {
        currentTree.initWithDefaultZeroes(30);
        fsTree.initWithDefaultZeroes(30);

        for (uint256 i = 0; i < 100; i++) {
            currentTree.insert(1000 + i);
            fsTree.insert(1000 + i);
        }

        // Generate proof for leaf 0 from the full-storage tree
        uint256[] memory proof = fsTree.getProof(0);
        for (uint256 i = 0; i < 30; i++) {
            storedProof[i] = proof[i];
        }
    }

    function test_cold_current_update_leaf0() public {
        // Load proof from storage into memory BEFORE measurement.
        // The cost of reading storedProof[] is NOT included in the benchmark.
        // In production, this data comes from calldata (paid separately in tx gas).
        uint256[] memory proof = new uint256[](30);
        for (uint256 i = 0; i < 30; i++) {
            proof[i] = storedProof[i];
        }

        uint256 g0 = gasleft();
        currentTree.update(0, 1000, 9999, proof);
        uint256 g1 = gasleft();
        console.log("[COLD] current update leaf 0 (100-leaf tree): %s gas", g0 - g1);
    }

    function test_cold_fs_update_leaf0() public {
        uint256 g0 = gasleft();
        fsTree.update(0, 1000, 9999);
        uint256 g1 = gasleft();
        console.log("[COLD] fs update leaf 0 (100-leaf tree): %s gas", g0 - g1);
    }

    function test_cold_current_update_leaf50() public {
        // For leaf 50, we need its proof. Generate from fsTree.
        // This warms up fsTree's slots, but we're only measuring currentTree.
        uint256[] memory proof = fsTree.getProof(50);

        uint256 g0 = gasleft();
        currentTree.update(50, 1050, 9999, proof);
        uint256 g1 = gasleft();
        console.log("[COLD] current update leaf 50 (100-leaf tree): %s gas", g0 - g1);
    }

    function test_cold_fs_update_leaf50() public {
        uint256 g0 = gasleft();
        fsTree.update(50, 1050, 9999);
        uint256 g1 = gasleft();
        console.log("[COLD] fs update leaf 50 (100-leaf tree): %s gas", g0 - g1);
    }
}

// =====================================================================
// Cold update: 1000-leaf tree (more realistic tree size)
// =====================================================================

contract ColdUpdate1000Bench is Test {
    using BinaryIMT for BinaryIMTData;
    using FullStorageBinaryIMT for FullBinaryIMTData;

    BinaryIMTData public currentTree;
    FullBinaryIMTData public fsTree;

    function setUp() public {
        currentTree.initWithDefaultZeroes(30);
        fsTree.initWithDefaultZeroes(30);

        uint256[] memory leaves = new uint256[](1000);
        for (uint256 i = 0; i < 1000; i++) {
            leaves[i] = 1000 + i;
        }
        currentTree.insertMany(leaves);
        fsTree.insertMany(leaves);
    }

    function test_cold_current_update_leaf0_1000tree() public {
        uint256[] memory proof = fsTree.getProof(0);

        uint256 g0 = gasleft();
        currentTree.update(0, 1000, 9999, proof);
        uint256 g1 = gasleft();
        console.log("[COLD] current update leaf 0 (1000-leaf tree): %s gas", g0 - g1);
    }

    function test_cold_fs_update_leaf0_1000tree() public {
        uint256 g0 = gasleft();
        fsTree.update(0, 1000, 9999);
        uint256 g1 = gasleft();
        console.log("[COLD] fs update leaf 0 (1000-leaf tree): %s gas", g0 - g1);
    }

    function test_cold_current_update_leaf500_1000tree() public {
        uint256[] memory proof = fsTree.getProof(500);

        uint256 g0 = gasleft();
        currentTree.update(500, 1500, 9999, proof);
        uint256 g1 = gasleft();
        console.log("[COLD] current update leaf 500 (1000-leaf tree): %s gas", g0 - g1);
    }

    function test_cold_fs_update_leaf500_1000tree() public {
        uint256 g0 = gasleft();
        fsTree.update(500, 1500, 9999);
        uint256 g1 = gasleft();
        console.log("[COLD] fs update leaf 500 (1000-leaf tree): %s gas", g0 - g1);
    }

    function test_cold_current_update_leaf999_1000tree() public {
        uint256[] memory proof = fsTree.getProof(999);

        uint256 g0 = gasleft();
        currentTree.update(999, 1999, 9999, proof);
        uint256 g1 = gasleft();
        console.log("[COLD] current update leaf 999 (1000-leaf tree): %s gas", g0 - g1);
    }

    function test_cold_fs_update_leaf999_1000tree() public {
        uint256 g0 = gasleft();
        fsTree.update(999, 1999, 9999);
        uint256 g1 = gasleft();
        console.log("[COLD] fs update leaf 999 (1000-leaf tree): %s gas", g0 - g1);
    }
}

// =====================================================================
// Calldata cost comparison (for reporting, not execution)
// =====================================================================
// In a real transaction, the current update sends ~960 bytes of proof
// as calldata. Non-zero calldata costs 16 gas/byte, zero costs 4 gas/byte.
// A typical Poseidon hash is 32 bytes of non-zero data: 32 * 16 = 512 gas.
// 30 siblings: 30 * 512 = 15,360 gas (if all non-zero).
// Some siblings are default zeros (the empty half of the tree), costing
// 32 * 4 = 128 gas each.
//
// For a 100-leaf tree with depth 30:
//   ~7 non-zero siblings (levels 0-6): 7 * 512 = 3,584 gas
//   ~23 zero siblings (levels 7-29):  23 * 128 = 2,944 gas
//   Total calldata overhead: ~6,528 gas
//
// For a 1000-leaf tree:
//   ~10 non-zero siblings: 10 * 512 = 5,120 gas
//   ~20 zero siblings:     20 * 128 = 2,560 gas
//   Total calldata overhead: ~7,680 gas
//
// The full-storage update has zero proof calldata.
