// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {BinaryIMT, BinaryIMTData} from "../src/tree/BinaryIMT.sol";
import {InternalBinaryIMT} from "../src/tree/InternalBinaryIMT.sol";
import {console} from "forge-std/console.sol";
import {TreeHelper} from "../src/TreeHelper.sol";

contract BinaryIMTTest is Test {
    using BinaryIMT for BinaryIMTData;
    using InternalBinaryIMT for *;

    BinaryIMTData public tree1;
    BinaryIMTData public tree2;

    function setUp() public {
        tree1.initWithDefaultZeroes(30);
        tree2.initWithDefaultZeroes(30);
    }

    function test_InsertTree() public {
        uint256 leavesToInsert = 1000;
        uint256 gasStart = gasleft();
        for (uint256 i = 0; i < leavesToInsert; i++) {
            tree1.insert(1337 + i);
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
        tree1.insertMany(leaves);
        uint256 gasEnd = gasleft();
        console.log("Gas used: %s", (gasStart - gasEnd) / leavesToInsert);
    }

    function test_InsertManyCorrectness() public {
        uint256 leavesToInsert = 1000;
        uint256[] memory leaves = new uint256[](leavesToInsert);
        for (uint256 i = 0; i < leavesToInsert; i++) {
            leaves[i] = 1337 + i;
            tree1.insert(leaves[i]);
        }
        tree2.insertMany(leaves);
        assertEq(tree1.root, tree2.root);
    }

    function test_UpdateTree() public {
        tree1.insert(1337);
        uint256 depth = 30;
        uint256[] memory proof = new uint256[](depth);
        for (uint256 i = 0; i < depth; i++) {
            proof[i] = BinaryIMT.defaultZero(i);
        }
        uint256 gasStart = gasleft();
        tree1.update(0, 1337, 1338, proof);
        uint256 gasEnd = gasleft();
        console.log("Gas used: %s", (gasStart - gasEnd));
    }
}
