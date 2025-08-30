// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {TreeHelper} from "../src/TreeHelper.sol";
import {console} from "forge-std/console.sol";
import {Skyscraper} from "../src/hash/Skyscraper.sol";

contract TreeHelperTest is Test {
    function setUp() public {}

    function test_emptyNode() external pure {
        uint256 node = TreeHelper.emptyNode(1);
        assertEq(node, TreeHelper.hash(0, 0));
    }

    function test_allNodesEmptyTree() external pure {
        uint256[] memory leaves = new uint256[](4);
        leaves[0] = 0;
        leaves[1] = 0;
        leaves[2] = 0;
        leaves[3] = 0;
        uint256[][] memory proof = TreeHelper.allNodes(leaves);
        for (uint256 i = 0; i < proof.length; i++) {
            for (uint256 j = 0; j < proof[i].length; j++) {
                assertEq(proof[i][j], TreeHelper.emptyNode(i));
            }
        }
    }

    function test_allNodes() external pure {
        uint256[] memory leaves = new uint256[](3);
        leaves[0] = 1;
        leaves[1] = 2;
        leaves[2] = 3;
        uint256[][] memory nodes = TreeHelper.allNodes(leaves);
        assertEq(nodes[0][0], 1);
        assertEq(nodes[0][1], 2);
        assertEq(nodes[0][2], 3);
        assertEq(nodes[1][0], TreeHelper.hash(1, 2));
        assertEq(nodes[1][1], TreeHelper.hash(3, 0));
    }

    function test_inclusionProof() external pure {
        uint256[] memory leaves = new uint256[](3);
        leaves[0] = 0;
        leaves[1] = 1;
        leaves[2] = 2;
        uint256[] memory proof = TreeHelper.inclusionProof(leaves, 0);
        assertEq(proof[0], 1);
        assertEq(proof[1], TreeHelper.hash(2, 0));
        assertEq(proof.length, 2);
    }
}
