// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Skyscraper} from "./hash/Skyscraper.sol";
import {Poseidon2T2} from "./hash/Poseidon2.sol";
import {console} from "forge-std/console.sol";

library TreeHelper {
    function hash(uint256 a, uint256 b) internal pure returns (uint256) {
        // return Skyscraper.compress(a, b);
        return Poseidon2T2.compress([a, b]);
    }

    function emptyNode(uint256 depth) internal pure returns (uint256) {
        uint256 node = 0;
        for (uint256 i = 0; i < depth; i++) {
            node = hash(node, node);
        }
        return node;
    }

    function allNodes(uint256[] memory leaves) internal pure returns (uint256[][] memory) {
        uint256 depth = 0;
        while (2 ** depth < leaves.length) {
            depth++;
        }

        uint256[][] memory nodes = new uint256[][](depth);
        for (uint256 i = 0; i < depth; i++) {
            nodes[i] = new uint256[](2 ** (depth - i));
        }
        for (uint256 i = 0; i < leaves.length; i++) {
            nodes[0][i] = leaves[i];
        }

        for (uint256 i = 1; i < depth; i++) {
            for (uint256 j = 0; j < nodes[i].length; j++) {
                nodes[i][j] = hash(nodes[i - 1][j * 2], nodes[i - 1][j * 2 + 1]);
            }
        }

        return nodes;
    }

    function inclusionProof(uint256[] memory leaves, uint256 leafIndex) internal pure returns (uint256[] memory) {
        uint256[][] memory nodes = allNodes(leaves);
        uint256 maxDepth = nodes.length;
        uint256[] memory proof = new uint256[](maxDepth);
        uint256 depth = 0;
        while (depth < maxDepth) {
            proof[depth] = nodes[depth][leafIndex ^ 1];
            leafIndex = leafIndex >> 1;
            depth++;
        }
        return proof;
    }

    /// @notice Builds an inclusion proof for Lean IMT semantics (no zero padding).
    /// @dev For each level, includes a sibling only if it exists. If the node is
    ///      the last left child without a right sibling, no element is added for that level.
    /// @param leaves The leaves of the tree in insertion order.
    /// @param leafIndex The index of the leaf to prove.
    /// @return proof The sibling nodes from leaf level upwards (variable length).
    function leanInclusionProof(uint256[] memory leaves, uint256 leafIndex) internal pure returns (uint256[] memory) {
        uint256 n = leaves.length;
        require(n > 0, "LeanIMT: no leaves to insert");

        // Max proof length = tree depth
        uint256 depth = 0;
        for (uint256 len = n; len > 1; len = (len + 1) >> 1) {
            depth++;
        }

        uint256[] memory proofTmp = new uint256[](depth);
        uint256 p = 0;

        uint256[] memory level = leaves;
        uint256 lenLevel = n;
        uint256 idx = leafIndex;

        while (lenLevel > 1) {
            // Include sibling only if it exists at this level
            if ((idx & 1) == 1) {
                proofTmp[p++] = level[idx - 1];
            } else if (idx + 1 < lenLevel) {
                proofTmp[p++] = level[idx + 1];
            }

            // Build next level (Lean IMT carry: last left child carries up)
            uint256 nextLen = (lenLevel + 1) >> 1;
            uint256[] memory next = new uint256[](nextLen);
            uint256 ni = 0;
            for (uint256 j = 0; j < lenLevel; j += 2) {
                uint256 left = level[j];
                uint256 parent = (j + 1 < lenLevel) ? hash(left, level[j + 1]) : left;
                next[ni++] = parent;
            }

            level = next;
            lenLevel = nextLen;
            idx >>= 1;
        }

        // Trim to actual proof length
        uint256[] memory proof = new uint256[](p);
        for (uint256 i = 0; i < p; i++) {
            proof[i] = proofTmp[i];
        }
        return proof;
    }
}
