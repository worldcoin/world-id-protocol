// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Poseidon2T2V1 as Poseidon2T2} from "../hash/Poseidon2V1.sol";
import {
    FullBinaryIMTData,
    FullStorageBinaryIMT,
    LeafDoesNotExist,
    LeafIndexOutOfRange,
    NewLeafCannotEqualOldLeaf,
    SNARK_SCALAR_FIELD,
    TreeIsFull,
    ValueGreaterThanSnarkScalarField
} from "./FullStorageBinaryIMT.sol";

/// @dev V1 registry write paths copied from FullStorageBinaryIMT, with Poseidon2T2 aliased to the V1 public wrapper.
library WorldIDRegistryV1Tree {
    function insert(FullBinaryIMTData storage self, uint256 leaf) internal returns (uint256) {
        uint256 depth = self.depth;

        if (leaf >= SNARK_SCALAR_FIELD) {
            revert ValueGreaterThanSnarkScalarField();
        }
        if (self.numberOfLeaves >= uint256(1) << depth) {
            revert TreeIsFull();
        }

        uint256 numLeaves = self.numberOfLeaves;
        uint256 idx = numLeaves;

        self.nodes[FullStorageBinaryIMT._key(0, idx)] = leaf;

        uint256 hash = leaf;
        for (uint256 level = 0; level < depth;) {
            uint256 siblingIdx = idx ^ 1;
            uint256 sibling = FullStorageBinaryIMT._getNode(self, level, siblingIdx, numLeaves);

            if ((idx & 1) == 0) {
                hash = Poseidon2T2.compress([hash, sibling]);
            } else {
                hash = Poseidon2T2.compress([sibling, hash]);
            }

            idx >>= 1;
            unchecked {
                ++level;
            }

            // Write the parent node
            self.nodes[FullStorageBinaryIMT._key(level, idx)] = hash;
        }

        self.root = hash;
        self.numberOfLeaves += 1;
        return hash;
    }

    function insertMany(FullBinaryIMTData storage self, uint256[] memory leaves) internal returns (uint256) {
        uint256 k = leaves.length;
        if (k == 0) return self.root;

        uint256 depth = self.depth;
        uint256 start = self.numberOfLeaves;
        uint256 cap = uint256(1) << depth;
        if (start >= cap || k > cap - start) revert TreeIsFull();

        for (uint256 i = 0; i < k;) {
            uint256 leaf = leaves[i];
            if (leaf >= SNARK_SCALAR_FIELD) {
                revert ValueGreaterThanSnarkScalarField();
            }
            self.nodes[FullStorageBinaryIMT._key(0, start + i)] = leaf;
            unchecked {
                ++i;
            }
        }

        uint256 levelStart = start;
        uint256 levelEnd = start + k - 1;
        uint256 effectiveLeaves = start + k;

        for (uint256 level = 0; level < depth;) {
            uint256 parentStart = levelStart >> 1;
            uint256 parentEnd = levelEnd >> 1;
            uint256 parentLevel;
            unchecked {
                parentLevel = level + 1;
            }

            for (uint256 p = parentStart; p <= parentEnd;) {
                uint256 leftChild = p << 1;
                uint256 left = FullStorageBinaryIMT._getNode(self, level, leftChild, effectiveLeaves);
                uint256 right = FullStorageBinaryIMT._getNode(self, level, leftChild | 1, effectiveLeaves);

                self.nodes[FullStorageBinaryIMT._key(parentLevel, p)] = Poseidon2T2.compress([left, right]);
                unchecked {
                    ++p;
                }
            }

            levelStart = parentStart;
            levelEnd = parentEnd;
            unchecked {
                ++level;
            }
        }

        uint256 newRoot = self.nodes[FullStorageBinaryIMT._key(depth, 0)];
        self.root = newRoot;
        self.numberOfLeaves = start + k;
        return newRoot;
    }

    function update(FullBinaryIMTData storage self, uint256 index, uint256 oldLeaf, uint256 newLeaf) internal {
        if (newLeaf == oldLeaf) {
            revert NewLeafCannotEqualOldLeaf();
        }
        if (newLeaf >= SNARK_SCALAR_FIELD) {
            revert ValueGreaterThanSnarkScalarField();
        }
        uint256 numLeaves = self.numberOfLeaves;
        if (index >= numLeaves) {
            revert LeafIndexOutOfRange();
        }

        uint256 stored = FullStorageBinaryIMT._getNode(self, 0, index, numLeaves);
        if (stored != oldLeaf) {
            revert LeafDoesNotExist();
        }

        uint256 depth = self.depth;
        uint256 idx = index;

        self.nodes[FullStorageBinaryIMT._key(0, idx)] = newLeaf;

        uint256 hash = newLeaf;
        for (uint256 level = 0; level < depth;) {
            uint256 siblingIdx = idx ^ 1;
            uint256 sibling = FullStorageBinaryIMT._getNode(self, level, siblingIdx, numLeaves);

            if ((idx & 1) == 0) {
                hash = Poseidon2T2.compress([hash, sibling]);
            } else {
                hash = Poseidon2T2.compress([sibling, hash]);
            }

            idx >>= 1;
            unchecked {
                ++level;
            }
            self.nodes[FullStorageBinaryIMT._key(level, idx)] = hash;
        }

        self.root = hash;
    }
}
