// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {Skyscraper} from "../hash/Skyscraper.sol";
import {Poseidon2T2} from "../hash/Poseidon2.sol";
import {console} from "forge-std/console.sol";

uint256 constant SNARK_SCALAR_FIELD =
    21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617;

struct LeanIMTData {
    // Tracks the current number of leaves in the tree.
    uint256 size;
    // Represents the current depth of the tree, which can increase as new leaves are inserted.
    uint256 depth;
    // A mapping from each level of the tree to the node value of the last even position at that level.
    // Used for efficient inserts, updates and root calculations.
    mapping(uint256 => uint256) sideNodes;
}

error WrongSiblingNodes();
error LeafGreaterThanSnarkScalarField();
error LeafCannotBeZero();
error LeafAlreadyExists();
error LeafDoesNotExist();

/// @title Lean Incremental binary Merkle tree.
/// @dev The LeanIMT is an optimized version of the BinaryIMT.
/// This implementation eliminates the use of zeroes, and make the tree depth dynamic.
/// When a node doesn't have the right child, instead of using a zero hash as in the BinaryIMT,
/// the node's value becomes that of its left child. Furthermore, rather than utilizing a static tree depth,
/// it is updated based on the number of leaves in the tree. This approach
/// results in the calculation of significantly fewer hashes, making the tree more efficient.
library InternalLeanIMT {
    function _initialize(LeanIMTData storage self, uint256 depth, uint256 size, uint256[] calldata sideNodes)
        external
    {
        self.depth = depth;
        self.size = size;
        for (uint256 i = 0; i < sideNodes.length; i++) {
            self.sideNodes[i] = sideNodes[i];
        }
    }

    function _debugPrint(LeanIMTData storage self) external view {
        console.log("depth: %s", self.depth);
        console.log("size: %s", self.size);
        for (uint256 i = 0; i < self.depth; i++) {
            console.log("sideNodes[%s]: %s", i, self.sideNodes[i]);
        }
    }

    /**
     * @dev Implements the Hash function used in the tree.
     * @param a The first input to the hash function.
     * @param b The second input to the hash function.
     * @return The hash of the two inputs.
     */
    function hash(uint256 a, uint256 b) internal pure returns (uint256) {
        // return Skyscraper.compress(a, b);
        return Poseidon2T2.compress([a, b]);
    }

    /// @dev Inserts a new leaf into the incremental merkle tree.
    /// The function ensures that the leaf is valid according to the
    /// constraints of the tree and then updates the tree's structure accordingly.
    /// @param self: A storage reference to the 'LeanIMTData' struct.
    /// @param leaf: The value of the new leaf to be inserted into the tree.
    /// @return The new hash of the node after the leaf has been inserted.
    function _insert(LeanIMTData storage self, uint256 leaf) internal returns (uint256) {
        if (leaf >= SNARK_SCALAR_FIELD) {
            revert LeafGreaterThanSnarkScalarField();
        }

        uint256 index = self.size;

        // Cache tree depth to optimize gas
        uint256 treeDepth = self.depth;

        // A new insertion can increase a tree's depth by at most 1,
        // and only if the number of leaves supported by the current
        // depth is less than the number of leaves to be supported after insertion.
        if (2 ** treeDepth < index + 1) {
            ++treeDepth;
        }

        self.depth = treeDepth;

        uint256 node = leaf;

        for (uint256 level = 0; level < treeDepth;) {
            if ((index >> level) & 1 == 1) {
                node = hash(self.sideNodes[level], node);
            } else {
                self.sideNodes[level] = node;
            }

            unchecked {
                ++level;
            }
        }

        self.size = ++index;

        self.sideNodes[treeDepth] = node;

        return node;
    }

    /// @dev Inserts many leaves into the incremental merkle tree.
    /// The function ensures that the leaves are valid according to the
    /// constraints of the tree and then updates the tree's structure accordingly.
    /// @param self: A storage reference to the 'LeanIMTData' struct.
    /// @param leaves: The values of the new leaves to be inserted into the tree.
    /// @return The root after the leaves have been inserted.
    function _insertMany(LeanIMTData storage self, uint256[] calldata leaves) internal returns (uint256) {
        // Cache tree size to optimize gas
        uint256 treeSize = self.size;

        // Check that all the new values are correct to be added.
        for (uint256 i = 0; i < leaves.length;) {
            if (leaves[i] >= SNARK_SCALAR_FIELD) {
                revert LeafGreaterThanSnarkScalarField();
            }

            unchecked {
                ++i;
            }
        }

        // Array to save the nodes that will be used to create the next level of the tree.
        uint256[] memory currentLevelNewNodes;

        currentLevelNewNodes = leaves;

        // Cache tree depth to optimize gas
        uint256 treeDepth = self.depth;

        // Calculate the depth of the tree after adding the new values.
        // Unlike the 'insert' function, we need a while here as
        // N insertions can increase the tree's depth more than once.
        while (2 ** treeDepth < treeSize + leaves.length) {
            ++treeDepth;
        }

        self.depth = treeDepth;

        // First index to change in every level.
        uint256 currentLevelStartIndex = treeSize;

        // Size of the level used to create the next level.
        uint256 currentLevelSize = treeSize + leaves.length;

        // The index where changes begin at the next level.
        uint256 nextLevelStartIndex = currentLevelStartIndex >> 1;

        // The size of the next level.
        uint256 nextLevelSize = ((currentLevelSize - 1) >> 1) + 1;

        for (uint256 level = 0; level < treeDepth;) {
            // The number of nodes for the new level that will be created,
            // only the new values, not the entire level.
            uint256 numberOfNewNodes = nextLevelSize - nextLevelStartIndex;
            uint256[] memory nextLevelNewNodes = new uint256[](numberOfNewNodes);
            for (uint256 i = 0; i < numberOfNewNodes;) {
                uint256 leftNode;

                // Assign the left node using the saved path or the position in the array.
                if ((i + nextLevelStartIndex) * 2 < currentLevelStartIndex) {
                    leftNode = self.sideNodes[level];
                } else {
                    leftNode = currentLevelNewNodes[(i + nextLevelStartIndex) * 2 - currentLevelStartIndex];
                }

                uint256 rightNode;

                // Assign the right node if the value exists.
                if ((i + nextLevelStartIndex) * 2 + 1 < currentLevelSize) {
                    rightNode = currentLevelNewNodes[(i + nextLevelStartIndex) * 2 + 1 - currentLevelStartIndex];
                }

                uint256 parentNode;

                // Assign the parent node.
                // If it has a right child the result will be the hash(leftNode, rightNode) if not,
                // it will be the leftNode.
                if (rightNode != 0) {
                    parentNode = hash(leftNode, rightNode);
                } else {
                    parentNode = leftNode;
                }

                nextLevelNewNodes[i] = parentNode;

                unchecked {
                    ++i;
                }
            }

            // Update the `sideNodes` variable.
            // If `currentLevelSize` is odd, the saved value will be the last value of the array
            // if it is even and there are more than 1 element in `currentLevelNewNodes`, the saved value
            // will be the value before the last one.
            // If it is even and there is only one element, there is no need to save anything because
            // the correct value for this level was already saved before.
            if (currentLevelSize & 1 == 1) {
                self.sideNodes[level] = currentLevelNewNodes[currentLevelNewNodes.length - 1];
            } else if (currentLevelNewNodes.length > 1) {
                self.sideNodes[level] = currentLevelNewNodes[currentLevelNewNodes.length - 2];
            }

            currentLevelStartIndex = nextLevelStartIndex;

            // Calculate the next level startIndex value.
            // It is the position of the parent node which is pos/2.
            nextLevelStartIndex >>= 1;

            // Update the next array that will be used to calculate the next level.
            currentLevelNewNodes = nextLevelNewNodes;

            currentLevelSize = nextLevelSize;

            // Calculate the size of the next level.
            // The size of the next level is (currentLevelSize - 1) / 2 + 1.
            nextLevelSize = ((nextLevelSize - 1) >> 1) + 1;

            unchecked {
                ++level;
            }
        }

        // Update tree size
        self.size = treeSize + leaves.length;

        // Update tree root
        self.sideNodes[treeDepth] = currentLevelNewNodes[0];

        return currentLevelNewNodes[0];
    }

    /// @dev Updates the value of an existing leaf and recalculates hashes
    /// to maintain tree integrity.
    /// @param self: A storage reference to the 'LeanIMTData' struct.
    /// @param oldLeaf: The value of the leaf that is to be updated.
    /// @param newLeaf: The new value that will replace the oldLeaf in the tree.
    /// @param siblingNodes: An array of sibling nodes that are necessary to recalculate the path to the root.
    /// @return The new hash of the updated node after the leaf has been updated.
    function _update(
        LeanIMTData storage self,
        uint256 index,
        uint256 oldLeaf,
        uint256 newLeaf,
        uint256[] calldata siblingNodes
    ) internal returns (uint256) {
        if (newLeaf >= SNARK_SCALAR_FIELD) {
            revert LeafGreaterThanSnarkScalarField();
        }

        uint256 node = newLeaf;
        uint256 oldRoot = oldLeaf;

        uint256 lastIndex = self.size - 1;
        uint256 i = 0;

        // Cache tree depth to optimize gas
        uint256 treeDepth = self.depth;

        for (uint256 level = 0; level < treeDepth;) {
            if ((index >> level) & 1 == 1) {
                if (siblingNodes[i] >= SNARK_SCALAR_FIELD) {
                    revert LeafGreaterThanSnarkScalarField();
                }

                node = hash(siblingNodes[i], node);
                oldRoot = hash(siblingNodes[i], oldRoot);

                unchecked {
                    ++i;
                }
            } else {
                if (index >> level != lastIndex >> level) {
                    if (siblingNodes[i] >= SNARK_SCALAR_FIELD) {
                        revert LeafGreaterThanSnarkScalarField();
                    }

                    if (self.sideNodes[level] == oldRoot) {
                        self.sideNodes[level] = node;
                    }

                    node = hash(node, siblingNodes[i]);
                    oldRoot = hash(oldRoot, siblingNodes[i]);

                    unchecked {
                        ++i;
                    }
                } else {
                    self.sideNodes[level] = node;
                }
            }

            unchecked {
                ++level;
            }
        }

        if (oldRoot != _root(self)) {
            revert WrongSiblingNodes();
        }

        self.sideNodes[treeDepth] = node;

        return node;
    }

    /// @dev Removes a leaf from the tree by setting its value to zero.
    /// This function utilizes the update function to set the leaf's value
    /// to zero and update the tree's state accordingly.
    /// @param self: A storage reference to the 'LeanIMTData' struct.
    /// @param oldLeaf: The value of the leaf to be removed.
    /// @param siblingNodes: An array of sibling nodes required for updating the path to the root after removal.
    /// @return The new root hash of the tree after the leaf has been removed.
    function _remove(LeanIMTData storage self, uint256 index, uint256 oldLeaf, uint256[] calldata siblingNodes)
        internal
        returns (uint256)
    {
        return _update(self, index, oldLeaf, 0, siblingNodes);
    }

    /// @dev Retrieves the root of the tree from the 'sideNodes' mapping using the
    /// current tree depth.
    /// @param self: A storage reference to the 'LeanIMTData' struct.
    /// @return The root hash of the tree.
    function _root(LeanIMTData storage self) internal view returns (uint256) {
        return self.sideNodes[self.depth];
    }
}
