// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {Poseidon2T2} from "../hash/Poseidon2.sol";

uint256 constant SNARK_SCALAR_FIELD =
    21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617;
uint256 constant MAX_DEPTH = 30;

/// @dev Stores the full Merkle tree so that siblings can be looked up on-chain.
/// This eliminates the need for callers to supply Merkle proofs when updating
/// leaves, removing the TOCTOU race condition inherent in proof-based updates.
struct FullBinaryIMTData {
    uint256 depth; // Depth of the tree.
    uint256 root; // Root hash of the tree.
    uint256 numberOfLeaves; // Number of leaves of the tree.
    // nodes[(level << 32) | index] = hash of the node at (level, index).
    // Level 0 = leaves, level depth = root.
    // For a node at (level, index), its children are at (level-1, 2*index) and (level-1, 2*index+1).
    mapping(uint256 => uint256) nodes;
}

error ValueGreaterThanSnarkScalarField();
error DepthNotSupported();
error WrongDefaultZeroIndex();
error TreeIsFull();
error NewLeafCannotEqualOldLeaf();
error LeafDoesNotExist();
error LeafIndexOutOfRange();
error AlreadyInitialized();

/// @title Full-storage binary Merkle tree.
/// @dev All internal nodes are persisted in storage so that update operations
/// can read siblings directly, avoiding caller-supplied proofs.
library FullStorageBinaryIMT {
    uint256 internal constant Z_0 = 0;
    uint256 internal constant Z_1 = 0x228981b886e5effb2c05a6be7ab4a05fde6bf702a2d039e46c87057dd729ef97;
    uint256 internal constant Z_2 = 0x218fbf2e2f12f0475d3dcf2e0ab1bd4b9ab528e954738c18c4b7c9b5f4b84964;
    uint256 internal constant Z_3 = 0x2e16a8d602271ea50b5a1bd35b854610ef0bddf8f385bdeb0bb31c4562fa0cd6;
    uint256 internal constant Z_4 = 0x2b44a101801fa0b810feb3d82c25e71b88bc6f4aeecd9fcdc2152b1f3c38d044;
    uint256 internal constant Z_5 = 0x19f2fcaf65567ab8803e4fb84e67854815d83a4e1b7be24c6814ba2ba9bdc5ca;
    uint256 internal constant Z_6 = 0x1a3bd772e2782ad018b9c451bf66c3b0ad223a0e68347fae11c78681bf6478df;
    uint256 internal constant Z_7 = 0x34d4539eb24682272ab024133ca575c1cade051f9fdce5948b6b806767e225b;
    uint256 internal constant Z_8 = 0x2971eb2b9cd60a1270db7ab8aada485f64fae5a5e85bed736c67329c410fffee;
    uint256 internal constant Z_9 = 0x2ef220cf75c94a6bc8f4900fe8153ce53132c2de05163d55ecd0fd13519104b4;
    uint256 internal constant Z_10 = 0x2075381e03f1e1f60029fc3079d49b918c967b58e2655b1770c86ca3984ab65c;
    uint256 internal constant Z_11 = 0x1d4789eb40dffb09091a0690d88df7ff993c23d172e866a93631f6792909118c;
    uint256 internal constant Z_12 = 0x2b082d0afac14544d746c924d6fc882f6931b7b6aacd796c82d7fe81ce33ce4c;
    uint256 internal constant Z_13 = 0x175c16bc97822dba5fdf5580638d4983831dab655f5095bde23b6685f61981cd;
    uint256 internal constant Z_14 = 0x0c4b05c87053bf236ef505872eac4304546d3c4f989b1d19b93ef9115e883f66;
    uint256 internal constant Z_15 = 0x2d7e044c16807771000769efac4e9147a90359c5f58da39880697de3afdd6d56;
    uint256 internal constant Z_16 = 0x18b029a33a590d748323e8d6cb8ac7636cdff4a154ddb7e19ac9cb6845adff69;
    uint256 internal constant Z_17 = 0x1e45bd2b39d74ef50d211fc7303d55a06478517cd44887308ba40cb6d4d44216;
    uint256 internal constant Z_18 = 0x189b2c3495c37308649a0c3e9fe3dd06e83612e9cb1528833acf358bc9b43271;
    uint256 internal constant Z_19 = 0x0ec11644818dab9d62fdacacda9fdc5d2fb6f4627a332e3b25bbbc7dfb0672e7;
    uint256 internal constant Z_20 = 0x119827e780a1850d7b7e34646edc1ce918211c26dda4e13bcd1611f6f81c3680;
    uint256 internal constant Z_21 = 0x084449b11bad2bd26ab39b799cccb9408c4f3bcdbef4210f5cd6544d821c85c6;
    uint256 internal constant Z_22 = 0x02f313f5eaf87dd5e81f34e8ef6b98c2928272ba35b80821267b95176775a5dd;
    uint256 internal constant Z_23 = 0x2d01ab8332efd3bcd5d4fe99cdb66d809fbf6a1a84c931942ea40fb5cf4ebdaa;
    uint256 internal constant Z_24 = 0x2adfa5bb110a920158ca367f5cfa6f632aeb78a9a7b1f2d9c0d29f2a197c244b;
    uint256 internal constant Z_25 = 0x1045e59b73045e7bb07ad0bd51e8b5ec08c2b71abc64eaec485ad91a2a528ea8;
    uint256 internal constant Z_26 = 0x1549ebd6196d7d303bf4791a3b33c08809f19e5ebf9a5ef5ba438d3ec4d9a324;
    uint256 internal constant Z_27 = 0x305e08a953165f5d8e4560d619ca03d05c06e7514dfb7f7a2a25dfaf558907dc;
    uint256 internal constant Z_28 = 0x0fb5add1601d2850978d2c5b2de15426a50b7c766c5939843637f759a34ab617;
    uint256 internal constant Z_29 = 0x232052690c527bf35f76a2fd8db54c96f1dd28d009e19c6d00af6d389188fac5;
    uint256 internal constant Z_30 = 0x228ffdf6570d757e6ebc79516241b636bdceed0996036242d00fdd61050975a2;

    function defaultZero(uint256 index) internal pure returns (uint256) {
        if (index == 0) return Z_0;
        if (index == 1) return Z_1;
        if (index == 2) return Z_2;
        if (index == 3) return Z_3;
        if (index == 4) return Z_4;
        if (index == 5) return Z_5;
        if (index == 6) return Z_6;
        if (index == 7) return Z_7;
        if (index == 8) return Z_8;
        if (index == 9) return Z_9;
        if (index == 10) return Z_10;
        if (index == 11) return Z_11;
        if (index == 12) return Z_12;
        if (index == 13) return Z_13;
        if (index == 14) return Z_14;
        if (index == 15) return Z_15;
        if (index == 16) return Z_16;
        if (index == 17) return Z_17;
        if (index == 18) return Z_18;
        if (index == 19) return Z_19;
        if (index == 20) return Z_20;
        if (index == 21) return Z_21;
        if (index == 22) return Z_22;
        if (index == 23) return Z_23;
        if (index == 24) return Z_24;
        if (index == 25) return Z_25;
        if (index == 26) return Z_26;
        if (index == 27) return Z_27;
        if (index == 28) return Z_28;
        if (index == 29) return Z_29;
        if (index == 30) return Z_30;
        revert WrongDefaultZeroIndex();
    }

    /// @dev Encode (level, idx) into a single mapping key.
    function _key(uint256 level, uint256 idx) private pure returns (uint256) {
        return (level << 32) | idx;
    }

    /// @dev Returns the node value at (level, index). Unset nodes return the
    ///      default zero for that level.
    function _getNode(FullBinaryIMTData storage self, uint256 level, uint256 idx, uint256 numLeaves)
        private
        view
        returns (uint256)
    {
        // For an incremental tree with numLeaves leaves, at level L any node
        // with index > (numLeaves - 1) >> L has never been written.
        if (numLeaves == 0 || idx > (numLeaves - 1) >> level) {
            return defaultZero(level);
        }
        uint256 v = self.nodes[_key(level, idx)];
        if (v != 0) return v;
        return defaultZero(level);
    }

    /// @dev Initializes a tree with default zeroes. Can only be called once
    ///      (depth == 0 is the uninitialized sentinel).
    function initWithDefaultZeroes(FullBinaryIMTData storage self, uint256 depth) internal {
        if (depth == 0 || depth > MAX_DEPTH) {
            revert DepthNotSupported();
        }
        if (self.depth != 0) revert AlreadyInitialized();
        self.depth = depth;
        self.root = defaultZero(depth);
    }

    /// @dev Inserts a leaf at the next available position.
    ///      Writes the leaf and every internal node on its path to the root.
    function insert(FullBinaryIMTData storage self, uint256 leaf) internal returns (uint256) {
        uint256 depth = self.depth;

        if (leaf >= SNARK_SCALAR_FIELD) {
            revert ValueGreaterThanSnarkScalarField();
        }
        if (self.numberOfLeaves >= 1 << depth) {
            revert TreeIsFull();
        }

        uint256 numLeaves = self.numberOfLeaves;
        uint256 idx = numLeaves;

        // Write the leaf at level 0
        self.nodes[_key(0, idx)] = leaf;

        // Walk up the tree, hashing with the sibling at each level
        uint256 hash = leaf;
        for (uint256 level = 0; level < depth;) {
            uint256 siblingIdx = idx ^ 1; // flip the lowest bit to get sibling
            uint256 sibling = _getNode(self, level, siblingIdx, numLeaves);

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
            self.nodes[_key(level, idx)] = hash;
        }

        self.root = hash;
        self.numberOfLeaves += 1;
        return hash;
    }

    /// @dev Batch-insert multiple leaves using bottom-up recomputation.
    ///
    ///      Phase 1: Write all k leaves to level 0 in storage.
    ///      Phase 2: Walk up level by level, recomputing only the parents whose
    ///               children changed.  At level L the affected parent range is
    ///               [start >> (L+1),  (start+k-1) >> (L+1)], so the total work
    ///               is  k + k/2 + k/4 + … + 1 + (D − log₂k)  ≈  2k + D
    ///               hashes and the same number of SSTOREs.
    function insertMany(FullBinaryIMTData storage self, uint256[] memory leaves) internal returns (uint256) {
        uint256 k = leaves.length;
        if (k == 0) return self.root;

        uint256 depth = self.depth;
        uint256 start = self.numberOfLeaves;
        uint256 cap = uint256(1) << depth;
        if (start >= cap || k > cap - start) revert TreeIsFull();

        // ── Phase 1: write all leaves to level 0 ──────────────────────
        for (uint256 i = 0; i < k;) {
            uint256 leaf = leaves[i];
            if (leaf >= SNARK_SCALAR_FIELD) {
                revert ValueGreaterThanSnarkScalarField();
            }
            self.nodes[_key(0, start + i)] = leaf;
            unchecked {
                ++i;
            }
        }

        // ── Phase 2: bottom-up recomputation ──────────────────────────
        // levelStart / levelEnd track the range of indices that changed
        // at the current level.  Each iteration computes the parents at
        // the next level whose children overlap that range.
        uint256 levelStart = start;
        uint256 levelEnd = start + k - 1;

        // Use start + k as effective numLeaves for lazy SLOAD: nodes beyond
        // this range at any level have never been written (even accounting
        // for the leaves we just wrote in Phase 1).
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
                uint256 left = _getNode(self, level, leftChild, effectiveLeaves);
                uint256 right = _getNode(self, level, leftChild | 1, effectiveLeaves);

                self.nodes[_key(parentLevel, p)] = Poseidon2T2.compress([left, right]);
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

        uint256 newRoot = self.nodes[_key(depth, 0)];
        self.root = newRoot;
        self.numberOfLeaves = start + k;
        return newRoot;
    }

    /// @dev Updates a leaf in the tree. No caller-supplied proof needed.
    ///      Reads siblings from storage, verifies the old leaf, writes the new
    ///      path, and updates the root.
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

        // Verify the old leaf matches what's stored
        uint256 stored = _getNode(self, 0, index, numLeaves);
        if (stored != oldLeaf) {
            revert LeafDoesNotExist();
        }

        uint256 depth = self.depth;
        uint256 idx = index;

        // Write new leaf
        self.nodes[_key(0, idx)] = newLeaf;

        // Walk up, reading siblings from storage and writing updated parents
        uint256 hash = newLeaf;
        for (uint256 level = 0; level < depth;) {
            uint256 siblingIdx = idx ^ 1;
            uint256 sibling = _getNode(self, level, siblingIdx, numLeaves);

            if ((idx & 1) == 0) {
                hash = Poseidon2T2.compress([hash, sibling]);
            } else {
                hash = Poseidon2T2.compress([sibling, hash]);
            }

            idx >>= 1;
            unchecked {
                ++level;
            }
            self.nodes[_key(level, idx)] = hash;
        }

        self.root = hash;
    }

    /// @dev Removes a leaf from the tree (sets it to zero).
    function remove(FullBinaryIMTData storage self, uint256 index, uint256 leaf) internal {
        update(self, index, leaf, Z_0);
    }

    /// @dev Verify if a leaf is part of the tree.
    function verify(FullBinaryIMTData storage self, uint256 leaf, uint256 index) internal view returns (bool) {
        uint256 numLeaves = self.numberOfLeaves;
        if (index >= numLeaves) return false;
        return _getNode(self, 0, index, numLeaves) == leaf;
    }

    /// @dev Get the inclusion proof (sibling nodes) for a leaf.
    ///      Useful for off-chain consumers that still need proofs.
    function getProof(FullBinaryIMTData storage self, uint256 index) internal view returns (uint256[] memory siblings) {
        uint256 depth = self.depth;
        uint256 numLeaves = self.numberOfLeaves;
        if (index >= numLeaves) revert LeafIndexOutOfRange();
        siblings = new uint256[](depth);
        uint256 idx = index;
        for (uint256 level = 0; level < depth;) {
            siblings[level] = _getNode(self, level, idx ^ 1, numLeaves);
            idx >>= 1;
            unchecked {
                ++level;
            }
        }
    }
}
