// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {Poseidon2T2} from "../hash/Poseidon2.sol";

uint256 constant SNARK_SCALAR_FIELD =
    21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617;
uint256 constant MAX_DEPTH = 30;

// Each incremental tree has certain properties and data that will
// be used to add new leaves.
struct BinaryIMTData {
    uint256 depth; // Depth of the tree (levels - 1).
    uint256 root; // Root hash of the tree.
    uint256 numberOfLeaves; // Number of leaves of the tree.
    mapping(uint256 => uint256) zeroes; // Zero hashes used for empty nodes (level -> zero hash).
    // The nodes of the subtrees used in the last addition of a leaf (level -> [left node, right node]).
    mapping(uint256 => uint256[2]) lastSubtrees; // Caching these values is essential to efficient appends.
    bool useDefaultZeroes;
}

error ValueGreaterThanSnarkScalarField();
error DepthNotSupported();
error WrongDefaultZeroIndex();
error TreeIsFull();
error NewLeafCannotEqualOldLeaf();
error LeafDoesNotExist();
error LeafIndexOutOfRange();
error WrongMerkleProofPath();

/// @title Incremental binary Merkle tree.
/// @dev The incremental tree allows to calculate the root hash each time a leaf is added, ensuring
/// the integrity of the tree.
library InternalBinaryIMT {
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
    uint256 internal constant Z_31 = 0x5933a091621546ed0b08a34233c40bffd7de08aac23eda0986afc620f1ebe84;
    uint256 internal constant Z_32 = 0x28bef8a9be13a1c0c2b7b4c67a1d618918021883fef28174a46b32fab4b05b97;

    function _defaultZero(uint256 index) internal pure returns (uint256) {
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
        if (index == 31) return Z_31;
        if (index == 32) return Z_32;
        revert WrongDefaultZeroIndex();
    }

    /// @dev Initializes a tree.
    /// @param self: Tree data.
    /// @param depth: Depth of the tree.
    /// @param zero: Zero value to be used.
    function _init(BinaryIMTData storage self, uint256 depth, uint256 zero) internal {
        if (zero >= SNARK_SCALAR_FIELD) {
            revert ValueGreaterThanSnarkScalarField();
        } else if (depth <= 0 || depth > MAX_DEPTH) {
            revert DepthNotSupported();
        }

        self.depth = depth;

        for (uint8 i = 0; i < depth;) {
            self.zeroes[i] = zero;
            zero = Poseidon2T2.compress([zero, zero]);

            unchecked {
                ++i;
            }
        }

        self.root = zero;
    }

    function _initWithDefaultZeroes(BinaryIMTData storage self, uint256 depth) internal {
        if (depth <= 0 || depth > MAX_DEPTH) {
            revert DepthNotSupported();
        }

        self.depth = depth;
        self.useDefaultZeroes = true;

        self.root = _defaultZero(depth);
    }

    /// @dev Inserts a leaf in the tree.
    /// @param self: Tree data.
    /// @param leaf: Leaf to be inserted.
    function _insert(BinaryIMTData storage self, uint256 leaf) internal returns (uint256) {
        uint256 depth = self.depth;

        if (leaf >= SNARK_SCALAR_FIELD) {
            revert ValueGreaterThanSnarkScalarField();
        } else if (self.numberOfLeaves >= 2 ** depth) {
            revert TreeIsFull();
        }

        uint256 index = self.numberOfLeaves;
        uint256 hash = leaf;
        bool useDefaultZeroes = self.useDefaultZeroes;

        for (uint8 i = 0; i < depth;) {
            if (index & 1 == 0) {
                self.lastSubtrees[i] = [hash, useDefaultZeroes ? _defaultZero(i) : self.zeroes[i]];
            } else {
                self.lastSubtrees[i][1] = hash;
            }

            hash = Poseidon2T2.compress(self.lastSubtrees[i]);
            index >>= 1;

            unchecked {
                ++i;
            }
        }

        self.root = hash;
        self.numberOfLeaves += 1;
        return hash;
    }

    function _insertMany(BinaryIMTData storage self, uint256[] calldata leaves) internal returns (uint256) {
        uint256 k = leaves.length;
        if (k == 0) return self.root;

        uint256 depth = self.depth;
        uint256 start = self.numberOfLeaves;

        uint256 cap = uint256(1) << depth;
        if (start >= cap || k > cap - start) revert TreeIsFull();

        bool useDefaultZeroes = self.useDefaultZeroes;

        // Lazy frontier: load per level only on first use
        uint256[] memory frontier = new uint256[](depth);
        uint256 loadedMask = 0; // bit i == level i is loaded into 'frontier'
        uint256[2] memory t; // reused Poseidon input

        // Stream + validate in one pass
        uint256 index = start;
        for (uint256 li = 0; li < k;) {
            uint256 node = leaves[li];
            if (node >= SNARK_SCALAR_FIELD) revert ValueGreaterThanSnarkScalarField();

            uint256 idx = index;
            uint256 level = 0;

            // carry while idx is odd
            while (true) {
                if ((idx & 1) == 0) {
                    // even => store left child at this level and stop
                    frontier[level] = node;
                    // mark loaded so future carries at this level use the in-memory value
                    loadedMask |= (uint256(1) << level);
                    break;
                }

                // odd => combine with existing left sibling and carry up
                if ((loadedMask & (uint256(1) << level)) == 0) {
                    // first touch; pull from storage
                    frontier[level] = self.lastSubtrees[level][0];
                    loadedMask |= (uint256(1) << level);
                }

                t[0] = frontier[level];
                t[1] = node;
                node = Poseidon2T2.compress(t);

                idx >>= 1;
                unchecked {
                    ++level;
                }
                if (level == depth) {
                    // carried to (virtual) root; nothing more to store in frontier
                    break;
                }
            }

            unchecked {
                ++li;
                ++index;
            }
        }

        // Recompute root along last leaf's path; update lastSubtrees along that path
        uint256 finalIdx = start + k - 1;
        uint256 hash = leaves[k - 1];
        uint256 pathIdx = finalIdx;

        for (uint256 level = 0; level < depth;) {
            if ((pathIdx & 1) == 0) {
                // left child; right sibling is default zero
                uint256 rz = useDefaultZeroes ? _defaultZero(level) : self.zeroes[level];
                self.lastSubtrees[level][0] = hash;
                self.lastSubtrees[level][1] = rz;

                t[0] = hash;
                t[1] = rz;
                hash = Poseidon2T2.compress(t);
            } else {
                // right child; left sibling comes from frontier (ensure loaded)
                if ((loadedMask & (uint256(1) << level)) == 0) {
                    frontier[level] = self.lastSubtrees[level][0];
                    loadedMask |= (uint256(1) << level);
                }
                uint256 leftNode = frontier[level];

                self.lastSubtrees[level][0] = leftNode;
                self.lastSubtrees[level][1] = hash;

                t[0] = leftNode;
                t[1] = hash;
                hash = Poseidon2T2.compress(t);
            }

            pathIdx >>= 1;
            unchecked {
                ++level;
            }
        }

        self.root = hash;
        self.numberOfLeaves = start + k;
        return hash;
    }

    /// @dev Updates a leaf in the tree.
    /// @param self: Tree data.
    /// @param leaf: Leaf to be updated.
    /// @param newLeaf: New leaf.
    /// @param proofSiblings: Array of the sibling nodes of the proof of membership.
    /// @param index: Index of the leaf.
    function _update(
        BinaryIMTData storage self,
        uint256 index,
        uint256 leaf,
        uint256 newLeaf,
        uint256[] calldata proofSiblings
    ) internal {
        if (newLeaf == leaf) {
            revert NewLeafCannotEqualOldLeaf();
        } else if (newLeaf >= SNARK_SCALAR_FIELD) {
            revert ValueGreaterThanSnarkScalarField();
        } else if (!_verify(self, leaf, proofSiblings, index)) {
            revert LeafDoesNotExist();
        }

        uint256 depth = self.depth;
        uint256 hash = newLeaf;
        uint256 updateIndex;

        for (uint8 i = 0; i < depth;) {
            uint256 bit = (index >> i) & 1;
            updateIndex |= uint256(bit) << uint256(i);

            if (bit == 0) {
                if (proofSiblings[i] == self.lastSubtrees[i][1]) {
                    self.lastSubtrees[i][0] = hash;
                }

                hash = Poseidon2T2.compress([hash, proofSiblings[i]]);
            } else {
                if (proofSiblings[i] == self.lastSubtrees[i][0]) {
                    self.lastSubtrees[i][1] = hash;
                }

                hash = Poseidon2T2.compress([proofSiblings[i], hash]);
            }

            unchecked {
                ++i;
            }
        }

        if (updateIndex >= self.numberOfLeaves) {
            revert LeafIndexOutOfRange();
        }

        self.root = hash;
    }

    /// @dev Removes a leaf from the tree.
    /// @param self: Tree data.
    /// @param leaf: Leaf to be removed.
    /// @param proofSiblings: Array of the sibling nodes of the proof of membership.
    /// @param index: Index of the leaf.
    function _remove(BinaryIMTData storage self, uint256 index, uint256 leaf, uint256[] calldata proofSiblings)
        internal
    {
        _update(self, index, leaf, self.useDefaultZeroes ? Z_0 : self.zeroes[0], proofSiblings);
    }

    /// @dev Verify if the path is correct and the leaf is part of the tree.
    /// @param self: Tree data.
    /// @param leaf: Leaf to be removed.
    /// @param proofSiblings: Array of the sibling nodes of the proof of membership.
    /// @param index: Index of the leaf.
    /// @return True or false.
    function _verify(BinaryIMTData storage self, uint256 leaf, uint256[] calldata proofSiblings, uint256 index)
        internal
        view
        returns (bool)
    {
        uint256 depth = self.depth;

        if (leaf >= SNARK_SCALAR_FIELD) {
            revert ValueGreaterThanSnarkScalarField();
        } else if (proofSiblings.length != depth) {
            revert WrongMerkleProofPath();
        }

        uint256 hash = leaf;

        for (uint8 i = 0; i < depth;) {
            uint256 bit = (index >> i) & 1;
            if (proofSiblings[i] >= SNARK_SCALAR_FIELD) {
                revert ValueGreaterThanSnarkScalarField();
            } else if (bit != 1 && bit != 0) {
                revert WrongMerkleProofPath();
            }

            if (bit == 0) {
                hash = Poseidon2T2.compress([hash, proofSiblings[i]]);
            } else {
                hash = Poseidon2T2.compress([proofSiblings[i], hash]);
            }

            unchecked {
                ++i;
            }
        }

        return hash == self.root;
    }
}
