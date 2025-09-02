// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {InternalBinaryIMT, BinaryIMTData} from "./InternalBinaryIMT.sol";

library BinaryIMT {
    using InternalBinaryIMT for *;

    function defaultZero(uint256 index) public pure returns (uint256) {
        return InternalBinaryIMT._defaultZero(index);
    }

    function init(BinaryIMTData storage self, uint256 depth, uint256 zero) public {
        InternalBinaryIMT._init(self, depth, zero);
    }

    function initWithDefaultZeroes(BinaryIMTData storage self, uint256 depth) public {
        InternalBinaryIMT._initWithDefaultZeroes(self, depth);
    }

    function insert(BinaryIMTData storage self, uint256 leaf) public returns (uint256) {
        return InternalBinaryIMT._insert(self, leaf);
    }

    function insertMany(BinaryIMTData storage self, uint256[] calldata leaves) public returns (uint256) {
        return InternalBinaryIMT._insertMany(self, leaves);
    }

    function update(
        BinaryIMTData storage self,
        uint256 index,
        uint256 leaf,
        uint256 newLeaf,
        uint256[] calldata proofSiblings
    ) public {
        InternalBinaryIMT._update(self, index, leaf, newLeaf, proofSiblings);
    }

    function remove(BinaryIMTData storage self, uint256 index, uint256 leaf, uint256[] calldata proofSiblings) public {
        InternalBinaryIMT._remove(self, index, leaf, proofSiblings);
    }
}
