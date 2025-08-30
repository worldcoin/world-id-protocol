// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {InternalLeanIMT, LeanIMTData} from "./InternalLeanIMT.sol";

library LeanIMT {
    using InternalLeanIMT for *;

    function insert(LeanIMTData storage self, uint256 leaf) public returns (uint256) {
        return InternalLeanIMT._insert(self, leaf);
    }

    function insertMany(LeanIMTData storage self, uint256[] calldata leaves) public returns (uint256) {
        return InternalLeanIMT._insertMany(self, leaves);
    }

    function update(
        LeanIMTData storage self,
        uint256 index,
        uint256 oldLeaf,
        uint256 newLeaf,
        uint256[] calldata siblingNodes
    ) public returns (uint256) {
        return InternalLeanIMT._update(self, index, oldLeaf, newLeaf, siblingNodes);
    }

    function remove(LeanIMTData storage self, uint256 index, uint256 oldLeaf, uint256[] calldata siblingNodes)
        public
        returns (uint256)
    {
        return InternalLeanIMT._remove(self, index, oldLeaf, siblingNodes);
    }

    function root(LeanIMTData storage self) public view returns (uint256) {
        return InternalLeanIMT._root(self);
    }

    function initialize(LeanIMTData storage self, uint256 depth, uint256 size, uint256[] calldata sideNodes) external {
        InternalLeanIMT._initialize(self, depth, size, sideNodes);
    }

    function debugPrint(LeanIMTData storage self) external view {
        InternalLeanIMT._debugPrint(self);
    }
}
