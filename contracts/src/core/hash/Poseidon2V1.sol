// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Poseidon2T2} from "./Poseidon2.sol";

/// @dev V1 compatibility wrapper that keeps Poseidon behind a public library call.
library Poseidon2T2V1 {
    function compress(uint256[2] memory inputs) public pure returns (uint256) {
        return Poseidon2T2.compress(inputs);
    }
}
