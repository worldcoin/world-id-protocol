// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

library Types {
    struct Groth16Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    struct BabyJubJubElement {
        uint256 x;
        uint256 y;
    }
}

interface IOprfKeyRegistry {
    function getOprfPublicKey(uint160 oprfKeyId) external view returns (Types.BabyJubJubElement memory);
}
