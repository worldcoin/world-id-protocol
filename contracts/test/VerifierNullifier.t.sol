// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Verifier} from "../src/VerifierNullifier.sol";

contract NullififerVerifier is Test {
    Verifier public verifier;

    function setUp() public {
        verifier = new Verifier();
    }

    function testVerifyNullifier() public view {
        verifier.verifyCompressedProof(
            [
                0x11a62a784302af372005a5f6bba5881b31305f3c13b82350ce02ed9bc127c4d0,
                0xd1d3fe4aec085b183afb7ab4508e52d87563d96a881636bca3d8e15afbce3ef,
                0x1d03401954bff6b2b46053fa08d5d3b60c935746a435307f8ca1dbef5add6947,
                0x4e7fbfd14327ce56399deeb81afe79c23527920e128b71f1e3e63f9f97641e6d
            ],
            [
                0x2e48ba260f6ee4c1fc61db48cffda1d1abf65821e37eef35125a0298417a91c0,
                0x48611d24f30e734a57a6e3cc64908f48aa9e98f1b97e3a5ead88e4b5305c57a,
                0x1,
                0x2154832e9e7a0689923ec05cc6a548e9efde6d3202df65ae86606ea768655fa0,
                0x2915e9fea96b5e6c8ab0d7b1b1670f7fc253c2d3236ce5d1fcc170d896c8c7e8,
                0x696e5409,
                0x0,
                0xaf727d9412a9d5c73b685fd09dc39e727064e65b8269b233009edfc105f9853,
                0x1e,
                0xf6ddb6592eb648ff,
                0x3ac892062c48339dd301947f75c02063e25b4ce859ebe1ef37027c6d60033d4,
                0x2f6d3b9cfd75e5e3320da1b72f5b79c58e1f1e09a2694e453b3ce33c1a177957,
                0x16ef9937250a3d05099d135515ecd0f1116ce760a4ae2737c2e5857eabd0519b,
                0x1578ed0de47522ad0b38e87031739c6a65caecc39ce3410bf3799e756a220f,
                0x593651f65f824ac2b289e33d52f5a785c917afcaa89816e62229d5e84508c54
            ]
        );
    }
}
