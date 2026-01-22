// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

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
                0x3282817e430906e0a5f73e22d404971f1e8701d4d4270f3d531f07d0d8819db8,
                0x79a6dee01c030080298a09adfd0294edc84f1650b68763d0aab5d6a1c1bbd8,
                0x850d06c33658c9d2cc0e873cb45ad5375a31a6661cd4a11d833466ffe79b8bdd,
                0x2c4257a1f6ab47e8432f815b1a48e8e760b541d92a1bbd7cedf1fa2ec51b4eed
            ],
            [
                0x18a48a7958bc33c7fb3f6351e52a76da4615cd366dabff91fec68e0df1e8cf42,
                0x1,
                0x13792652ea0af01565bbb64d51607bf96447930b33e52d1bae28ad027dfddc15,
                0x1a03e277ea354e453878e02f6e151a7a497c53e6cd9772ad33829235f89d6496,
                0x6970f9bf,
                0x0,
                0xaf727d9412a9d5c73b685fd09dc39e727064e65b8269b233009edfc105f9853,
                0x1e,
                0x3207461bd9fc9797,
                0x29271a44e95107ab7b69f320ea73605f7651ac5ee61927205999662e3f620bd3,
                0x1d988b77dfe70c867df95aede734b9c52cd99810f58ff109f9f13d9093cd58e2,
                0x1c33af244fd6b4d1bec338f99a73b800633fbfa027b2b45811e715cd5b66994b,
                0x1578ed0de47522ad0b38e87031739c6a65caecc39ce3410bf3799e756a220f,
                0x2c42d5fb6f893752c1f8e6a7178a3400762a64039ded1af1190109a3f5e63a1b,
                0x0
            ]
        );
    }
}
