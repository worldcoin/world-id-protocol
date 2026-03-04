// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Verifier} from "../../src/core/Verifier.sol";

contract VerifierTest is Test {
    Verifier public verifier;

    function setUp() public {
        verifier = new Verifier();
    }

    function testVerifyNullifier() public view {
        verifier.verifyCompressedProof(
            [
                0x4906f4e17b969ef2cfc44bd96520f01a3f5c32972bca2e10b70e05e03e3d9f13,
                0xd6d9a3456e9af7d8f6f78eb3380deb8c93505c062f62fa18b8ef8a2ccb55db8,
                0xa92a48edeb327b190048648788de9a8eff0abed5dc93bee8881387da40571278,
                0x38f52985c393efb732be8f54b5f00f7f25370ac5945de84e0d8d2f2d298866b8
            ],
            [
                0x1bae01b23e5f0ee96151331fffb0550351c52e5ee0ced452c762e120723ae702,
                0x1,
                0x252c8234509649bb469ecb7a7e758f306b41415f2d80d4d67967902d6f589a81,
                0x230e4f93a5f1187639314dd25e595db06dc18de219cfaeb8cfdf81d4afe910d5,
                0x699cfa47,
                0x0,
                0xaf727d9412a9d5c73b685fd09dc39e727064e65b8269b233009edfc105f9853,
                0x1e,
                0x1a6ccf8f70e5de68,
                0x15d4b66e5417cb9875f6a2b5be9814dca80651d7c74b3b21685fdd494566e79f,
                0xac79da013272129ddceae6d20c0f579abd04b0a00160ed2be2151bf4014e8d,
                0x187ce5ac507fe0760e95d1893cc6ebf3a115eb9adeaa355c14cc52722a2275be,
                0x1578ed0de47522ad0b38e87031739c6a65caecc39ce3410bf3799e756a220f,
                0x18e3ab3d5fedc6eaa5e0d06a3a6f3dd5e0bf2d17b18b797a1cc6ff4706169d1e,
                0x0
            ]
        );
    }
}
