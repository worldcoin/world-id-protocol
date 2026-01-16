// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Groth16Verifier} from "../src/Groth16VerifierNullifier.sol";

contract NullifierGroth16Verifier is Test {
    Groth16Verifier public verifier;

    function setUp() public {
        verifier = new Groth16Verifier();
    }

    function testVerifyNullifier() public view {
        bool result = verifier.verifyProof(
            [
                0x187f24c372a1c42c8a8ed9c74592210ac3fa4337d810c401dbd313a2e9424f03,
                0x13fff489f24d745ecb90697e33d35e02e1c1f14c2ee28d4677c8fdf5d19ba947
            ],
            [
                [
                    0x2586480928ac0651b735c8024d575d2f5d59c2946c305e123a867ae88fd83600,
                    0x07f3795a9842c1a41ca17f0f7c275efa0da09f214d61267126f7f317afc39133
                ],
                [
                    0x00d20fbd777d3648b1670dcf46f12ad52dbb56aa4bb58a3cdf0b5c97d426e1f1,
                    0x1e8306e907e700e1f9160eee3bc9cc7fe988bb66a28f232e43d988c32675b50a
                ]
            ],
            [
                0x220825adf76ca3730ce0241de7cf5ce388d4d275886fe7b01d82155c55915d24,
                0x202410723daf76348a7d4123e867676e27375a95e70a06815b8895f9d21f8ecb
            ],
            [
                0x08987cf30dc2d612c1ff5b578e13c88e79c93f97ce5b5de38cd32398e38b49e0,
                0x05a691b2dce9717b041201d1050b716c2c53626b71283c4dfa8a69a1f05e0500,
                0x29a0a9a447716d534de135000087753a335dba7af26fafb88209d837cacf5631,
                0x2b400d3ada4bafcb92128545f2498fe10db3932df5f65dc029d11246f3602e38,
                0x00000000000000000000000000000000000000000000000000000000691c5060,
                0x1d22549d78774db0d351d984a476f26fca780643e134f435ad966c29c4652122,
                0x000000000000000000000000000000000000000000000000000000000000001e,
                0x00000000000000000000000000000000a3d3be8a7b705148db53d2bb75cf436b,
                0x05af36be93f35ed0611d38e6f759aade2532563da3bf91fbf251bedb228c4326,
                0x158bde45465f643c741ec671211d8cdda47f2015843d5d8d6f0fd3823773b08e,
                0x06cd134f217937f3f88d19f9418a67d481b67c87ce959e51f08d18ea76972d8b,
                0x2ecfa99ecb77772534c42713e20a21ff36c838870a6a3846fd1c4667326ca5e5,
                0x2005e5e4b247df0f284a7e717835b18d18dfddcbb8f65c31fa22edbb047d78ea
            ]
        );
        assert(result);
    }
}
