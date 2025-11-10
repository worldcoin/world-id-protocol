// SPDX-License-Identifier: UNLICENSED
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
                0x266fe1cb3647102c92f073f3818641aca99ba997a6101fd90b5d2b231ec6fd67,
                0x2f5d33a9de94fd5045377234205a25aac7ffddabae3b1c4e6557e49639c8542d
            ],
            [
                [
                    0x2aa798b9e477fe79018edebce512c0a129ca20bead4337a3fe686d7d7edcbc95,
                    0x0c8ddd2b5540d567cf57a1a56278b3b6ec3efbc6f8cdcc4a0c3923e718a40925
                ],
                [
                    0x158ae9ea9aa816b3ecad7b6e9af27b677ede447128c44239f46547ad50647317,
                    0x1a66279399270c4231efadea2c1ccd7a4bfb9b6c77e1a5fba0bc156500bc14d9
                ]
            ],
            [
                0x2750f5c10227b80d42d016df30e3ada05d1ac995a99de5491cdd040b346e68b3,
                0x0a0552a79c0d862111e78e1cdc090fb52d7805e804f65ed6ff35993eca58e8f1
            ],
            [
                0x2227c04ecb75e771b827685ab5622a67a08d557f00b2ab6867d03afd11b06624,
                0x037fddd3d405b27286ffe9b472bf9b10a5df1e6ae06a6e6014392dfc51a0e3da,
                0x11472d905dbd235545a10fe003712f02ccb337feae307d9e2cc98572a9e49949,
                0x1b2d6ece3d71105ab4658320564b9a8ea4fedb8bca5e1b01986aaefe87c43cd7,
                0x00000000000000000000000000000000000000000000000000000000690e0683,
                0x11e122f688a8b3e47f02c77e0ccc7fa083ac6578be56690d72b300f2c3982846,
                0x000000000000000000000000000000000000000000000000000000000000001e,
                0x00000000000000000000000000000000cb3e8192a99de46a08eeb093ef3b2144,
                0x1cd71ef9ab434e89a42c11587ea8f554331f10001fb292ba8cd798dd62385e15,
                0x091b6c36599c463334b4921b3dcd0aa2170f3081007b33364ca033ea1442ccc0,
                0x11f62caebb20e2db44861e4ae188bc954243591c5bb677f84e1560fdb1cb1de6,
                0x21677a0062b3c7a73f76603fc57af2006dc41b4c0bf952e77e92491f91d74ce9,
                0x3003f4a26ec49b51cbd7b3e15a880770e0a90f189757f46524d5619e8408a11f
            ]
        );
        assert(result);
    }
}
