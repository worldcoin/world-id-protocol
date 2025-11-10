// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Groth16Verifier} from "../src/Groth16VerifierNullifier.sol";
import {Verifier} from "../src/Verifier.sol";
import {Types, IRpRegistry} from "../src/interfaces/RpRegistry.sol";
import {CredentialSchemaIssuerRegistry} from "../src/CredentialSchemaIssuerRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

uint256 constant credentialIssuerIdCorrect = 1;
uint256 constant credentialIssuerIdWrong = 2;

uint128 constant rpIdCorrect = 0xcb3e8192a99de46a08eeb093ef3b2144;
uint128 constant rpIdWrong = 2;

uint256 constant rootCorrect = 0x11e122f688a8b3e47f02c77e0ccc7fa083ac6578be56690d72b300f2c3982846;
uint256 constant rootWrong = 2;

contract RpRegistryMock {
    using Types for Types.BabyJubJubElement;

    function getRpNullifierKey(uint128 rpId) external view returns (Types.BabyJubJubElement memory) {
        if (rpId == rpIdCorrect) {
            return Types.BabyJubJubElement({
                x: 0x091b6c36599c463334b4921b3dcd0aa2170f3081007b33364ca033ea1442ccc0,
                y: 0x11f62caebb20e2db44861e4ae188bc954243591c5bb677f84e1560fdb1cb1de6
            });
        } else {
            return Types.BabyJubJubElement({
                x: 0x1583c671e97dd91df79d8c5b311d452a3eec14932c89d9cff0364d5b98ef215e,
                y: 0x3f5c610720cfa296066965732468ea34a8f7e3725899e1b4470c6b5a76321a3
            });
        }
    }
}

contract AccountRegistryMock {
    function isValidRoot(uint256 root) external view virtual returns (bool) {
        return rootCorrect == root;
    }
}

contract CredentialSchemaIssuerRegistryMock {
    function issuerSchemaIdToPubkey(uint256 issuerSchemaId)
        public
        view
        virtual
        returns (CredentialSchemaIssuerRegistry.Pubkey memory)
    {
        if (issuerSchemaId == credentialIssuerIdCorrect) {
            return CredentialSchemaIssuerRegistry.Pubkey({
                x: 0x11472d905dbd235545a10fe003712f02ccb337feae307d9e2cc98572a9e49949,
                y: 0x1b2d6ece3d71105ab4658320564b9a8ea4fedb8bca5e1b01986aaefe87c43cd7
            });
        } else {
            return CredentialSchemaIssuerRegistry.Pubkey({
                x: 0x1583c671e97dd91df79d8c5b311d452a3eec14932c89d9cff0364d5b98ef215e,
                y: 0x3f5c610720cfa296066965732468ea34a8f7e3725899e1b4470c6b5a76321a3
            });
        }
    }
}

contract NullifierVerifier is Test {
    using Types for Types.Groth16Proof;
    Verifier public verifier;

    address public verifierGroth16;

    uint256 accountCommitment = 0x2227c04ecb75e771b827685ab5622a67a08d557f00b2ab6867d03afd11b06624;
    uint256 nullifier = 0x037fddd3d405b27286ffe9b472bf9b10a5df1e6ae06a6e6014392dfc51a0e3da;
    uint256 proofTimestamp = 0x00000000000000000000000000000000000000000000000000000000690e0683;
    uint128 rpId = 0xcb3e8192a99de46a08eeb093ef3b2144;
    uint256 action = 0x1cd71ef9ab434e89a42c11587ea8f554331f10001fb292ba8cd798dd62385e15;
    uint256 rpKey_x = 0x091b6c36599c463334b4921b3dcd0aa2170f3081007b33364ca033ea1442ccc0;
    uint256 rpKey_y = 0x11f62caebb20e2db44861e4ae188bc954243591c5bb677f84e1560fdb1cb1de6;
    uint256 signalHash = 0x21677a0062b3c7a73f76603fc57af2006dc41b4c0bf952e77e92491f91d74ce9;
    uint256 nonce = 0x03003f4a26ec49b51cbd7b3e15a880770e0a90f189757f46524d5619e8408a11f;

    Types.Groth16Proof proof = Types.Groth16Proof({
        a: [
            0x266fe1cb3647102c92f073f3818641aca99ba997a6101fd90b5d2b231ec6fd67,
            0x2f5d33a9de94fd5045377234205a25aac7ffddabae3b1c4e6557e49639c8542d
        ],
        b: [
            [
                0x2aa798b9e477fe79018edebce512c0a129ca20bead4337a3fe686d7d7edcbc95,
                0x0c8ddd2b5540d567cf57a1a56278b3b6ec3efbc6f8cdcc4a0c3923e718a40925
            ],
            [
                0x158ae9ea9aa816b3ecad7b6e9af27b677ede447128c44239f46547ad50647317,
                0x1a66279399270c4231efadea2c1ccd7a4bfb9b6c77e1a5fba0bc156500bc14d9
            ]
        ],
        c: [
            0x2750f5c10227b80d42d016df30e3ada05d1ac995a99de5491cdd040b346e68b3,
            0x0a0552a79c0d862111e78e1cdc090fb52d7805e804f65ed6ff35993eca58e8f1
        ]
    });

    function setUp() public {
        address rpRegistry = address(new RpRegistryMock());
        address accountRegistryMock = address(new AccountRegistryMock());
        address credentialSchemaIssuerRegistryMock = address(new CredentialSchemaIssuerRegistryMock());
        verifierGroth16 = address(new Groth16Verifier());

        Verifier implementation = new Verifier();
        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            Verifier.initialize.selector, credentialSchemaIssuerRegistryMock, accountRegistryMock, verifierGroth16
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        verifier = Verifier(address(proxy));
        verifier.updateRpRegistry(rpRegistry);
    }

    function test_Success() public {
        vm.warp(proofTimestamp + 1 hours);
        bool success = verifier.verify(
            nullifier,
            action,
            rpIdCorrect,
            accountCommitment,
            nonce,
            signalHash,
            rootCorrect,
            proofTimestamp,
            credentialIssuerIdCorrect,
            proof
        );
        assert(success);
    }

    function test_WrongRpId() public {
        vm.warp(proofTimestamp + 1 hours);
        bool success = verifier.verify(
            nullifier,
            action,
            rpIdWrong,
            accountCommitment,
            nonce,
            signalHash,
            rootCorrect,
            proofTimestamp,
            credentialIssuerIdCorrect,
            proof
        );
        assert(!success);
    }

    function test_WrongCredentialIssuer() public {
        vm.warp(proofTimestamp + 1 hours);
        bool success = verifier.verify(
            nullifier,
            action,
            rpIdCorrect,
            accountCommitment,
            nonce,
            signalHash,
            rootCorrect,
            proofTimestamp,
            credentialIssuerIdWrong,
            proof
        );
        assert(!success);
    }

    function test_WrongProof() public {
        Types.Groth16Proof memory brokenProof = Types.Groth16Proof({
            a: [
                0x266fe1cb3647102c92f073f3818641aca99ba997a6101fd90b5d2b231ec6fd67,
                0x2f5d33a9de94fd5045377234205a25aac7ffddabae3b1c4e6557e49639c8542d
            ],
            b: [
                [
                    0x2aa798b9e477fe79018edebce512c0a129ca20bead4337a3fe686d7d7edcbc95,
                    0x0c8ddd2b5540d567cf57a1a56278b3b6ec3efbc6f8cdcc4a0c3923e718a40925
                ],
                [
                    0x158ae9ea9aa816b3ecad7b6e9af27b677ede447128c44239f46547ad50647317,
                    0x1a66279399270c4231efadea2c1ccd7a4bfb9b6c77e1a5fba0bc156500bc14d9
                ]
            ],
            c: [
                0x2750f5c10227b80d42d016df30e3ada05d1ac995a99de5491cdd040b346e68b3,
                0x0a0552a79c0d862111e78e1cdc090fb52d7805e804f65ed6ff35993eca58e8f
            ]
        });
        vm.warp(proofTimestamp + 1 hours);
        bool success = verifier.verify(
            nullifier,
            action,
            rpIdCorrect,
            accountCommitment,
            nonce,
            signalHash,
            rootCorrect,
            proofTimestamp,
            credentialIssuerIdCorrect,
            brokenProof
        );
        assert(!success);
    }

    function test_InvalidRoot() public {
        vm.warp(proofTimestamp + 1 hours);
        vm.expectRevert();
        verifier.verify(
            nullifier,
            action,
            rpIdCorrect,
            accountCommitment,
            nonce,
            signalHash,
            rootWrong,
            proofTimestamp,
            credentialIssuerIdCorrect,
            proof
        );
    }

    function test_TimestampFuture() public {
        vm.warp(proofTimestamp - 1 hours);
        vm.expectRevert(abi.encodeWithSelector(Verifier.NullifierFromFuture.selector));
        verifier.verify(
            nullifier,
            action,
            rpIdCorrect,
            accountCommitment,
            nonce,
            signalHash,
            rootCorrect,
            proofTimestamp,
            credentialIssuerIdCorrect,
            proof
        );
    }

    function test_TimestampTooOld() public {
        vm.warp(proofTimestamp + 24 hours);
        vm.expectRevert(abi.encodeWithSelector(Verifier.OutdatedNullifier.selector));
        verifier.verify(
            nullifier,
            action,
            rpIdCorrect,
            accountCommitment,
            nonce,
            signalHash,
            rootCorrect,
            proofTimestamp,
            credentialIssuerIdCorrect,
            proof
        );
    }
}
