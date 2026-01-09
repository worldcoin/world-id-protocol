// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Verifier} from "../src/Verifier.sol";
import {Types} from "oprf-key-registry/src/Types.sol";
import {Groth16Verifier} from "../src/Groth16VerifierNullifier.sol";
import {OprfKeyRegistry} from "oprf-key-registry/src/OprfKeyRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {CredentialSchemaIssuerRegistry} from "../src/CredentialSchemaIssuerRegistry.sol";

uint256 constant credentialIssuerIdCorrect = 1;
uint256 constant credentialIssuerIdWrong = 2;

uint160 constant rpIdCorrect = 0xa3d3be8a7b705148db53d2bb75cf436b;
uint160 constant rpIdWrong = 2;

uint256 constant rootCorrect = 0x1d22549d78774db0d351d984a476f26fca780643e134f435ad966c29c4652122;
uint256 constant rootWrong = 2;

contract OprfKeyRegistryMock {
    using Types for Types.BabyJubJubElement;

    function getOprfPublicKey(uint160 oprfKeyId) external view returns (Types.BabyJubJubElement memory) {
        // TODO update for mapping of rpId to oprfKeyId
        if (oprfKeyId == rpIdCorrect) {
            return Types.BabyJubJubElement({
                x: 0x158bde45465f643c741ec671211d8cdda47f2015843d5d8d6f0fd3823773b08e,
                y: 0x6cd134f217937f3f88d19f9418a67d481b67c87ce959e51f08d18ea76972d8b
            });
        } else {
            return Types.BabyJubJubElement({
                x: 0x1583c671e97dd91df79d8c5b311d452a3eec14932c89d9cff0364d5b98ef215e,
                y: 0x3f5c610720cfa296066965732468ea34a8f7e3725899e1b4470c6b5a76321a3
            });
        }
    }
}

contract WorldIDRegistryMock {
    uint256 public treeDepth = 30;

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
                x: 0x29a0a9a447716d534de135000087753a335dba7af26fafb88209d837cacf5631,
                y: 0x2b400d3ada4bafcb92128545f2498fe10db3932df5f65dc029d11246f3602e38
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

    uint256 public proofTimestampDelta;

    uint256 accountCommitment = 0x08987cf30dc2d612c1ff5b578e13c88e79c93f97ce5b5de38cd32398e38b49e0;
    uint256 nullifier = 0x5a691b2dce9717b041201d1050b716c2c53626b71283c4dfa8a69a1f05e0500;
    uint256 proofTimestamp = 0x691c5060;
    uint160 rpId = 0xa3d3be8a7b705148db53d2bb75cf436b;
    uint256 action = 0x5af36be93f35ed0611d38e6f759aade2532563da3bf91fbf251bedb228c4326;
    uint256 oprfPublicKey_x = 0x158bde45465f643c741ec671211d8cdda47f2015843d5d8d6f0fd3823773b08e;
    uint256 oprfPublicKey_y = 0x6cd134f217937f3f88d19f9418a67d481b67c87ce959e51f08d18ea76972d8b;
    uint256 signalHash = 0x2ecfa99ecb77772534c42713e20a21ff36c838870a6a3846fd1c4667326ca5e5;
    uint256 nonce = 0x2005e5e4b247df0f284a7e717835b18d18dfddcbb8f65c31fa22edbb047d78ea;

    Types.Groth16Proof proof = Types.Groth16Proof({
        pA: [
            0x187f24c372a1c42c8a8ed9c74592210ac3fa4337d810c401dbd313a2e9424f03,
            0x13fff489f24d745ecb90697e33d35e02e1c1f14c2ee28d4677c8fdf5d19ba947
        ],
        pB: [
            [
                0x2586480928ac0651b735c8024d575d2f5d59c2946c305e123a867ae88fd83600,
                0x07f3795a9842c1a41ca17f0f7c275efa0da09f214d61267126f7f317afc39133
            ],
            [
                0x00d20fbd777d3648b1670dcf46f12ad52dbb56aa4bb58a3cdf0b5c97d426e1f1,
                0x1e8306e907e700e1f9160eee3bc9cc7fe988bb66a28f232e43d988c32675b50a
            ]
        ],
        pC: [
            0x220825adf76ca3730ce0241de7cf5ce388d4d275886fe7b01d82155c55915d24,
            0x202410723daf76348a7d4123e867676e27375a95e70a06815b8895f9d21f8ecb
        ]
    });

    function setUp() public {
        address oprfKeyRegistry = address(new OprfKeyRegistryMock());
        address worldIDRegistryMock = address(new WorldIDRegistryMock());
        address credentialSchemaIssuerRegistryMock = address(new CredentialSchemaIssuerRegistryMock());
        verifierGroth16 = address(new Groth16Verifier());
        proofTimestampDelta = 5 hours;

        Verifier implementation = new Verifier();
        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            Verifier.initialize.selector,
            credentialSchemaIssuerRegistryMock,
            worldIDRegistryMock,
            verifierGroth16,
            proofTimestampDelta
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        verifier = Verifier(address(proxy));
        verifier.updateOprfKeyRegistry(oprfKeyRegistry);
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
            pA: [
                0x220825adf76ca3730ce0241de7cf5ce388d4d275886fe7b01d82155c55915d24,
                0x202410723daf76348a7d4123e867676e27375a95e70a06815b8895f9d21f8ecb
            ],
            pB: [
                [
                    0x2586480928ac0651b735c8024d575d2f5d59c2946c305e123a867ae88fd83600,
                    0x07f3795a9842c1a41ca17f0f7c275efa0da09f214d61267126f7f317afc39133
                ],
                [
                    0x00d20fbd777d3648b1670dcf46f12ad52dbb56aa4bb58a3cdf0b5c97d426e1f1,
                    0x1e8306e907e700e1f9160eee3bc9cc7fe988bb66a28f232e43d988c32675b50a
                ]
            ],
            pC: [
                0x187f24c372a1c42c8a8ed9c74592210ac3fa4337d810c401dbd313a2e9424f03,
                0x13fff489f24d745ecb90697e33d35e02e1c1f14c2ee28d4677c8fdf5d19ba947
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
