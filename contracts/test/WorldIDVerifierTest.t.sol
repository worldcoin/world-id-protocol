// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {WorldIDVerifier as WorldIdVerifier} from "../src/WorldIDVerifier.sol";
import {IWorldIDVerifier} from "../src/interfaces/IWorldIDVerifier.sol";
import {BabyJubJub} from "oprf-key-registry/src/BabyJubJub.sol";
import {Verifier} from "../src/Verifier.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {CredentialSchemaIssuerRegistry} from "../src/CredentialSchemaIssuerRegistry.sol";
import {ICredentialSchemaIssuerRegistry} from "../src/interfaces/ICredentialSchemaIssuerRegistry.sol";

uint64 constant credentialIssuerIdCorrect = 1;
uint64 constant credentialIssuerIdWrong = 2;

uint64 constant rpIdCorrect = 0x53a9a80aba3b204;
uint64 constant rpIdWrong = 2;

uint256 constant rootCorrect = 0xaf727d9412a9d5c73b685fd09dc39e727064e65b8269b233009edfc105f9853;
uint256 constant rootWrong = 2;

contract OprfKeyRegistryMock {
    function getOprfPublicKey(uint160 oprfKeyId) external view returns (BabyJubJub.Affine memory) {
        // TODO update for mapping of rpId to oprfKeyId
        if (oprfKeyId == rpIdCorrect) {
            return BabyJubJub.Affine({
                x: 0xf6fd2a88ea804c58be59ad3515982c07b5a6524311906ad69e3ef50f7a32d59,
                y: 0x17cb049e14cdfd8009641892e6ee9ee33e564e6c675e47a89922c818cc603c68
            });
        } else {
            return BabyJubJub.Affine({
                x: 0x1583c671e97dd91df79d8c5b311d452a3eec14932c89d9cff0364d5b98ef215e,
                y: 0x3f5c610720cfa296066965732468ea34a8f7e3725899e1b4470c6b5a76321a3
            });
        }
    }
}

contract WorldIDRegistryMock {
    uint256 private treeDepth = 30;

    function getTreeDepth() external view virtual returns (uint256) {
        return treeDepth;
    }

    function isValidRoot(uint256 root) external view virtual returns (bool) {
        return rootCorrect == root;
    }
}

contract CredentialSchemaIssuerRegistryMock {
    function issuerSchemaIdToPubkey(uint64 issuerSchemaId)
        public
        view
        virtual
        returns (ICredentialSchemaIssuerRegistry.Pubkey memory)
    {
        if (issuerSchemaId == credentialIssuerIdCorrect) {
            return ICredentialSchemaIssuerRegistry.Pubkey({
                x: 0xae7ba7c51efaa3c6b215c9cf0d148e6c01091bc0001a4da342e4f872591a105,
                y: 0x24b378870638c68d90b3f7d8acbf540d2262af52ad1bbe64370931c280bab0d
            });
        } else {
            return ICredentialSchemaIssuerRegistry.Pubkey({
                x: 0x1583c671e97dd91df79d8c5b311d452a3eec14932c89d9cff0364d5b98ef215e,
                y: 0x3f5c610720cfa296066965732468ea34a8f7e3725899e1b4470c6b5a76321a3
            });
        }
    }
}

contract ProofVerifier is Test {
    WorldIdVerifier public worldIDVerifier;

    address public verifier;

    uint256 public proofTimestampDelta;

    uint256 nullifier = 0x104b3a1c8e29cca4c7279df4831ac6c20a4d841e069c3ccdce2c1ac88d55b5a;
    uint256 proofTimestamp = 0x6980a43f;
    uint256 action = 0x2e22e1a5485379a647255f72583f9120788c61e9c42413b7555f20d75cd34408;
    uint256 signalHash = 0x1578ed0de47522ad0b38e87031739c6a65caecc39ce3410bf3799e756a220f;
    uint256 nonce = 0x2882e7cb420e5424bf554832447223dc43aae09b1cf5b50de8d8385e7d43d0f;
    uint256 sessionId = 0x28a183c30acb760a226de203ddff3f2d50a79e589446841f010590e0794434ed;

    uint256[5] proof = [
        0x381236ea6b2ef1d3697ab7fb5f285505b52e7ed3a3b0155ef0a01d0922cb3480,
        0xd525669a85aee300ba1cd02257e371fb1f49b16cd00318a5826450ad5f44ac8,
        0xa3d8307cee3d1ece3d803ce27d46e36788e6862f18487e88e01b1e6ef6e83f25,
        0x3c57db0c9868886c91766850dd42acc4f3fdf4d4f9750304319a7da6352602c5,
        rootCorrect
    ];

    uint256[5] sessionProof = [
        0x518ec7114c28f1243086bc82e79d97fea23087dc26e33d324585e8a4315952d5,
        0x25420bc78b243ece38fe9e219014ad4eb5fe89852f52853b3430da1ef85f74bb,
        0x6c036f6f88f00e371e69c0c5b99d0331ad131721b74f1bd1fb478b44513082c5,
        0xe0a6a530acf85c094b52e46a7be17f43ef5c960383c76e989a1b9487066662,
        rootCorrect
    ];

    function setUp() public {
        address oprfKeyRegistry = address(new OprfKeyRegistryMock());
        address worldIDRegistryMock = address(new WorldIDRegistryMock());
        address credentialSchemaIssuerRegistryMock = address(new CredentialSchemaIssuerRegistryMock());
        verifier = address(new Verifier());
        proofTimestampDelta = 5 hours;

        WorldIdVerifier implementation = new WorldIdVerifier();
        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            WorldIdVerifier.initialize.selector,
            credentialSchemaIssuerRegistryMock,
            worldIDRegistryMock,
            oprfKeyRegistry,
            verifier,
            proofTimestampDelta
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        worldIDVerifier = WorldIdVerifier(address(proxy));
        worldIDVerifier.updateOprfKeyRegistry(oprfKeyRegistry);
    }

    function test_Success() public {
        vm.warp(proofTimestamp + 1 hours);
        worldIDVerifier.verify(
            nullifier, action, rpIdCorrect, nonce, signalHash, proofTimestamp, credentialIssuerIdCorrect, 0, proof
        );
    }

    function test_SessionSuccess() public {
        vm.warp(proofTimestamp + 1 hours);
        worldIDVerifier.verifySession(
            rpIdCorrect,
            nonce,
            signalHash,
            proofTimestamp,
            credentialIssuerIdCorrect,
            0,
            sessionId,
            [nullifier, action],
            sessionProof
        );
    }

    function test_WrongRpId() public {
        vm.warp(proofTimestamp + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(Verifier.ProofInvalid.selector));
        worldIDVerifier.verify(
            nullifier,
            action,
            rpIdWrong, // NOTE incorrect rp id
            nonce,
            signalHash,
            proofTimestamp,
            credentialIssuerIdCorrect,
            0,
            proof
        );
    }

    function test_WrongCredentialIssuer() public {
        vm.warp(proofTimestamp + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(Verifier.ProofInvalid.selector));
        worldIDVerifier.verify(
            nullifier,
            action,
            rpIdCorrect,
            nonce,
            signalHash,
            proofTimestamp,
            credentialIssuerIdWrong, // NOTE incorrect credential issuer id
            0,
            proof
        );
    }

    function test_WrongProof() public {
        uint256[5] memory brokenProof = [
            0x3282817e430906e0a5f73e22d404971f1e8701d4d4270f3d531f07d0d8819db8,
            0x79a6dee01c030080298a09adfd0294edc84f1650b68763d0aab5d6a1c1bbd8,
            0x850d06c33658c9d2cc0e873cb45ad5375a31a6661cd4a11d833466ffe79b8bdd,
            0x3282817e430906e0a5f73e22d404971f1e8701d4d4270f3d531f07d0d8819db8,
            rootCorrect
        ];
        vm.warp(proofTimestamp + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(Verifier.ProofInvalid.selector));
        worldIDVerifier.verify(
            nullifier, action, rpIdCorrect, nonce, signalHash, proofTimestamp, credentialIssuerIdCorrect, 0, brokenProof
        );
    }

    function test_InvalidRoot() public {
        uint256[5] memory invalidRootProof = proof;
        invalidRootProof[4] = rootWrong;

        vm.warp(proofTimestamp + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDVerifier.InvalidMerkleRoot.selector));

        worldIDVerifier.verify(
            nullifier,
            action,
            rpIdCorrect,
            nonce,
            signalHash,
            proofTimestamp,
            credentialIssuerIdCorrect,
            0,
            invalidRootProof
        );
    }

    function test_TimestampFuture() public {
        vm.warp(proofTimestamp - 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDVerifier.NullifierFromFuture.selector));
        worldIDVerifier.verify(
            nullifier, action, rpIdCorrect, nonce, signalHash, proofTimestamp, credentialIssuerIdCorrect, 0, proof
        );
    }

    function test_TimestampTooOld() public {
        vm.warp(proofTimestamp + 24 hours);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDVerifier.OutdatedNullifier.selector));
        worldIDVerifier.verify(
            nullifier, action, rpIdCorrect, nonce, signalHash, proofTimestamp, credentialIssuerIdCorrect, 0, proof
        );
    }
}
