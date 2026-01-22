// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {Verifier} from "../src/Verifier.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";
import {BabyJubJub} from "oprf-key-registry/src/BabyJubJub.sol";
import {Verifier as VerifierNullifier} from "../src/VerifierNullifier.sol";
import {IVerifierNullifier} from "../src/interfaces/IVerifierNullifier.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {CredentialSchemaIssuerRegistry} from "../src/CredentialSchemaIssuerRegistry.sol";
import {ICredentialSchemaIssuerRegistry} from "../src/interfaces/ICredentialSchemaIssuerRegistry.sol";

uint256 constant credentialIssuerIdCorrect = 1;
uint256 constant credentialIssuerIdWrong = 2;

uint64 constant rpIdCorrect = 3604927112168642455;
uint64 constant rpIdWrong = 2;

uint256 constant rootCorrect = 4959814736111706042728533661656003495359474679272202023690954858781105690707;
uint256 constant rootWrong = 2;

contract OprfKeyRegistryMock {
    function getOprfPublicKey(uint160 oprfKeyId) external view returns (BabyJubJub.Affine memory) {
        // TODO update for mapping of rpId to oprfKeyId
        if (oprfKeyId == rpIdCorrect) {
            return BabyJubJub.Affine({
                x: 0x1d988b77dfe70c867df95aede734b9c52cd99810f58ff109f9f13d9093cd58e2,
                y: 0x1c33af244fd6b4d1bec338f99a73b800633fbfa027b2b45811e715cd5b66994b
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
    function issuerSchemaIdToPubkey(uint256 issuerSchemaId)
        public
        view
        virtual
        returns (ICredentialSchemaIssuerRegistry.Pubkey memory)
    {
        if (issuerSchemaId == credentialIssuerIdCorrect) {
            return ICredentialSchemaIssuerRegistry.Pubkey(
                0x13792652ea0af01565bbb64d51607bf96447930b33e52d1bae28ad027dfddc15,
                0x1a03e277ea354e453878e02f6e151a7a497c53e6cd9772ad33829235f89d6496
            );
        } else {
            return ICredentialSchemaIssuerRegistry.Pubkey(
                0x1583c671e97dd91df79d8c5b311d452a3eec14932c89d9cff0364d5b98ef215e,
                0x3f5c610720cfa296066965732468ea34a8f7e3725899e1b4470c6b5a76321a3
            );
        }
    }
}

contract ProofVerifier is Test {
    Verifier public verifier;

    address public verifierNullifier;

    uint256 public proofTimestampDelta;

    uint256 sessionId = 0x0;
    uint256 nullifier = 0x18a48a7958bc33c7fb3f6351e52a76da4615cd366dabff91fec68e0df1e8cf42;
    uint256 proofTimestamp = 0x6970f9bf;
    uint64 rpId = 0x3207461bd9fc9797;
    uint256 action = 0x29271a44e95107ab7b69f320ea73605f7651ac5ee61927205999662e3f620bd3;
    uint256 oprfPublicKey_x = 0x1d988b77dfe70c867df95aede734b9c52cd99810f58ff109f9f13d9093cd58e2;
    uint256 oprfPublicKey_y = 0x1c33af244fd6b4d1bec338f99a73b800633fbfa027b2b45811e715cd5b66994b;
    uint256 signalHash = 0x1578ed0de47522ad0b38e87031739c6a65caecc39ce3410bf3799e756a220f;
    uint256 nonce = 0x2c42d5fb6f893752c1f8e6a7178a3400762a64039ded1af1190109a3f5e63a1b;

    uint256[4] proof = [
        0x3282817e430906e0a5f73e22d404971f1e8701d4d4270f3d531f07d0d8819db8,
        0x79a6dee01c030080298a09adfd0294edc84f1650b68763d0aab5d6a1c1bbd8,
        0x850d06c33658c9d2cc0e873cb45ad5375a31a6661cd4a11d833466ffe79b8bdd,
        0x2c4257a1f6ab47e8432f815b1a48e8e760b541d92a1bbd7cedf1fa2ec51b4eed
    ];

    function setUp() public {
        address oprfKeyRegistry = address(new OprfKeyRegistryMock());
        address worldIDRegistryMock = address(new WorldIDRegistryMock());
        address credentialSchemaIssuerRegistryMock = address(new CredentialSchemaIssuerRegistryMock());
        verifierNullifier = address(new VerifierNullifier());
        proofTimestampDelta = 5 hours;

        Verifier implementation = new Verifier();
        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            Verifier.initialize.selector,
            credentialSchemaIssuerRegistryMock,
            worldIDRegistryMock,
            oprfKeyRegistry,
            verifierNullifier,
            proofTimestampDelta
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        verifier = Verifier(address(proxy));
        verifier.updateOprfKeyRegistry(oprfKeyRegistry);
    }

    function test_Success() public {
        vm.warp(proofTimestamp + 1 hours);
        verifier.verify(
            nullifier,
            action,
            rpIdCorrect,
            sessionId,
            nonce,
            signalHash,
            rootCorrect,
            proofTimestamp,
            credentialIssuerIdCorrect,
            0,
            proof
        );
    }

    function test_WrongRpId() public {
        vm.warp(proofTimestamp + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IVerifierNullifier.ProofInvalid.selector));
        verifier.verify(
            nullifier,
            action,
            rpIdWrong, // NOTE incorrect rp id
            sessionId,
            nonce,
            signalHash,
            rootCorrect,
            proofTimestamp,
            credentialIssuerIdCorrect,
            0,
            proof
        );
    }

    function test_WrongCredentialIssuer() public {
        vm.warp(proofTimestamp + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IVerifierNullifier.ProofInvalid.selector));
        verifier.verify(
            nullifier,
            action,
            rpIdCorrect,
            sessionId,
            nonce,
            signalHash,
            rootCorrect,
            proofTimestamp,
            credentialIssuerIdWrong, // NOTE incorrect credential issuer id
            0,
            proof
        );
    }

    function test_WrongProof() public {
        uint256[4] memory brokenProof = [
            0x3282817e430906e0a5f73e22d404971f1e8701d4d4270f3d531f07d0d8819db8,
            0x79a6dee01c030080298a09adfd0294edc84f1650b68763d0aab5d6a1c1bbd8,
            0x850d06c33658c9d2cc0e873cb45ad5375a31a6661cd4a11d833466ffe79b8bdd,
            0x3282817e430906e0a5f73e22d404971f1e8701d4d4270f3d531f07d0d8819db8
        ];
        vm.warp(proofTimestamp + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IVerifierNullifier.ProofInvalid.selector));
        verifier.verify(
            nullifier,
            action,
            rpIdCorrect,
            sessionId,
            nonce,
            signalHash,
            rootCorrect,
            proofTimestamp,
            credentialIssuerIdCorrect,
            0,
            brokenProof
        );
    }

    function test_InvalidRoot() public {
        vm.warp(proofTimestamp + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IVerifier.InvalidMerkleRoot.selector));
        verifier.verify(
            nullifier,
            action,
            rpIdCorrect,
            sessionId,
            nonce,
            signalHash,
            rootWrong,
            proofTimestamp,
            credentialIssuerIdCorrect,
            0,
            proof
        );
    }

    function test_TimestampFuture() public {
        vm.warp(proofTimestamp - 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IVerifier.NullifierFromFuture.selector));
        verifier.verify(
            nullifier,
            action,
            rpIdCorrect,
            sessionId,
            nonce,
            signalHash,
            rootCorrect,
            proofTimestamp,
            credentialIssuerIdCorrect,
            0,
            proof
        );
    }

    function test_TimestampTooOld() public {
        vm.warp(proofTimestamp + 24 hours);
        vm.expectRevert(abi.encodeWithSelector(IVerifier.OutdatedNullifier.selector));
        verifier.verify(
            nullifier,
            action,
            rpIdCorrect,
            sessionId,
            nonce,
            signalHash,
            rootCorrect,
            proofTimestamp,
            credentialIssuerIdCorrect,
            0,
            proof
        );
    }
}
