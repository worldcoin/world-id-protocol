// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Verifier} from "../src/Verifier.sol";
import {OprfKeyGen} from "oprf-key-registry/src/OprfKeyGen.sol";
import {BabyJubJub} from "oprf-key-registry/src/BabyJubJub.sol";
import {Verifier as VerifierNullifier} from "../src/VerifierNullifier.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {CredentialSchemaIssuerRegistry} from "../src/CredentialSchemaIssuerRegistry.sol";

uint256 constant credentialIssuerIdCorrect = 1;
uint256 constant credentialIssuerIdWrong = 2;

uint64 constant rpIdCorrect = 17788574597335369983;
uint64 constant rpIdWrong = 2;

uint256 constant rootCorrect = 4959814736111706042728533661656003495359474679272202023690954858781105690707;
uint256 constant rootWrong = 2;

contract OprfKeyRegistryMock {
    function getOprfPublicKey(uint160 oprfKeyId) external view returns (BabyJubJub.Affine memory) {
        // TODO update for mapping of rpId to oprfKeyId
        if (oprfKeyId == rpIdCorrect) {
            return BabyJubJub.Affine({
                x: 0x2f6d3b9cfd75e5e3320da1b72f5b79c58e1f1e09a2694e453b3ce33c1a177957,
                y: 0x16ef9937250a3d05099d135515ecd0f1116ce760a4ae2737c2e5857eabd0519b
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
        returns (CredentialSchemaIssuerRegistry.Pubkey memory)
    {
        if (issuerSchemaId == credentialIssuerIdCorrect) {
            return CredentialSchemaIssuerRegistry.Pubkey({
                x: 0x2154832e9e7a0689923ec05cc6a548e9efde6d3202df65ae86606ea768655fa0,
                y: 0x2915e9fea96b5e6c8ab0d7b1b1670f7fc253c2d3236ce5d1fcc170d896c8c7e8
            });
        } else {
            return CredentialSchemaIssuerRegistry.Pubkey({
                x: 0x1583c671e97dd91df79d8c5b311d452a3eec14932c89d9cff0364d5b98ef215e,
                y: 0x3f5c610720cfa296066965732468ea34a8f7e3725899e1b4470c6b5a76321a3
            });
        }
    }
}

contract ProofVerifier is Test {
    Verifier public verifier;

    address public verifierNullifier;

    uint256 public proofTimestampDelta;

    uint256 sessionId = 0x2e48ba260f6ee4c1fc61db48cffda1d1abf65821e37eef35125a0298417a91c0;
    uint256 nullifier = 0x48611d24f30e734a57a6e3cc64908f48aa9e98f1b97e3a5ead88e4b5305c57a;
    uint256 proofTimestamp = 0x696e5409;
    uint64 rpId = 0xf6ddb6592eb648ff;
    uint256 action = 0x3ac892062c48339dd301947f75c02063e25b4ce859ebe1ef37027c6d60033d4;
    uint256 oprfPublicKey_x = 0x2f6d3b9cfd75e5e3320da1b72f5b79c58e1f1e09a2694e453b3ce33c1a177957;
    uint256 oprfPublicKey_y = 0x16ef9937250a3d05099d135515ecd0f1116ce760a4ae2737c2e5857eabd0519b;
    uint256 signalHash = 0x1578ed0de47522ad0b38e87031739c6a65caecc39ce3410bf3799e756a220f;
    uint256 nonce = 0x593651f65f824ac2b289e33d52f5a785c917afcaa89816e62229d5e84508c54;

    uint256[4] proof = [
        0x11a62a784302af372005a5f6bba5881b31305f3c13b82350ce02ed9bc127c4d0,
        0xd1d3fe4aec085b183afb7ab4508e52d87563d96a881636bca3d8e15afbce3ef,
        0x1d03401954bff6b2b46053fa08d5d3b60c935746a435307f8ca1dbef5add6947,
        0x4e7fbfd14327ce56399deeb81afe79c23527920e128b71f1e3e63f9f97641e6d
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
        vm.expectRevert(abi.encodeWithSelector(VerifierNullifier.ProofInvalid.selector));
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
        vm.expectRevert(abi.encodeWithSelector(VerifierNullifier.ProofInvalid.selector));
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
            0x11a62a784302af372005a5f6bba5881b31305f3c13b82350ce02ed9bc127c4d0,
            0xd1d3fe4aec085b183afb7ab4508e52d87563d96a881636bca3d8e15afbce3ef,
            0x1d03401954bff6b2b46053fa08d5d3b60c935746a435307f8ca1dbef5add6947,
            0x11a62a784302af372005a5f6bba5881b31305f3c13b82350ce02ed9bc127c4d0
        ];
        vm.warp(proofTimestamp + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(VerifierNullifier.ProofInvalid.selector));
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
        vm.expectRevert(abi.encodeWithSelector(Verifier.InvalidMerkleRoot.selector));
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
        vm.expectRevert(abi.encodeWithSelector(Verifier.NullifierFromFuture.selector));
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
        vm.expectRevert(abi.encodeWithSelector(Verifier.OutdatedNullifier.selector));
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
