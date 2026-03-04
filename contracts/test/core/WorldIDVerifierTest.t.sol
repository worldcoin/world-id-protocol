// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {WorldIDVerifier as WorldIdVerifier} from "../../src/core/WorldIDVerifier.sol";
import {IWorldIDVerifier} from "../../src/core/interfaces/IWorldIDVerifier.sol";
import {BabyJubJub} from "oprf-key-registry/src/BabyJubJub.sol";
import {Verifier} from "../../src/core/Verifier.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {CredentialSchemaIssuerRegistry} from "../../src/core/CredentialSchemaIssuerRegistry.sol";
import {ICredentialSchemaIssuerRegistry} from "../../src/core/interfaces/ICredentialSchemaIssuerRegistry.sol";

uint64 constant credentialIssuerIdCorrect = 1;
uint64 constant credentialIssuerIdWrong = 2;

uint64 constant rpIdCorrect = 0x1a6ccf8f70e5de68;
uint64 constant rpIdWrong = 2;

uint256 constant rootCorrect = 0xaf727d9412a9d5c73b685fd09dc39e727064e65b8269b233009edfc105f9853;
uint256 constant rootWrong = 2;

contract OprfKeyRegistryMock {
    function getOprfPublicKey(uint160 oprfKeyId) external view returns (BabyJubJub.Affine memory) {
        // TODO update for mapping of rpId to oprfKeyId
        if (oprfKeyId == rpIdCorrect) {
            return BabyJubJub.Affine({
                x: 0xac79da013272129ddceae6d20c0f579abd04b0a00160ed2be2151bf4014e8d,
                y: 0x187ce5ac507fe0760e95d1893cc6ebf3a115eb9adeaa355c14cc52722a2275be
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
                x: 0x252c8234509649bb469ecb7a7e758f306b41415f2d80d4d67967902d6f589a81,
                y: 0x230e4f93a5f1187639314dd25e595db06dc18de219cfaeb8cfdf81d4afe910d5
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

    uint256 public minExpirationThreshold;

    uint256 nullifier = 0x1bae01b23e5f0ee96151331fffb0550351c52e5ee0ced452c762e120723ae702;
    uint64 expiresAtMin = 0x699cfa47;
    uint256 action = 0x15d4b66e5417cb9875f6a2b5be9814dca80651d7c74b3b21685fdd494566e79f;
    uint256 signalHash = 0x1578ed0de47522ad0b38e87031739c6a65caecc39ce3410bf3799e756a220f;
    uint256 nonce = 0x18e3ab3d5fedc6eaa5e0d06a3a6f3dd5e0bf2d17b18b797a1cc6ff4706169d1e;
    uint256 sessionId = 0x2025d8e786806a895f7e50ce403f7d6e33e501772b28116908ad6fa5108172f8;

    uint256[5] proof = [
        0x4906f4e17b969ef2cfc44bd96520f01a3f5c32972bca2e10b70e05e03e3d9f13,
        0xd6d9a3456e9af7d8f6f78eb3380deb8c93505c062f62fa18b8ef8a2ccb55db8,
        0xa92a48edeb327b190048648788de9a8eff0abed5dc93bee8881387da40571278,
        0x38f52985c393efb732be8f54b5f00f7f25370ac5945de84e0d8d2f2d298866b8,
        rootCorrect
    ];

    uint256[5] sessionProof = [
        0x4533f8d38447da676c8eac8ec01ce031af1cc140d8397f3baf792be414c28790,
        0xe05c9ada0f2a3ebb5863f0a3412aa852cea67099ce26bb46c44b264af5b6927,
        0x178bbfe59fc10b5ec4359ecb21b9f42fb8afef08e90cd3dec903fdd45cddc930,
        0x409b8908726ca9151d021fcecc882a3f5e93ba35f6043ad0bd51258b55e5018b,
        rootCorrect
    ];

    function setUp() public {
        address oprfKeyRegistry = address(new OprfKeyRegistryMock());
        address worldIDRegistryMock = address(new WorldIDRegistryMock());
        address credentialSchemaIssuerRegistryMock = address(new CredentialSchemaIssuerRegistryMock());
        verifier = address(new Verifier());
        minExpirationThreshold = 5 hours;

        WorldIdVerifier implementation = new WorldIdVerifier();
        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            WorldIdVerifier.initialize.selector,
            credentialSchemaIssuerRegistryMock,
            worldIDRegistryMock,
            oprfKeyRegistry,
            verifier,
            minExpirationThreshold
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        worldIDVerifier = WorldIdVerifier(address(proxy));
        worldIDVerifier.updateOprfKeyRegistry(oprfKeyRegistry);
    }

    function test_Success() public {
        vm.warp(expiresAtMin + 1 hours);
        worldIDVerifier.verify(
            nullifier, action, rpIdCorrect, nonce, signalHash, expiresAtMin, credentialIssuerIdCorrect, 0, proof
        );
    }

    function test_SessionSuccess() public {
        vm.warp(expiresAtMin + 1 hours);
        worldIDVerifier.verifySession(
            rpIdCorrect,
            nonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            sessionId,
            [nullifier, action],
            sessionProof
        );
    }

    function test_WrongRpId() public {
        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(Verifier.ProofInvalid.selector));
        worldIDVerifier.verify(
            nullifier,
            action,
            rpIdWrong, // NOTE incorrect rp id
            nonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            proof
        );
    }

    function test_WrongCredentialIssuer() public {
        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(Verifier.ProofInvalid.selector));
        worldIDVerifier.verify(
            nullifier,
            action,
            rpIdCorrect,
            nonce,
            signalHash,
            expiresAtMin,
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
        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(Verifier.ProofInvalid.selector));
        worldIDVerifier.verify(
            nullifier, action, rpIdCorrect, nonce, signalHash, expiresAtMin, credentialIssuerIdCorrect, 0, brokenProof
        );
    }

    function test_InvalidRoot() public {
        uint256[5] memory invalidRootProof = proof;
        invalidRootProof[4] = rootWrong;

        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDVerifier.InvalidMerkleRoot.selector));

        worldIDVerifier.verify(
            nullifier,
            action,
            rpIdCorrect,
            nonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            invalidRootProof
        );
    }

    function test_ExpiresAtTooOld() public {
        vm.warp(expiresAtMin + 24 hours);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDVerifier.ExpirationTooOld.selector));
        worldIDVerifier.verify(
            nullifier, action, rpIdCorrect, nonce, signalHash, expiresAtMin, credentialIssuerIdCorrect, 0, proof
        );
    }

    function test_SessionWrongRpId() public {
        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(Verifier.ProofInvalid.selector));
        worldIDVerifier.verifySession(
            rpIdWrong, // NOTE incorrect rp id
            nonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            sessionId,
            [nullifier, action],
            sessionProof
        );
    }

    function test_SessionWrongCredentialIssuer() public {
        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(Verifier.ProofInvalid.selector));
        worldIDVerifier.verifySession(
            rpIdCorrect,
            nonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdWrong, // NOTE incorrect credential issuer id
            0,
            sessionId,
            [nullifier, action],
            sessionProof
        );
    }

    function test_SessionWrongProof() public {
        uint256[5] memory brokenProof = [
            0x3282817e430906e0a5f73e22d404971f1e8701d4d4270f3d531f07d0d8819db8,
            0x79a6dee01c030080298a09adfd0294edc84f1650b68763d0aab5d6a1c1bbd8,
            0x850d06c33658c9d2cc0e873cb45ad5375a31a6661cd4a11d833466ffe79b8bdd,
            0x3282817e430906e0a5f73e22d404971f1e8701d4d4270f3d531f07d0d8819db8,
            rootCorrect
        ];
        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(Verifier.ProofInvalid.selector));
        worldIDVerifier.verifySession(
            rpIdCorrect,
            nonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            sessionId,
            [nullifier, action],
            brokenProof
        );
    }

    function test_SessionInvalidRoot() public {
        uint256[5] memory invalidRootProof = sessionProof;
        invalidRootProof[4] = rootWrong;

        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDVerifier.InvalidMerkleRoot.selector));

        worldIDVerifier.verifySession(
            rpIdCorrect,
            nonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            sessionId,
            [nullifier, action],
            invalidRootProof
        );
    }

    function test_SessionExpiresAtTooOld() public {
        vm.warp(expiresAtMin + 24 hours);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDVerifier.ExpirationTooOld.selector));
        worldIDVerifier.verifySession(
            rpIdCorrect,
            nonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            sessionId,
            [nullifier, action],
            sessionProof
        );
    }

    // UpdateOprfKeyRegistry Tests

    function test_UpdateOprfKeyRegistry() public {
        OprfKeyRegistryMock newOprfKeyRegistry = new OprfKeyRegistryMock();
        address oldOprfKeyRegistry = worldIDVerifier.getOprfKeyRegistry();

        vm.expectEmit(true, true, false, true);
        emit IWorldIDVerifier.OprfKeyRegistryUpdated(oldOprfKeyRegistry, address(newOprfKeyRegistry));

        worldIDVerifier.updateOprfKeyRegistry(address(newOprfKeyRegistry));

        assertEq(worldIDVerifier.getOprfKeyRegistry(), address(newOprfKeyRegistry));
    }

    function test_CannotUpdateOprfKeyRegistryToZeroAddress() public {
        vm.expectRevert();
        worldIDVerifier.updateOprfKeyRegistry(address(0));
    }

    function test_OnlyOwnerCanUpdateOprfKeyRegistry() public {
        OprfKeyRegistryMock newOprfKeyRegistry = new OprfKeyRegistryMock();
        address nonOwner = vm.addr(0xFFFF);
        address oldOprfKeyRegistry = worldIDVerifier.getOprfKeyRegistry();

        vm.prank(nonOwner);
        vm.expectRevert();
        worldIDVerifier.updateOprfKeyRegistry(address(newOprfKeyRegistry));

        // Verify it wasn't updated
        assertEq(worldIDVerifier.getOprfKeyRegistry(), oldOprfKeyRegistry);
    }
}
