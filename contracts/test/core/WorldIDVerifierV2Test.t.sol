// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {WorldIDVerifierV2} from "../../src/core/WorldIDVerifierV2Unreleased.sol";
import {WorldIDVerifier} from "../../src/core/WorldIDVerifier.sol";
import {IWorldIDVerifier} from "../../src/core/interfaces/IWorldIDVerifier.sol";
import {BabyJubJub} from "oprf-key-registry/src/BabyJubJub.sol";
import {Verifier} from "../../src/core/Verifier.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ICredentialSchemaIssuerRegistry} from "../../src/core/interfaces/ICredentialSchemaIssuerRegistry.sol";

import {
    OprfKeyRegistryMock,
    WorldIDRegistryMock,
    CredentialSchemaIssuerRegistryMock,
    credentialIssuerIdCorrect,
    rpIdCorrect,
    rootCorrect
} from "./WorldIDVerifierTest.t.sol";

contract WorldIDVerifierV2Test is Test {
    WorldIDVerifierV2 public verifier;

    uint256 nullifier = 0x1bae01b23e5f0ee96151331fffb0550351c52e5ee0ced452c762e120723ae702;
    uint64 expiresAtMin = 0x699cfa47;
    uint256 signalHash = 0x1578ed0de47522ad0b38e87031739c6a65caecc39ce3410bf3799e756a220f;
    uint256 nonce = 0x18e3ab3d5fedc6eaa5e0d06a3a6f3dd5e0bf2d17b18b797a1cc6ff4706169d1e;

    uint256[5] proof = [
        0x4906f4e17b969ef2cfc44bd96520f01a3f5c32972bca2e10b70e05e03e3d9f13,
        0xd6d9a3456e9af7d8f6f78eb3380deb8c93505c062f62fa18b8ef8a2ccb55db8,
        0xa92a48edeb327b190048648788de9a8eff0abed5dc93bee8881387da40571278,
        0x38f52985c393efb732be8f54b5f00f7f25370ac5945de84e0d8d2f2d298866b8,
        rootCorrect
    ];

    function setUp() public {
        address oprfKeyRegistry = address(new OprfKeyRegistryMock());
        address worldIDRegistryMock = address(new WorldIDRegistryMock());
        address credentialSchemaIssuerRegistryMock = address(new CredentialSchemaIssuerRegistryMock());
        address groth16Verifier = address(new Verifier());
        uint256 minExpirationThreshold = 5 hours;

        WorldIDVerifierV2 implementation = new WorldIDVerifierV2();
        bytes memory initData = abi.encodeWithSelector(
            WorldIDVerifier.initialize.selector,
            credentialSchemaIssuerRegistryMock,
            worldIDRegistryMock,
            oprfKeyRegistry,
            groth16Verifier,
            minExpirationThreshold
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        verifier = WorldIDVerifierV2(address(proxy));
        verifier.updateOprfKeyRegistry(oprfKeyRegistry);
    }

    function test_RevertsWhenActionFirstByteNonZero() public {
        uint256 action = 0x15d4b66e5417cb9875f6a2b5be9814dca80651d7c74b3b21685fdd494566e79f;

        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(WorldIDVerifierV2.InvalidAction.selector));
        verifier.verify(
            nullifier, action, rpIdCorrect, nonce, signalHash, expiresAtMin, credentialIssuerIdCorrect, 0, proof
        );
    }

    function testFuzz_RevertsWhenActionFirstByteNonZero(uint256 action) public {
        // Ensure the lowest byte is non-zero
        vm.assume(uint8(action >> 248) != 0);

        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(WorldIDVerifierV2.InvalidAction.selector));
        verifier.verify(
            nullifier, action, rpIdCorrect, nonce, signalHash, expiresAtMin, credentialIssuerIdCorrect, 0, proof
        );
    }

    function test_SessionRevertsWhenActionMissing0x02Prefix() public {
        // Action with 0x00 prefix (valid for uniqueness, not for session)
        uint256 action = 0x00d4b66e5417cb9875f6a2b5be9814dca80651d7c74b3b21685fdd494566e7;
        uint256 sessionId = 1;

        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(WorldIDVerifierV2.InvalidAction.selector));
        verifier.verifySession(
            rpIdCorrect,
            nonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            sessionId,
            [nullifier, action],
            proof
        );
    }

    function testFuzz_SessionRevertsWhenActionPrefixNot0x02(uint256 action) public {
        vm.assume(uint8(action >> 248) != 2);
        uint256 sessionId = 1;

        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(WorldIDVerifierV2.InvalidAction.selector));
        verifier.verifySession(
            rpIdCorrect,
            nonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            sessionId,
            [nullifier, action],
            proof
        );
    }

    function test_SessionPassesActionCheckWhenFirstByte0x02() public {
        // Action with correct 0x02 prefix — passes prefix check but fails proof verification
        uint256 action = 0x0200000000000000000000000000000000000000000000000000000000000001;
        uint256 sessionId = 1;

        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(Verifier.ProofInvalid.selector));
        verifier.verifySession(
            rpIdCorrect,
            nonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            sessionId,
            [nullifier, action],
            proof
        );
    }

    function test_PassesActionCheckWhenFirstByteZero() public {
        // passes the prefix check but fails proof verification
        uint256 action = 0x00d4b66e5417cb9875f6a2b5be9814dca80651d7c74b3b21685fdd494566e7;

        vm.warp(expiresAtMin + 1 hours);
        // Should NOT revert with InvalidAction — reverts later in proof verification
        vm.expectRevert(abi.encodeWithSelector(Verifier.ProofInvalid.selector));
        verifier.verify(
            nullifier, action, rpIdCorrect, nonce, signalHash, expiresAtMin, credentialIssuerIdCorrect, 0, proof
        );
    }
}
