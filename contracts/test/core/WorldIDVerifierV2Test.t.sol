// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {WorldIDVerifierV2} from "../../src/core/WorldIDVerifierV2.sol";
import {WorldIDVerifier} from "../../src/core/WorldIDVerifier.sol";
import {IWorldIDVerifier} from "../../src/core/interfaces/IWorldIDVerifier.sol";
import {IWorldIDVerifierV2} from "../../src/core/interfaces/IWorldIDVerifierV2.sol";
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

    uint256 nullifier = 0x5968cd4d3c50bfd2305671d1092bee10ccb679b93db3ca779b6477e4885e476;
    uint64 expiresAtMin = 0x6a54cd68;
    uint256 signalHash = 0x1578ed0de47522ad0b38e87031739c6a65caecc39ce3410bf3799e756a220f;
    uint256 nonce = 0x38ed3d4d95deac6e369dde48890d5b14b49a2d26a0b2e8854d429ff7c52cf99;
    uint256 actionCorrect = 0x978cc65f06353d8543971b65da8751833ff1253a192f58bed14f2739c0a345;
    uint256 sessionIdCorrect = 0x2018a266d26fbc1cd41743cc3126321302b8f0af39c367fe5718eeafb341d494;

    uint256[5] proof = [
        0x2a184f5930f2b6a0f367f649a80757e081b3fb28b76fffcfe325d82df87395b3,
        0xf6849ab589365a7537beeb70014958ae261fe2dd7fdbf5c4823c6b527aefa34,
        0xac5ee090f2ee180619c5c9825f22cee8873fc0d4764b7b0c5ffd7802d8f2e0f9,
        0x4a221ef1d3b5522ac95f38db43afda6863d34836f7a8cff0b50aa9c8ca52e727,
        rootCorrect
    ];

    // Uniqueness proof over the same request as `proof`, bound to `sessionIdCorrect`
    // (the session commitment is its `session_id` public signal).
    uint256[5] boundProof = [
        0x3de969d8cdd738c55fd10ccbd127b8cb41d21dc9f827b83e0063e3dcb84e8d3c,
        0x16861d8a24289d3b35f3939bc11162379e7ba20afed09cd2ac87a0bd4bff5194,
        0x94ec109be9e4e3a6a3199ecde261bf300f9f04ccfee6401ebf3689272ed907d,
        0x42010c88d24d3cb7ef95c32b49ccee40acdc083f8d8b3c3a26164bff52dfb699,
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
        vm.expectRevert(abi.encodeWithSelector(IWorldIDVerifierV2.InvalidAction.selector));
        verifier.verify(
            nullifier, action, rpIdCorrect, nonce, signalHash, expiresAtMin, credentialIssuerIdCorrect, 0, proof
        );
    }

    function testFuzz_RevertsWhenActionFirstByteNonZero(uint256 action) public {
        // Ensure the lowest byte is non-zero
        vm.assume(uint8(action >> 248) != 0);

        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDVerifierV2.InvalidAction.selector));
        verifier.verify(
            nullifier, action, rpIdCorrect, nonce, signalHash, expiresAtMin, credentialIssuerIdCorrect, 0, proof
        );
    }

    function test_SessionRevertsWhenActionMissing0x02Prefix() public {
        // Action with 0x00 prefix (valid for uniqueness, not for session)
        uint256 action = 0x00d4b66e5417cb9875f6a2b5be9814dca80651d7c74b3b21685fdd494566e7;
        uint256 sessionId = 1;

        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDVerifierV2.InvalidAction.selector));
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
        vm.expectRevert(abi.encodeWithSelector(IWorldIDVerifierV2.InvalidAction.selector));
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

    function test_BoundRevertsWhenActionFirstByteNonZero() public {
        uint256 action = 0x15d4b66e5417cb9875f6a2b5be9814dca80651d7c74b3b21685fdd494566e79f;
        uint256 sessionId = 1;

        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDVerifierV2.InvalidAction.selector));
        verifier.verifyWithSession(
            nullifier,
            action,
            rpIdCorrect,
            nonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            sessionId,
            proof
        );
    }

    function test_BoundRevertsWhenSessionIdZero() public {
        // Valid uniqueness action prefix, but a zero session id must not pass —
        // it would silently degrade to unbound verify() semantics.
        uint256 action = 0x00d4b66e5417cb9875f6a2b5be9814dca80651d7c74b3b21685fdd494566e7;

        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDVerifierV2.InvalidSessionId.selector));
        verifier.verifyWithSession(
            nullifier, action, rpIdCorrect, nonce, signalHash, expiresAtMin, credentialIssuerIdCorrect, 0, 0, proof
        );
    }

    function test_BoundPassesChecksWhenValid() public {
        // 0x00 action prefix and non-zero session id — passes both checks,
        // reverts later in proof verification
        uint256 action = 0x00d4b66e5417cb9875f6a2b5be9814dca80651d7c74b3b21685fdd494566e7;
        uint256 sessionId = 1;

        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(Verifier.ProofInvalid.selector));
        verifier.verifyWithSession(
            nullifier,
            action,
            rpIdCorrect,
            nonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            sessionId,
            proof
        );
    }

    function test_BoundSuccess() public {
        vm.warp(expiresAtMin + 1 hours);
        verifier.verifyWithSession(
            nullifier,
            actionCorrect,
            rpIdCorrect,
            nonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            sessionIdCorrect,
            boundProof
        );
    }

    function test_BoundRejectedByVerify() public {
        // The bound proof commits to the session id, while verify() pins the signal to 0
        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(Verifier.ProofInvalid.selector));
        verifier.verify(
            nullifier,
            actionCorrect,
            rpIdCorrect,
            nonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            boundProof
        );
    }

    function test_UnboundRejectedByVerifyWithSession() public {
        // The unbound proof commits to a session id of 0
        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(Verifier.ProofInvalid.selector));
        verifier.verifyWithSession(
            nullifier,
            actionCorrect,
            rpIdCorrect,
            nonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            sessionIdCorrect,
            proof
        );
    }

    function test_BoundWrongSessionId() public {
        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(Verifier.ProofInvalid.selector));
        verifier.verifyWithSession(
            nullifier,
            actionCorrect,
            rpIdCorrect,
            nonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            sessionIdCorrect + 1, // NOTE incorrect session id
            boundProof
        );
    }
}
