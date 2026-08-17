// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {WorldIDVerifier} from "../../src/core/WorldIDVerifier.sol";
import {WorldIDVerifierV2} from "../../src/core/WorldIDVerifierV2.sol";
import {IWorldIDVerifierV2} from "../../src/core/interfaces/IWorldIDVerifierV2.sol";
import {Verifier} from "../../src/core/Verifier.sol";

import {Lib} from "../../src/crosschain/lib/Lib.sol";
import {
    CredentialSchemaIssuerRegistryMock,
    OprfKeyRegistryMock,
    WorldIDRegistryMock,
    WorldIDSatelliteHarness
} from "./SatelliteVerifierParity.t.sol";

import "../../src/crosschain/Error.sol";

/// @notice Regression tests for proof-domain separation on the satellite.
/// @dev The satellite reimplements the verification surface against bridged state, so it must enforce
///   the same conventions as the core verifier on World Chain: `verify` only accepts uniqueness-domain
///   actions (`0x00` prefix), `verifySession` only accepts session-domain actions (`0x02` prefix) bound
///   to a non-zero session. Before this was enforced, an ordinary proof was accepted through
///   `verifySession` with `sessionId == 0`, which any World ID can satisfy.
contract SatelliteSessionDomainSeparationTest is Test {
    bytes4 internal constant UPDATE_ROOT_SELECTOR = bytes4(keccak256("updateRoot(uint256,uint256,bytes32)"));
    bytes4 internal constant SET_ISSUER_PUBKEY_SELECTOR =
        bytes4(keccak256("setIssuerPubkey(uint64,uint256,uint256,bytes32)"));
    bytes4 internal constant SET_OPRF_KEY_SELECTOR = bytes4(keccak256("setOprfKey(uint160,uint256,uint256,bytes32)"));

    uint64 internal constant ISSUER_SCHEMA_ID = 1;
    uint64 internal constant RP_ID = 0x1a6ccf8f70e5de68;

    uint256 internal constant TREE_DEPTH = 30;
    uint256 internal constant ROOT_VALIDITY_WINDOW = 3600;
    uint64 internal constant MIN_EXPIRATION_THRESHOLD = 5 hours;

    uint256 internal constant ROOT = 0xaf727d9412a9d5c73b685fd09dc39e727064e65b8269b233009edfc105f9853;
    uint64 internal constant EXPIRES_AT_MIN = 0x699cfa47;

    uint256 internal constant NULLIFIER = 0x1bae01b23e5f0ee96151331fffb0550351c52e5ee0ced452c762e120723ae702;
    /// @dev MSB is `0x15`: neither the uniqueness domain (`0x00`) nor the session domain (`0x02`).
    uint256 internal constant ACTION = 0x15d4b66e5417cb9875f6a2b5be9814dca80651d7c74b3b21685fdd494566e79f;
    uint256 internal constant SIGNAL_HASH = 0x1578ed0de47522ad0b38e87031739c6a65caecc39ce3410bf3799e756a220f;
    uint256 internal constant NONCE = 0x18e3ab3d5fedc6eaa5e0d06a3a6f3dd5e0bf2d17b18b797a1cc6ff4706169d1e;

    uint256 internal constant ISSUER_PUBKEY_X = 0x252c8234509649bb469ecb7a7e758f306b41415f2d80d4d67967902d6f589a81;
    uint256 internal constant ISSUER_PUBKEY_Y = 0x230e4f93a5f1187639314dd25e595db06dc18de219cfaeb8cfdf81d4afe910d5;
    uint256 internal constant OPRF_PUBKEY_X = 0xac79da013272129ddceae6d20c0f579abd04b0a00160ed2be2151bf4014e8d;
    uint256 internal constant OPRF_PUBKEY_Y = 0x187ce5ac507fe0760e95d1893cc6ebf3a115eb9adeaa355c14cc52722a2275be;

    /// @dev The circuit's "no session" sentinel, satisfiable by any World ID.
    uint256 internal constant NO_SESSION = 0;

    uint256 internal constant SESSION_DOMAIN_MSB = 0x02 << 248;
    uint256 internal constant MSB_MASK = uint256(0xff) << 248;

    uint256[5] internal proof = [
        uint256(0x4906f4e17b969ef2cfc44bd96520f01a3f5c32972bca2e10b70e05e03e3d9f13),
        uint256(0xd6d9a3456e9af7d8f6f78eb3380deb8c93505c062f62fa18b8ef8a2ccb55db8),
        uint256(0xa92a48edeb327b190048648788de9a8eff0abed5dc93bee8881387da40571278),
        uint256(0x38f52985c393efb732be8f54b5f00f7f25370ac5945de84e0d8d2f2d298866b8),
        uint256(ROOT)
    ];

    WorldIDVerifierV2 internal coreV2;
    WorldIDSatelliteHarness internal satellite;

    function setUp() public {
        Verifier verifier = new Verifier();

        address worldIdRegistry = address(new WorldIDRegistryMock(TREE_DEPTH, ROOT));
        address issuerRegistry =
            address(new CredentialSchemaIssuerRegistryMock(ISSUER_SCHEMA_ID, ISSUER_PUBKEY_X, ISSUER_PUBKEY_Y));
        address oprfRegistry = address(new OprfKeyRegistryMock(uint160(RP_ID), OPRF_PUBKEY_X, OPRF_PUBKEY_Y));

        bytes memory initData = abi.encodeWithSelector(
            WorldIDVerifier.initialize.selector,
            issuerRegistry,
            worldIdRegistry,
            oprfRegistry,
            address(verifier),
            MIN_EXPIRATION_THRESHOLD
        );
        coreV2 = WorldIDVerifierV2(address(new ERC1967Proxy(address(new WorldIDVerifierV2()), initData)));

        satellite =
            new WorldIDSatelliteHarness(address(verifier), ROOT_VALIDITY_WINDOW, TREE_DEPTH, MIN_EXPIRATION_THRESHOLD);

        Lib.Commitment[] memory commits = new Lib.Commitment[](3);
        bytes32 proofId = bytes32(uint256(1));
        bytes32 blockHash = bytes32(uint256(0x1234));

        commits[0] = Lib.Commitment({
            blockHash: blockHash, data: abi.encodeWithSelector(UPDATE_ROOT_SELECTOR, ROOT, block.timestamp, proofId)
        });
        commits[1] = Lib.Commitment({
            blockHash: blockHash,
            data: abi.encodeWithSelector(
                SET_ISSUER_PUBKEY_SELECTOR, ISSUER_SCHEMA_ID, ISSUER_PUBKEY_X, ISSUER_PUBKEY_Y, proofId
            )
        });
        commits[2] = Lib.Commitment({
            blockHash: blockHash,
            data: abi.encodeWithSelector(SET_OPRF_KEY_SELECTOR, uint160(RP_ID), OPRF_PUBKEY_X, OPRF_PUBKEY_Y, proofId)
        });

        satellite.applyCommitments(commits);

        vm.warp(EXPIRES_AT_MIN + 1 hours);
    }

    /// @notice A non-session proof is rejected by `verifySession`, matching the core verifier.
    function test_verifySessionRejectsNonSessionAction() public {
        vm.expectRevert(InvalidAction.selector);
        satellite.verifySession(
            RP_ID, NONCE, SIGNAL_HASH, EXPIRES_AT_MIN, ISSUER_SCHEMA_ID, 0, 1, [NULLIFIER, ACTION], proof
        );

        vm.expectRevert(IWorldIDVerifierV2.InvalidAction.selector);
        coreV2.verifySession(
            RP_ID, NONCE, SIGNAL_HASH, EXPIRES_AT_MIN, ISSUER_SCHEMA_ID, 0, 1, [NULLIFIER, ACTION], proof
        );
    }

    function testFuzz_verifySessionRejectsNonSessionAction(uint256 action) public {
        vm.assume(uint8(action >> 248) != 0x02);

        vm.expectRevert(InvalidAction.selector);
        satellite.verifySession(
            RP_ID, NONCE, SIGNAL_HASH, EXPIRES_AT_MIN, ISSUER_SCHEMA_ID, 0, 1, [NULLIFIER, action], proof
        );
    }

    /// @notice A session-domain action bound to the "no session" sentinel proves nothing and is rejected.
    function test_verifySessionRejectsZeroSessionId() public {
        uint256 sessionAction = (ACTION & ~MSB_MASK) | SESSION_DOMAIN_MSB;

        vm.expectRevert(InvalidSessionId.selector);
        satellite.verifySession(
            RP_ID,
            NONCE,
            SIGNAL_HASH,
            EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            0,
            NO_SESSION,
            [NULLIFIER, sessionAction],
            proof
        );
    }

    /// @notice The mirror-image direction: `verify` only accepts uniqueness-domain actions.
    function test_verifyRejectsNonUniquenessAction() public {
        vm.expectRevert(InvalidAction.selector);
        satellite.verify(NULLIFIER, ACTION, RP_ID, NONCE, SIGNAL_HASH, EXPIRES_AT_MIN, ISSUER_SCHEMA_ID, 0, proof);

        vm.expectRevert(IWorldIDVerifierV2.InvalidAction.selector);
        coreV2.verify(NULLIFIER, ACTION, RP_ID, NONCE, SIGNAL_HASH, EXPIRES_AT_MIN, ISSUER_SCHEMA_ID, 0, proof);
    }

    function testFuzz_verifyRejectsNonUniquenessAction(uint256 action) public {
        vm.assume(uint8(action >> 248) != 0);

        vm.expectRevert(InvalidAction.selector);
        satellite.verify(NULLIFIER, action, RP_ID, NONCE, SIGNAL_HASH, EXPIRES_AT_MIN, ISSUER_SCHEMA_ID, 0, proof);
    }

    /// @notice `verifyProofAndSignals` stays the unconstrained escape hatch, on both sides.
    function test_verifyProofAndSignalsAcceptsAnyActionDomain() public view {
        satellite.verifyProofAndSignals(
            NULLIFIER, ACTION, RP_ID, NONCE, SIGNAL_HASH, EXPIRES_AT_MIN, ISSUER_SCHEMA_ID, 0, 0, proof
        );

        coreV2.verifyProofAndSignals(
            NULLIFIER, ACTION, RP_ID, NONCE, SIGNAL_HASH, EXPIRES_AT_MIN, ISSUER_SCHEMA_ID, 0, 0, proof
        );
    }
}
