// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {WorldIDVerifier} from "../../src/core/WorldIDVerifier.sol";
import {Verifier} from "../../src/core/Verifier.sol";
import {ICredentialSchemaIssuerRegistry} from "../../src/core/interfaces/ICredentialSchemaIssuerRegistry.sol";
import {BabyJubJub} from "oprf-key-registry/src/BabyJubJub.sol";

import {WorldIDSatellite} from "../../src/crosschain/WorldIDSatellite.sol";
import {Lib} from "../../src/crosschain/lib/Lib.sol";

contract WorldIDRegistryMock {
    uint256 private immutable _treeDepth;
    uint256 private immutable _root;

    constructor(uint256 treeDepth_, uint256 root_) {
        _treeDepth = treeDepth_;
        _root = root_;
    }

    function getTreeDepth() external view returns (uint256) {
        return _treeDepth;
    }

    function isValidRoot(uint256 root) external view returns (bool) {
        return root == _root;
    }
}

contract CredentialSchemaIssuerRegistryMock {
    uint64 private immutable _issuerSchemaId;
    ICredentialSchemaIssuerRegistry.Pubkey private _pubkey;

    constructor(uint64 issuerSchemaId_, uint256 x_, uint256 y_) {
        _issuerSchemaId = issuerSchemaId_;
        _pubkey = ICredentialSchemaIssuerRegistry.Pubkey({x: x_, y: y_});
    }

    function issuerSchemaIdToPubkey(uint64 issuerSchemaId)
        external
        view
        returns (ICredentialSchemaIssuerRegistry.Pubkey memory)
    {
        if (issuerSchemaId == _issuerSchemaId) {
            return _pubkey;
        }
        return ICredentialSchemaIssuerRegistry.Pubkey({x: 0, y: 0});
    }
}

contract OprfKeyRegistryMock {
    uint160 private immutable _oprfKeyId;
    BabyJubJub.Affine private _pubkey;

    constructor(uint160 oprfKeyId_, uint256 x_, uint256 y_) {
        _oprfKeyId = oprfKeyId_;
        _pubkey = BabyJubJub.Affine({x: x_, y: y_});
    }

    function getOprfPublicKey(uint160 oprfKeyId) external view returns (BabyJubJub.Affine memory) {
        if (oprfKeyId == _oprfKeyId) {
            return _pubkey;
        }
        return BabyJubJub.Affine({x: 0, y: 0});
    }
}

contract WorldIDSatelliteHarness is WorldIDSatellite {
    constructor(address verifier_, uint256 rootValidityWindow_, uint256 treeDepth_, uint64 minExpirationThreshold_)
        WorldIDSatellite(verifier_, rootValidityWindow_, treeDepth_, minExpirationThreshold_)
    {}

    function applyCommitments(Lib.Commitment[] memory commits) external {
        _applyAndCommit(commits);
    }
}

contract SatelliteVerifierParityTest is Test {
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
    uint256 internal constant ACTION = 0x15d4b66e5417cb9875f6a2b5be9814dca80651d7c74b3b21685fdd494566e79f;
    uint256 internal constant SIGNAL_HASH = 0x1578ed0de47522ad0b38e87031739c6a65caecc39ce3410bf3799e756a220f;
    uint256 internal constant NONCE = 0x18e3ab3d5fedc6eaa5e0d06a3a6f3dd5e0bf2d17b18b797a1cc6ff4706169d1e;

    uint256 internal constant ISSUER_PUBKEY_X = 0x252c8234509649bb469ecb7a7e758f306b41415f2d80d4d67967902d6f589a81;
    uint256 internal constant ISSUER_PUBKEY_Y = 0x230e4f93a5f1187639314dd25e595db06dc18de219cfaeb8cfdf81d4afe910d5;
    uint256 internal constant OPRF_PUBKEY_X = 0xac79da013272129ddceae6d20c0f579abd04b0a00160ed2be2151bf4014e8d;
    uint256 internal constant OPRF_PUBKEY_Y = 0x187ce5ac507fe0760e95d1893cc6ebf3a115eb9adeaa355c14cc52722a2275be;

    uint256[5] internal proof = [
        uint256(0x4906f4e17b969ef2cfc44bd96520f01a3f5c32972bca2e10b70e05e03e3d9f13),
        uint256(0xd6d9a3456e9af7d8f6f78eb3380deb8c93505c062f62fa18b8ef8a2ccb55db8),
        uint256(0xa92a48edeb327b190048648788de9a8eff0abed5dc93bee8881387da40571278),
        uint256(0x38f52985c393efb732be8f54b5f00f7f25370ac5945de84e0d8d2f2d298866b8),
        uint256(ROOT)
    ];

    WorldIDVerifier internal coreVerifier;
    WorldIDSatelliteHarness internal satellite;

    function setUp() public {
        Verifier verifier = new Verifier();

        address worldIdRegistry = address(new WorldIDRegistryMock(TREE_DEPTH, ROOT));
        address issuerRegistry =
            address(new CredentialSchemaIssuerRegistryMock(ISSUER_SCHEMA_ID, ISSUER_PUBKEY_X, ISSUER_PUBKEY_Y));
        address oprfRegistry = address(new OprfKeyRegistryMock(uint160(RP_ID), OPRF_PUBKEY_X, OPRF_PUBKEY_Y));

        WorldIDVerifier implementation = new WorldIDVerifier();
        bytes memory initData = abi.encodeWithSelector(
            WorldIDVerifier.initialize.selector,
            issuerRegistry,
            worldIdRegistry,
            oprfRegistry,
            address(verifier),
            MIN_EXPIRATION_THRESHOLD
        );
        coreVerifier = WorldIDVerifier(address(new ERC1967Proxy(address(implementation), initData)));

        satellite =
            new WorldIDSatelliteHarness(address(verifier), ROOT_VALIDITY_WINDOW, TREE_DEPTH, MIN_EXPIRATION_THRESHOLD);

        // Bridge equivalent root + issuer key + OPRF key state into the satellite.
        // Important: we set OPRF at key == issuerSchemaId to mirror satellite's current lookup path.
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
            data: abi.encodeWithSelector(
                SET_OPRF_KEY_SELECTOR, uint160(ISSUER_SCHEMA_ID), OPRF_PUBKEY_X, OPRF_PUBKEY_Y, proofId
            )
        });

        satellite.applyCommitments(commits);
    }

    /// @notice Intentionally failing regression test:
    ///   bridges OPRF key at `rpId` (canonical contract behavior) and expects satellite verification parity.
    ///   It fails today because satellite reads OPRF key by `issuerSchemaId`.
    function test_keyIdentityMismatch() public {
        WorldIDSatelliteHarness satelliteWithRpKey = new WorldIDSatelliteHarness(
            coreVerifier.getVerifier(), ROOT_VALIDITY_WINDOW, TREE_DEPTH, MIN_EXPIRATION_THRESHOLD
        );

        Lib.Commitment[] memory commits = new Lib.Commitment[](3);
        bytes32 proofId = bytes32(uint256(2));
        bytes32 blockHash = bytes32(uint256(0x5678));

        commits[0] = Lib.Commitment({
            blockHash: blockHash, data: abi.encodeWithSelector(UPDATE_ROOT_SELECTOR, ROOT, block.timestamp, proofId)
        });
        commits[1] = Lib.Commitment({
            blockHash: blockHash,
            data: abi.encodeWithSelector(
                SET_ISSUER_PUBKEY_SELECTOR, ISSUER_SCHEMA_ID, ISSUER_PUBKEY_X, ISSUER_PUBKEY_Y, proofId
            )
        });
        // Canonical mapping: oprfKeyId == rpId (as in WorldIDVerifier)
        commits[2] = Lib.Commitment({
            blockHash: blockHash,
            data: abi.encodeWithSelector(SET_OPRF_KEY_SELECTOR, uint160(RP_ID), OPRF_PUBKEY_X, OPRF_PUBKEY_Y, proofId)
        });

        satelliteWithRpKey.applyCommitments(commits);

        vm.warp(EXPIRES_AT_MIN + 1 hours);

        // Canonical verifier accepts this proof.
        coreVerifier.verify(NULLIFIER, ACTION, RP_ID, NONCE, SIGNAL_HASH, EXPIRES_AT_MIN, ISSUER_SCHEMA_ID, 0, proof);

        // Expected parity behavior: this should also verify on satellite.
        // Current behavior: reverts UnregisteredOprfKeyId() because satellite looks up by issuerSchemaId.
        satelliteWithRpKey.verify(
            NULLIFIER, ACTION, RP_ID, NONCE, SIGNAL_HASH, EXPIRES_AT_MIN, ISSUER_SCHEMA_ID, 0, proof
        );
    }
}
