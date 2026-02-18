// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {WorldIDVerifier} from "../../src/core/WorldIDVerifier.sol";
import {Verifier} from "../../src/core/Verifier.sol";
import {ICredentialSchemaIssuerRegistry} from "../../src/core/interfaces/ICredentialSchemaIssuerRegistry.sol";
import {BabyJubJub} from "oprf-key-registry/src/BabyJubJub.sol";

import {WorldIDSatellite} from "../../src/crosschain/Satellite.sol";
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
    uint64 internal constant RP_ID = 0x53a9a80aba3b204;

    uint256 internal constant TREE_DEPTH = 30;
    uint256 internal constant ROOT_VALIDITY_WINDOW = 3600;
    uint64 internal constant MIN_EXPIRATION_THRESHOLD = 5 hours;

    uint256 internal constant ROOT = 0xaf727d9412a9d5c73b685fd09dc39e727064e65b8269b233009edfc105f9853;
    uint64 internal constant EXPIRES_AT_MIN = 0x6980a43f;

    uint256 internal constant NULLIFIER = 0x104b3a1c8e29cca4c7279df4831ac6c20a4d841e069c3ccdce2c1ac88d55b5a;
    uint256 internal constant ACTION = 0x2e22e1a5485379a647255f72583f9120788c61e9c42413b7555f20d75cd34408;
    uint256 internal constant SIGNAL_HASH = 0x1578ed0de47522ad0b38e87031739c6a65caecc39ce3410bf3799e756a220f;
    uint256 internal constant NONCE = 0x2882e7cb420e5424bf554832447223dc43aae09b1cf5b50de8d8385e7d43d0f;

    uint256 internal constant ISSUER_PUBKEY_X = 0xae7ba7c51efaa3c6b215c9cf0d148e6c01091bc0001a4da342e4f872591a105;
    uint256 internal constant ISSUER_PUBKEY_Y = 0x24b378870638c68d90b3f7d8acbf540d2262af52ad1bbe64370931c280bab0d;
    uint256 internal constant OPRF_PUBKEY_X = 0xf6fd2a88ea804c58be59ad3515982c07b5a6524311906ad69e3ef50f7a32d59;
    uint256 internal constant OPRF_PUBKEY_Y = 0x17cb049e14cdfd8009641892e6ee9ee33e564e6c675e47a89922c818cc603c68;

    uint256[5] internal proof = [
        uint256(0x381236ea6b2ef1d3697ab7fb5f285505b52e7ed3a3b0155ef0a01d0922cb3480),
        uint256(0xd525669a85aee300ba1cd02257e371fb1f49b16cd00318a5826450ad5f44ac8),
        uint256(0xa3d8307cee3d1ece3d803ce27d46e36788e6862f18487e88e01b1e6ef6e83f25),
        uint256(0x3c57db0c9868886c91766850dd42acc4f3fdf4d4f9750304319a7da6352602c5),
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
