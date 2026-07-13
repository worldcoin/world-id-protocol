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

uint64 constant rpIdCorrect = 0x387df34f862cd4e;
uint64 constant rpIdWrong = 2;

uint256 constant rootCorrect = 0xaf727d9412a9d5c73b685fd09dc39e727064e65b8269b233009edfc105f9853;
uint256 constant rootWrong = 2;

contract OprfKeyRegistryMock {
    function getOprfPublicKey(uint160 oprfKeyId) external view returns (BabyJubJub.Affine memory) {
        // TODO update for mapping of rpId to oprfKeyId
        if (oprfKeyId == rpIdCorrect) {
            return BabyJubJub.Affine({
                x: 0x24a3480be33ae5a83f68fbefe658e65053cbe99ee442c178859070a23372a4d4,
                y: 0x2fc70cc380d5bb9d8537a8fd82e98fb29eb837ff3943f5704ec3957f444ec6cd
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
                x: 0xf178f8128469f6be2f108a02b2a3f96d107d9466c4f95460ed7d4e8f10384b3,
                y: 0x21b8a276d0b75460b075f4a4cc1961938e62f4964bcca87cffce8ada4d6e11d5
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

    uint256 nullifier = 0x5968cd4d3c50bfd2305671d1092bee10ccb679b93db3ca779b6477e4885e476;
    uint64 expiresAtMin = 0x6a54cd68;
    uint256 action = 0x978cc65f06353d8543971b65da8751833ff1253a192f58bed14f2739c0a345;
    uint256 signalHash = 0x1578ed0de47522ad0b38e87031739c6a65caecc39ce3410bf3799e756a220f;
    uint256 nonce = 0x38ed3d4d95deac6e369dde48890d5b14b49a2d26a0b2e8854d429ff7c52cf99;
    uint256 sessionId = 0x2018a266d26fbc1cd41743cc3126321302b8f0af39c367fe5718eeafb341d494;
    uint256 sessionNonce = 0xa138dc568a2548155f3991625ddec3b466d2a49b19d6ff26a94ba0310cdf5ba;

    uint256[5] proof = [
        0x2a184f5930f2b6a0f367f649a80757e081b3fb28b76fffcfe325d82df87395b3,
        0xf6849ab589365a7537beeb70014958ae261fe2dd7fdbf5c4823c6b527aefa34,
        0xac5ee090f2ee180619c5c9825f22cee8873fc0d4764b7b0c5ffd7802d8f2e0f9,
        0x4a221ef1d3b5522ac95f38db43afda6863d34836f7a8cff0b50aa9c8ca52e727,
        rootCorrect
    ];

    uint256[5] sessionProof = [
        0x4930872a26a12446d943042e1958e65d4b3eecca9bf2b80c6bdba2dd24f37467,
        0x15bba2773377d7ef96c76ede7d8d12bc5725441961de9f1b330484e1f24a19a8,
        0x86dc81c5fccb1de6766036f308db3b6e1e6eb0fa7d780096d701cc97fb4a20f1,
        0x3d4279efe1806d0c7747915b9852ade3738e8ffd87604e01034ca78e8cb81c54,
        rootCorrect
    ];

    // [nullifier, action] tuple of the session proof; the action is randomly generated
    // at OPRF-query time and carries the 0x02 session prefix.
    uint256[2] sessionNullifier = [
        0x8ce710377b04b2605fd6c5545f15f638527bd0315f223b8c2c070a4ac0a62d0,
        0x2b6b35cb561c84d7a137fbc715c9df67152fa28c1b81042a4c0e80d1ba01b00
    ];

    // Uniqueness proof over the same request as `proof`, bound to `sessionId`
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
            sessionNonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            sessionId,
            sessionNullifier,
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
            sessionNonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            sessionId,
            sessionNullifier,
            sessionProof
        );
    }

    function test_SessionWrongCredentialIssuer() public {
        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(Verifier.ProofInvalid.selector));
        worldIDVerifier.verifySession(
            rpIdCorrect,
            sessionNonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdWrong, // NOTE incorrect credential issuer id
            0,
            sessionId,
            sessionNullifier,
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
            sessionNonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            sessionId,
            sessionNullifier,
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
            sessionNonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            sessionId,
            sessionNullifier,
            invalidRootProof
        );
    }

    function test_SessionExpiresAtTooOld() public {
        vm.warp(expiresAtMin + 24 hours);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDVerifier.ExpirationTooOld.selector));
        worldIDVerifier.verifySession(
            rpIdCorrect,
            sessionNonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            sessionId,
            sessionNullifier,
            sessionProof
        );
    }

    // Session-bound Uniqueness Proof Tests

    function test_BoundSuccess() public {
        vm.warp(expiresAtMin + 1 hours);
        worldIDVerifier.verifyWithSession(
            nullifier,
            action,
            rpIdCorrect,
            nonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            sessionId,
            boundProof
        );
    }

    function test_BoundRejectedByVerify() public {
        // The bound proof commits to the session id, while verify() pins the signal to 0
        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(Verifier.ProofInvalid.selector));
        worldIDVerifier.verify(
            nullifier, action, rpIdCorrect, nonce, signalHash, expiresAtMin, credentialIssuerIdCorrect, 0, boundProof
        );
    }

    function test_UnboundRejectedByVerifyWithSession() public {
        // The unbound proof commits to a session id of 0
        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(Verifier.ProofInvalid.selector));
        worldIDVerifier.verifyWithSession(
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

    function test_BoundWrongSessionId() public {
        vm.warp(expiresAtMin + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(Verifier.ProofInvalid.selector));
        worldIDVerifier.verifyWithSession(
            nullifier,
            action,
            rpIdCorrect,
            nonce,
            signalHash,
            expiresAtMin,
            credentialIssuerIdCorrect,
            0,
            sessionId + 1, // NOTE incorrect session id
            boundProof
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
