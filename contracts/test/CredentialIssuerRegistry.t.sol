// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {AbstractSignerPubkeyRegistry as A} from "../src/AbstractSignerPubkeyRegistry.sol";
import {CredentialIssuerRegistry} from "../src/CredentialIssuerRegistry.sol";
import {RegistryTestBase, RegistryLike} from "./RegistryTestBase.t.sol";

contract CredentialIssuerRegistryTest is RegistryTestBase {
    CredentialIssuerRegistry private registry;

    function setUp() public {
        registry = new CredentialIssuerRegistry();
    }

    function _generatePubkey(string memory str) public pure returns (A.Pubkey memory) {
        return A.Pubkey(uint256(keccak256(bytes(str))), uint256(keccak256(bytes(str))));
    }

    function _isEq(A.Pubkey memory a, A.Pubkey memory b) public pure returns (bool) {
        return a.x == b.x && a.y == b.y;
    }

    function testRegisterAndGetters() public {
        uint256 signerPk = 0xAAA1;
        address signer = vm.addr(signerPk);
        A.Pubkey memory pubkey = _generatePubkey("pubkey-issuer-1");

        vm.expectEmit();
        emit CredentialIssuerRegistry.IssuerRegistered(1, pubkey, signer);
        registry.register(pubkey, signer);

        assertEq(registry.nextIssuerId(), 2);
        assertTrue(_isEq(registry.issuerIdToPubkey(1), pubkey));
        assertEq(registry.addressToIssuerId(signer), 1);
    }

    function testUpdatePubkeyFlow() public {
        uint256 signerPk = 0xAAA2;
        address signer = vm.addr(signerPk);
        A.Pubkey memory pubkey = _generatePubkey("old");
        registry.register(pubkey, signer);

        A.Pubkey memory newPubkey = _generatePubkey("new");
        bytes memory sig = _signUpdatePubkey(
            registry.UPDATE_PUBKEY_TYPEHASH(), RegistryLike(address(registry)), signerPk, 1, newPubkey, pubkey
        );

        vm.expectEmit();
        emit CredentialIssuerRegistry.IssuerPubkeyUpdated(1, pubkey, newPubkey, signer);
        registry.updatePubkey(1, newPubkey, sig);

        assertTrue(_isEq(registry.issuerIdToPubkey(1), newPubkey));
    }

    function testUpdateSignerFlow() public {
        uint256 oldPk = 0xAAA3;
        address oldSigner = vm.addr(oldPk);
        registry.register(_generatePubkey("k"), oldSigner);

        address newSigner = vm.addr(0xAAA4);
        bytes memory sig =
            _signUpdateSigner(registry.UPDATE_SIGNER_TYPEHASH(), RegistryLike(address(registry)), oldPk, 1, newSigner);

        vm.expectEmit();
        emit CredentialIssuerRegistry.IssuerSignerUpdated(1, oldSigner, newSigner);
        registry.updateSigner(1, newSigner, sig);

        assertEq(registry.addressToIssuerId(oldSigner), 0);
        assertEq(registry.addressToIssuerId(newSigner), 1);
    }

    function testRemoveFlow() public {
        uint256 signerPk = 0xAAA5;
        address signer = vm.addr(signerPk);
        A.Pubkey memory pubkey = _generatePubkey("k");
        registry.register(pubkey, signer);

        bytes memory sig = _signRemove(registry.REMOVE_ISSUER_TYPEHASH(), RegistryLike(address(registry)), signerPk, 1);

        vm.expectEmit();
        emit CredentialIssuerRegistry.IssuerRemoved(1, pubkey, signer);
        registry.remove(1, sig);

        assertTrue(_isEq(registry.issuerIdToPubkey(1), A.Pubkey(0, 0)));
        assertEq(registry.addressToIssuerId(signer), 0);
    }

    function _signRegisterIssuerSchemaId(uint256 sk, uint256 issuerSchemaId, uint256 id, string memory schemaUri)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash =
            keccak256(abi.encode(registry.REGISTER_ISSUER_SCHEMA_ID_TYPEHASH(), issuerSchemaId, id, schemaUri));
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                _domainSeparator(address(registry), registry.EIP712_NAME(), registry.EIP712_VERSION()),
                structHash
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signUpdateIssuerSchemaUri(uint256 sk, uint256 issuerSchemaId, string memory schemaUri)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash =
            keccak256(abi.encode(registry.UPDATE_ISSUER_SCHEMA_URI_TYPEHASH(), issuerSchemaId, schemaUri));
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                _domainSeparator(address(registry), registry.EIP712_NAME(), registry.EIP712_VERSION()),
                structHash
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sk, digest);
        return abi.encodePacked(r, s, v);
    }

    function testRegisterIssuerSchemaIdFlow() public {
        uint256 signerSk = 0xAAA6;
        address signer = vm.addr(signerSk);
        registry.register(_generatePubkey("k"), signer);

        bytes memory sig = _signRegisterIssuerSchemaId(signerSk, 2, 1, "https://world.org/schemas/orb.json");

        vm.expectEmit();
        emit CredentialIssuerRegistry.IssuerSchemaIdRegistered(2, 1, "https://world.org/schemas/orb.json");
        registry.registerIssuerSchemaId(2, 1, "https://world.org/schemas/orb.json", sig);

        assertEq(registry.issuerSchemaIdToIssuerId(2), 1);
        assertEq(registry.issuerSchemaIdToSchemaUri(2), "https://world.org/schemas/orb.json");

        assertEq(registry.getIssuerSchemaUri(2), "https://world.org/schemas/orb.json");
    }

    function testUpdateIssuerSchemaUriFlow() public {
        uint256 signerSk = 0xAAA6;
        address signer = vm.addr(signerSk);
        registry.register(_generatePubkey("k"), signer);

        // initial registration
        bytes memory sig = _signRegisterIssuerSchemaId(signerSk, 2, 1, "https://world.org/schemas/orb.json");
        registry.registerIssuerSchemaId(2, 1, "https://world.org/schemas/orb.json", sig);
        assertEq(registry.issuerSchemaIdToSchemaUri(2), "https://world.org/schemas/orb.json");

        // update
        bytes memory updateSig = _signUpdateIssuerSchemaUri(signerSk, 2, "https://world.org/schemas/orb_v2.json");
        vm.expectEmit();
        emit CredentialIssuerRegistry.IssuerSchemaUriUpdated(
            2, "https://world.org/schemas/orb.json", "https://world.org/schemas/orb_v2.json"
        );
        registry.updateIssuerSchemaUri(2, "https://world.org/schemas/orb_v2.json", updateSig);
        assertEq(registry.issuerSchemaIdToSchemaUri(2), "https://world.org/schemas/orb_v2.json");
    }

    function testRegisterIssuerSchemaIdFlowInvalidSignature() public {
        uint256 signerSk = 0xAAA6;
        uint256 badSk = 0xAAA7;
        address signer = vm.addr(signerSk);
        registry.register(_generatePubkey("k"), signer);

        bytes memory sig = _signRegisterIssuerSchemaId(badSk, 2, 1, "https://world.org/schemas/orb.json");

        vm.expectRevert(bytes("Registry: invalid signature"));
        registry.registerIssuerSchemaId(2, 1, "https://world.org/schemas/orb.json", sig);

        assertEq(registry.issuerSchemaIdToIssuerId(2), 0);
        assertEq(registry.issuerSchemaIdToSchemaUri(2), "");
    }

    function testOnlyIssuerCanUpdateSchemaUri() public {
        uint256 signerSk = 0xAAA6;
        uint256 badSk = 0xAAA7;
        address signer = vm.addr(signerSk);
        registry.register(_generatePubkey("k"), signer);

        bytes memory sig = _signRegisterIssuerSchemaId(signerSk, 2, 1, "https://world.org/schemas/orb.json");
        registry.registerIssuerSchemaId(2, 1, "https://world.org/schemas/orb.json", sig);

        bytes memory updateSig = _signUpdateIssuerSchemaUri(badSk, 2, "https://world.org/schemas/malicious.json");
        vm.expectRevert(bytes("Registry: invalid signature"));
        registry.updateIssuerSchemaUri(2, "https://world.org/schemas/malicious.json", updateSig);
        assertEq(registry.issuerSchemaIdToSchemaUri(2), "https://world.org/schemas/orb.json");
    }

    function testCannotRegisterSameSchemaId() public {
        uint256 signerSk = 0xAAA6;
        uint256 anotherSk = 0xAAA7;
        address signer = vm.addr(signerSk);
        registry.register(_generatePubkey("k"), signer);

        bytes memory sig = _signRegisterIssuerSchemaId(signerSk, 2, 1, "https://world.org/schemas/orb.json");
        vm.expectEmit();
        emit CredentialIssuerRegistry.IssuerSchemaIdRegistered(2, 1, "https://world.org/schemas/orb.json");
        registry.registerIssuerSchemaId(2, 1, "https://world.org/schemas/orb.json", sig);

        vm.expectRevert(bytes("Schema ID already registered"));
        registry.registerIssuerSchemaId(2, 1, "https://world.org/schemas/orb_v4.json", sig);

        bytes memory sig2 = _signRegisterIssuerSchemaId(anotherSk, 2, 1, "https://world.org/schemas/orb_v4.json");
        vm.expectRevert(bytes("Schema ID already registered"));
        registry.registerIssuerSchemaId(2, 1, "https://world.org/schemas/orb_v4.json", sig2);

        assertEq(registry.issuerSchemaIdToSchemaUri(2), "https://world.org/schemas/orb.json");
    }

    function testIssuerSchemaIdToPubkey() public {
        uint256 signerSk = 0xAAA6;
        address signer = vm.addr(signerSk);
        A.Pubkey memory pubkey = _generatePubkey("k");
        registry.register(pubkey, signer);

        bytes memory sig = _signRegisterIssuerSchemaId(signerSk, 2, 1, "https://world.org/schemas/orb.json");
        registry.registerIssuerSchemaId(2, 1, "https://world.org/schemas/orb.json", sig);
        assertTrue(_isEq(registry.issuerSchemaIdToPubkey(2), pubkey));
    }
}
