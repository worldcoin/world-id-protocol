// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {CredentialSchemaIssuerRegistry} from "../src/CredentialSchemaIssuerRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract CredentialIssuerRegistryTest is Test {
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    CredentialSchemaIssuerRegistry private registry;

    function setUp() public {
        // Deploy implementation
        CredentialSchemaIssuerRegistry implementation = new CredentialSchemaIssuerRegistry();

        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(CredentialSchemaIssuerRegistry.initialize.selector);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);

        registry = CredentialSchemaIssuerRegistry(address(proxy));
    }

    function _generatePubkey(string memory str) public pure returns (CredentialSchemaIssuerRegistry.Pubkey memory) {
        return CredentialSchemaIssuerRegistry.Pubkey(uint256(keccak256(bytes(str))), uint256(keccak256(bytes(str))));
    }

    function _domainSeparator() internal view returns (bytes32) {
        bytes32 nameHash = keccak256(bytes(registry.EIP712_NAME()));
        bytes32 versionHash = keccak256(bytes(registry.EIP712_VERSION()));
        return keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, nameHash, versionHash, block.chainid, address(registry)));
    }

    function _signRemove(uint256 pk, uint256 id) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(registry.REMOVE_ISSUER_SCHEMA_TYPEHASH(), id, registry.nonceOf(id)));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signUpdatePubkey(
        uint256 pk,
        uint256 id,
        CredentialSchemaIssuerRegistry.Pubkey memory newPubkey,
        CredentialSchemaIssuerRegistry.Pubkey memory oldPubkey
    ) internal view returns (bytes memory) {
        bytes32 oldPubkeyHash = keccak256(abi.encode(registry.PUBKEY_TYPEHASH(), oldPubkey.x, oldPubkey.y));
        bytes32 newPubkeyHash = keccak256(abi.encode(registry.PUBKEY_TYPEHASH(), newPubkey.x, newPubkey.y));

        bytes32 structHash = keccak256(
            abi.encode(registry.UPDATE_PUBKEY_TYPEHASH(), id, newPubkeyHash, oldPubkeyHash, registry.nonceOf(id))
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signUpdateSigner(uint256 pk, uint256 id, address newSigner) internal view returns (bytes memory) {
        bytes32 structHash =
            keccak256(abi.encode(registry.UPDATE_SIGNER_TYPEHASH(), id, newSigner, registry.nonceOf(id)));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _isEq(CredentialSchemaIssuerRegistry.Pubkey memory a, CredentialSchemaIssuerRegistry.Pubkey memory b)
        public
        pure
        returns (bool)
    {
        return a.x == b.x && a.y == b.y;
    }

    function testRegisterAndGetters() public {
        uint256 signerPk = 0xAAA1;
        address signer = vm.addr(signerPk);
        CredentialSchemaIssuerRegistry.Pubkey memory pubkey = _generatePubkey("pubkey-issuer-1");

        vm.expectEmit();
        emit CredentialSchemaIssuerRegistry.IssuerSchemaRegistered(1, pubkey, signer);
        uint256 issuerSchemaId = registry.register(pubkey, signer);
        assertEq(issuerSchemaId, 1);

        assertEq(registry.nextIssuerSchemaId(), 2);
        assertTrue(_isEq(registry.issuerSchemaIdToPubkey(1), pubkey));
        assertEq(registry.getSignerForIssuerSchemaId(1), signer);
    }

    function testCannotRegisterWithEmptyPubkey() public {
        vm.expectRevert(abi.encodeWithSelector(CredentialSchemaIssuerRegistry.InvalidPubkey.selector));
        registry.register(CredentialSchemaIssuerRegistry.Pubkey(0, 0), vm.addr(0xAAA1));

        vm.expectRevert(abi.encodeWithSelector(CredentialSchemaIssuerRegistry.InvalidPubkey.selector));
        registry.register(CredentialSchemaIssuerRegistry.Pubkey(0, 1), vm.addr(0xAAA1));

        vm.expectRevert(abi.encodeWithSelector(CredentialSchemaIssuerRegistry.InvalidPubkey.selector));
        registry.register(CredentialSchemaIssuerRegistry.Pubkey(1, 0), vm.addr(0xAAA1));
    }

    function testUpdatePubkeyFlow() public {
        uint256 signerPk = 0xAAA2;
        address signer = vm.addr(signerPk);
        CredentialSchemaIssuerRegistry.Pubkey memory pubkey = _generatePubkey("old");
        registry.register(pubkey, signer);

        CredentialSchemaIssuerRegistry.Pubkey memory newPubkey = _generatePubkey("new");
        bytes memory sig = _signUpdatePubkey(signerPk, 1, newPubkey, pubkey);

        vm.expectEmit();
        emit CredentialSchemaIssuerRegistry.IssuerSchemaPubkeyUpdated(1, pubkey, newPubkey);
        registry.updatePubkey(1, newPubkey, sig);

        assertTrue(_isEq(registry.issuerSchemaIdToPubkey(1), newPubkey));
    }

    function testUpdateSignerFlow() public {
        uint256 oldPk = 0xAAA3;
        address oldSigner = vm.addr(oldPk);
        registry.register(_generatePubkey("k"), oldSigner);

        address newSigner = vm.addr(0xAAA4);
        bytes memory sig = _signUpdateSigner(oldPk, 1, newSigner);

        vm.expectEmit();
        emit CredentialSchemaIssuerRegistry.IssuerSchemaSignerUpdated(1, oldSigner, newSigner);
        registry.updateSigner(1, newSigner, sig);

        assertEq(registry.getSignerForIssuerSchemaId(1), newSigner);
    }

    function testUpdateSignerToSameSigner() public {
        uint256 signerPk = 0xAAA3;
        address signer = vm.addr(signerPk);
        registry.register(_generatePubkey("k"), signer);

        bytes memory sig = _signUpdateSigner(signerPk, 1, signer);
        vm.expectRevert(bytes("Registry: newSigner is already the assigned signer"));
        registry.updateSigner(1, signer, sig);
        assertEq(registry.getSignerForIssuerSchemaId(1), signer);
    }

    function testRemoveFlow() public {
        uint256 signerPk = 0xAAA5;
        address signer = vm.addr(signerPk);
        CredentialSchemaIssuerRegistry.Pubkey memory pubkey = _generatePubkey("k");
        registry.register(pubkey, signer);

        bytes memory sig = _signRemove(signerPk, 1);

        vm.expectEmit();
        emit CredentialSchemaIssuerRegistry.IssuerSchemaRemoved(1, pubkey, signer);
        registry.remove(1, sig);

        assertTrue(_isEq(registry.issuerSchemaIdToPubkey(1), CredentialSchemaIssuerRegistry.Pubkey(0, 0)));
        assertEq(registry.getSignerForIssuerSchemaId(1), address(0));
    }

    function _signUpdateIssuerSchemaUri(uint256 sk, uint256 issuerSchemaId, string memory schemaUri, uint256 nonce)
        internal
        view
        returns (bytes memory)
    {
        bytes32 schemaUriHash = keccak256(bytes(schemaUri));
        bytes32 structHash =
            keccak256(abi.encode(registry.UPDATE_ISSUER_SCHEMA_URI_TYPEHASH(), issuerSchemaId, schemaUriHash, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sk, digest);
        return abi.encodePacked(r, s, v);
    }

    function testUpdateIssuerSchemaUriFlow() public {
        uint256 signerSk = 0xAAA6;
        address signer = vm.addr(signerSk);
        registry.register(_generatePubkey("k"), signer);

        bytes memory updateSig = _signUpdateIssuerSchemaUri(signerSk, 1, "https://world.org/schemas/orb.json", 0);
        vm.expectEmit();
        emit CredentialSchemaIssuerRegistry.IssuerSchemaUpdated(1, "", "https://world.org/schemas/orb.json");
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/orb.json", updateSig);
        assertEq(registry.getIssuerSchemaUri(1), "https://world.org/schemas/orb.json");
        assertEq(registry.nonceOf(1), 1);

        updateSig = _signUpdateIssuerSchemaUri(signerSk, 1, "https://world.org/schemas/orb_new.json", 1);
        vm.expectEmit();
        emit CredentialSchemaIssuerRegistry.IssuerSchemaUpdated(
            1, "https://world.org/schemas/orb.json", "https://world.org/schemas/orb_new.json"
        );
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/orb_new.json", updateSig);
        assertEq(registry.getIssuerSchemaUri(1), "https://world.org/schemas/orb_new.json");
        assertEq(registry.nonceOf(1), 2);
    }

    function testOnlyIssuerCanUpdateSchemaUri() public {
        uint256 signerSk = 0xAAA6;
        uint256 badSk = 0xAAA7;
        address signer = vm.addr(signerSk);
        registry.register(_generatePubkey("k"), signer);

        bytes memory updateSig = _signUpdateIssuerSchemaUri(badSk, 1, "https://world.org/schemas/malicious.json", 0);
        vm.expectRevert(abi.encodeWithSelector(CredentialSchemaIssuerRegistry.InvalidSignature.selector));
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/malicious.json", updateSig);
        assertEq(registry.getIssuerSchemaUri(1), "");
    }

    /**
     * @dev Ensures that a previously valid message cannot be replayed to revert to a previous schema URI.
     */
    function testCannotReplayIssuerSchemaUri() public {
        uint256 signerSk = 0xAAA6;
        address signer = vm.addr(signerSk);
        registry.register(_generatePubkey("k"), signer);

        bytes memory updateSig = _signUpdateIssuerSchemaUri(signerSk, 1, "https://world.org/schemas/orb_old.json", 0);
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/orb_old.json", updateSig);
        assertEq(registry.getIssuerSchemaUri(1), "https://world.org/schemas/orb_old.json");

        bytes memory updateSigNew = _signUpdateIssuerSchemaUri(signerSk, 1, "https://world.org/schemas/orb_new.json", 1);
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/orb_new.json", updateSigNew);
        assertEq(registry.nonceOf(1), 2);

        // Replay the old update
        vm.expectRevert(abi.encodeWithSelector(CredentialSchemaIssuerRegistry.InvalidSignature.selector));
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/orb_old.json", updateSig);
        assertEq(registry.getIssuerSchemaUri(1), "https://world.org/schemas/orb_new.json");
        assertEq(registry.nonceOf(1), 2);
    }

    function testCannotUpdateSchemaUriToSameSchemaUri() public {
        uint256 signerSk = 0xAAA6;
        address signer = vm.addr(signerSk);
        registry.register(_generatePubkey("k"), signer);

        bytes memory updateSig = _signUpdateIssuerSchemaUri(signerSk, 1, "https://world.org/schemas/orb.json", 0);
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/orb.json", updateSig);
        assertEq(registry.getIssuerSchemaUri(1), "https://world.org/schemas/orb.json");

        updateSig = _signUpdateIssuerSchemaUri(signerSk, 1, "https://world.org/schemas/orb.json", 1);
        vm.expectRevert(abi.encodeWithSelector(CredentialSchemaIssuerRegistry.SchemaUriIsTheSameAsCurrentOne.selector));
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/orb.json", updateSig);
        assertEq(registry.getIssuerSchemaUri(1), "https://world.org/schemas/orb.json");
    }

    function testRemoveDeletesSchemaUri() public {
        uint256 signerPk = 0xAAA8;
        address signer = vm.addr(signerPk);
        registry.register(_generatePubkey("k"), signer);

        bytes memory updateSig = _signUpdateIssuerSchemaUri(signerPk, 1, "https://world.org/schemas/orb.json", 0);
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/orb.json", updateSig);
        assertEq(registry.getIssuerSchemaUri(1), "https://world.org/schemas/orb.json");

        bytes memory removeSig = _signRemove(signerPk, 1);
        registry.remove(1, removeSig);

        assertEq(registry.getIssuerSchemaUri(1), "");
    }

    function testCannotUpdateSchemaUriAfterRemoval() public {
        uint256 signerPk = 0xAAA9;
        address signer = vm.addr(signerPk);
        registry.register(_generatePubkey("k"), signer);

        bytes memory removeSig = _signRemove(signerPk, 1);
        registry.remove(1, removeSig);

        bytes memory updateSig = _signUpdateIssuerSchemaUri(signerPk, 1, "https://world.org/schemas/orb.json", 1);
        vm.expectRevert(abi.encodeWithSelector(CredentialSchemaIssuerRegistry.InvalidSignature.selector));
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/orb.json", updateSig);
    }

    function testCannotUpdateSchemaUriForNonExistentIssuer() public {
        uint256 signerPk = 0xAAAA;
        bytes memory updateSig = _signUpdateIssuerSchemaUri(signerPk, 999, "https://world.org/schemas/orb.json", 0);
        vm.expectRevert(abi.encodeWithSelector(CredentialSchemaIssuerRegistry.InvalidSignature.selector));
        registry.updateIssuerSchemaUri(999, "https://world.org/schemas/orb.json", updateSig);
    }
}
