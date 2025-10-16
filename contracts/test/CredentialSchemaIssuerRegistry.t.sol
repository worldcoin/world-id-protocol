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
        bytes32 structHash =
            keccak256(abi.encode(registry.UPDATE_PUBKEY_TYPEHASH(), id, newPubkey, oldPubkey, registry.nonceOf(id)));
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
        registry.register(pubkey, signer);

        assertEq(registry.nextIssuerSchemaId(), 2);
        assertTrue(_isEq(registry.issuerSchemaIdToPubkey(1), pubkey));
        assertEq(registry.addressToIssuerSchemaId(signer), 1);
    }

    function testUpdatePubkeyFlow() public {
        uint256 signerPk = 0xAAA2;
        address signer = vm.addr(signerPk);
        CredentialSchemaIssuerRegistry.Pubkey memory pubkey = _generatePubkey("old");
        registry.register(pubkey, signer);

        CredentialSchemaIssuerRegistry.Pubkey memory newPubkey = _generatePubkey("new");
        bytes memory sig = _signUpdatePubkey(signerPk, 1, newPubkey, pubkey);

        vm.expectEmit();
        emit CredentialSchemaIssuerRegistry.IssuerSchemaPubkeyUpdated(1, pubkey, newPubkey, signer);
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

        assertEq(registry.addressToIssuerSchemaId(oldSigner), 0);
        assertEq(registry.addressToIssuerSchemaId(newSigner), 1);
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
        assertEq(registry.addressToIssuerSchemaId(signer), 0);
    }

    function _signUpdateIssuerSchemaUri(uint256 sk, uint256 issuerSchemaId, string memory schemaUri)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash =
            keccak256(abi.encode(registry.UPDATE_ISSUER_SCHEMA_URI_TYPEHASH(), issuerSchemaId, schemaUri));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sk, digest);
        return abi.encodePacked(r, s, v);
    }

    function testUpdateIssuerSchemaUriFlow() public {
        uint256 signerSk = 0xAAA6;
        address signer = vm.addr(signerSk);
        registry.register(_generatePubkey("k"), signer);

        bytes memory updateSig = _signUpdateIssuerSchemaUri(signerSk, 1, "https://world.org/schemas/orb.json");
        vm.expectEmit();
        emit CredentialSchemaIssuerRegistry.IssuerSchemaUpdated(1, "", "https://world.org/schemas/orb.json");
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/orb.json", updateSig);
        assertEq(registry.getIssuerSchemaUri(1), "https://world.org/schemas/orb.json");
    }

    function testOnlyIssuerCanUpdateSchemaUri() public {
        uint256 signerSk = 0xAAA6;
        uint256 badSk = 0xAAA7;
        address signer = vm.addr(signerSk);
        registry.register(_generatePubkey("k"), signer);

        bytes memory updateSig = _signUpdateIssuerSchemaUri(badSk, 1, "https://world.org/schemas/malicious.json");
        vm.expectRevert(bytes("Registry: invalid signature"));
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/malicious.json", updateSig);
        assertEq(registry.getIssuerSchemaUri(1), "");
    }
}
