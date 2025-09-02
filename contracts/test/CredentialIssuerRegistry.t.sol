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
}
