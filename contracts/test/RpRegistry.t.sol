// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {RpRegistry} from "../src/RpRegistry.sol";
import {RegistryTestBase, RegistryLike} from "./RegistryTestBase.t.sol";

contract RpRegistryTest is RegistryTestBase {
    RpRegistry private registry;

    function setUp() public {
        registry = new RpRegistry();
    }

    function testRegisterAndGetters() public {
        uint256 signerPk = 0xA11CE;
        address signer = vm.addr(signerPk);
        bytes32 pubkey = keccak256("pubkey-1");

        vm.expectEmit();
        emit RpRegistry.RpRegistered(1, pubkey, signer);
        registry.register(pubkey, signer);

        assertEq(registry.nextRpId(), 2);
        assertEq(registry.rpIdToPubkey(1), pubkey);
        assertEq(registry.addressToRpId(signer), 1);
    }

    function testRegisterRevertsOnZeroOrDuplicate() public {
        uint256 signerPk = 0xB0B;
        address signer = vm.addr(signerPk);
        bytes32 pubkey = keccak256("pubkey-2");

        vm.expectRevert(bytes("Registry: pubkey cannot be zero"));
        registry.register(bytes32(0), signer);

        registry.register(pubkey, signer);

        vm.expectRevert(bytes("Registry: signer already registered"));
        registry.register(keccak256("another"), signer);
    }

    function testUpdatePubkeyFlow() public {
        uint256 signerPk = 0xC0FFEE;
        address signer = vm.addr(signerPk);
        bytes32 pubkey = keccak256("old");
        registry.register(pubkey, signer);

        bytes32 newPubkey = keccak256("new");
        bytes memory sig = _signUpdatePubkey(
            registry.UPDATE_PUBKEY_TYPEHASH(), RegistryLike(address(registry)), signerPk, 1, newPubkey, pubkey
        );

        vm.expectEmit();
        emit RpRegistry.PubkeyUpdated(1, pubkey, newPubkey, signer);
        registry.updatePubkey(1, newPubkey, sig);

        assertEq(registry.rpIdToPubkey(1), newPubkey);
    }

    function testUpdatePubkeyRevertsOnBadSig() public {
        uint256 goodPk = 0xD00D;
        uint256 badPk = 0xBAD;
        address signer = vm.addr(goodPk);
        registry.register(keccak256("k"), signer);

        bytes32 newPubkey = keccak256("new");
        bytes memory sig = _signUpdatePubkey(
            registry.UPDATE_PUBKEY_TYPEHASH(), RegistryLike(address(registry)), badPk, 1, newPubkey, keccak256("k")
        );

        vm.expectRevert(bytes("Registry: invalid signature"));
        registry.updatePubkey(1, newPubkey, sig);
    }

    function testUpdateSignerFlow() public {
        uint256 oldPk = 0x1111;
        address oldSigner = vm.addr(oldPk);
        registry.register(keccak256("k"), oldSigner);

        address newSigner = vm.addr(0x2222);
        bytes memory sig =
            _signUpdateSigner(registry.UPDATE_SIGNER_TYPEHASH(), RegistryLike(address(registry)), oldPk, 1, newSigner);

        vm.expectEmit();
        emit RpRegistry.SignerUpdated(1, oldSigner, newSigner);
        registry.updateSigner(1, newSigner, sig);

        assertEq(registry.addressToRpId(oldSigner), 0);
        assertEq(registry.addressToRpId(newSigner), 1);
    }

    function testRemoveFlow() public {
        uint256 signerPk = 0x3333;
        address signer = vm.addr(signerPk);
        bytes32 pubkey = keccak256("k");
        registry.register(pubkey, signer);

        bytes memory sig = _signRemove(registry.REMOVE_RP_TYPEHASH(), RegistryLike(address(registry)), signerPk, 1);

        vm.expectEmit();
        emit RpRegistry.RpRemoved(1, pubkey, signer);
        registry.remove(1, sig);

        assertEq(registry.rpIdToPubkey(1), bytes32(0));
        assertEq(registry.addressToRpId(signer), 0);
    }
}
