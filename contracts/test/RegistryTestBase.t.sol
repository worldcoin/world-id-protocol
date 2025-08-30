// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";

interface RegistryLike {
    function EIP712_NAME() external view returns (string memory);
    function EIP712_VERSION() external view returns (string memory);
    function nonceOf(uint256 id) external view returns (uint256);
}

abstract contract RegistryTestBase is Test {
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    function _domainSeparator(address registry, string memory name, string memory version)
        internal
        view
        returns (bytes32)
    {
        bytes32 nameHash = keccak256(bytes(name));
        bytes32 versionHash = keccak256(bytes(version));
        return keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, nameHash, versionHash, block.chainid, registry));
    }

    function _signRemove(bytes32 removeTypehash, RegistryLike registry, uint256 pk, uint256 id)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(abi.encode(removeTypehash, id, registry.nonceOf(id)));
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                _domainSeparator(address(registry), registry.EIP712_NAME(), registry.EIP712_VERSION()),
                structHash
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signUpdatePubkey(
        bytes32 updatePubkeyTypehash,
        RegistryLike registry,
        uint256 pk,
        uint256 id,
        bytes32 newPubkey,
        bytes32 oldPubkey
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(updatePubkeyTypehash, id, newPubkey, oldPubkey, registry.nonceOf(id)));
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                _domainSeparator(address(registry), registry.EIP712_NAME(), registry.EIP712_VERSION()),
                structHash
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signUpdateSigner(
        bytes32 updateSignerTypehash,
        RegistryLike registry,
        uint256 pk,
        uint256 id,
        address newSigner
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(updateSignerTypehash, id, newSigner, registry.nonceOf(id)));
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                _domainSeparator(address(registry), registry.EIP712_NAME(), registry.EIP712_VERSION()),
                structHash
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }
}
