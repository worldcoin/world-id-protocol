// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ICredentialSchemaIssuerRegistry} from "@world-id/interfaces/ICredentialSchemaIssuerRegistry.sol";
import {OprfKeyGen} from "lib/oprf-key-registry/src/OprfKeyGen.sol";
import {BabyJubJub} from "lib/oprf-key-registry/src/BabyJubJub.sol";

/// @dev Minimal mock for IWorldIDRegistry — only implements getLatestRoot().
contract MockWorldIDRegistry {
    uint256 public root;

    function setLatestRoot(uint256 r) external {
        root = r;
    }

    function getLatestRoot() external view returns (uint256) {
        return root;
    }
}

/// @dev Minimal mock for ICredentialSchemaIssuerRegistry — only implements issuerSchemaIdToPubkey().
contract MockIssuerRegistry {
    mapping(uint64 => ICredentialSchemaIssuerRegistry.Pubkey) internal _pubkeys;

    function setPubkey(uint64 id, uint256 x, uint256 y) external {
        _pubkeys[id] = ICredentialSchemaIssuerRegistry.Pubkey({x: x, y: y});
    }

    function issuerSchemaIdToPubkey(uint64 id) external view returns (ICredentialSchemaIssuerRegistry.Pubkey memory) {
        return _pubkeys[id];
    }
}

/// @dev Minimal mock for IOprfKeyRegistry — only implements getOprfPublicKeyAndEpoch().
contract MockOprfKeyRegistry {
    mapping(uint160 => OprfKeyGen.RegisteredOprfPublicKey) internal _keys;

    function setKey(uint160 id, uint256 x, uint256 y) external {
        _keys[id] = OprfKeyGen.RegisteredOprfPublicKey({key: BabyJubJub.Affine({x: x, y: y}), epoch: 1});
    }

    function getOprfPublicKeyAndEpoch(uint160 id) external view returns (OprfKeyGen.RegisteredOprfPublicKey memory) {
        return _keys[id];
    }
}
