// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ICredentialSchemaIssuerRegistry} from "@world-id/interfaces/ICredentialSchemaIssuerRegistry.sol";
import {BabyJubJub} from "lib/oprf-key-registry/src/BabyJubJub.sol";
import {OprfKeyGen} from "lib/oprf-key-registry/src/OprfKeyGen.sol";

/// @dev Minimal mock registries for E2E testing. Deployed to a real anvil instance
///   so that MPT proofs can be generated against their state.

contract MockWorldIDRegistryE2E {
    uint256 internal _latestRoot;

    function setRoot(uint256 root) external {
        _latestRoot = root;
    }

    function getLatestRoot() external view returns (uint256) {
        return _latestRoot;
    }
}

contract MockIssuerRegistryE2E {
    mapping(uint64 => ICredentialSchemaIssuerRegistry.Pubkey) internal _keys;

    function setPubkey(uint64 id, uint256 x, uint256 y) external {
        _keys[id] = ICredentialSchemaIssuerRegistry.Pubkey({x: x, y: y});
    }

    function issuerSchemaIdToPubkey(uint64 id) external view returns (ICredentialSchemaIssuerRegistry.Pubkey memory) {
        return _keys[id];
    }
}

contract MockOprfRegistryE2E {
    mapping(uint160 => OprfKeyGen.RegisteredOprfPublicKey) internal _keys;

    function setKey(uint160 id, uint256 x, uint256 y) external {
        _keys[id] = OprfKeyGen.RegisteredOprfPublicKey({key: BabyJubJub.Affine({x: x, y: y}), epoch: 1});
    }

    function getOprfPublicKeyAndEpoch(uint160 id) external view returns (OprfKeyGen.RegisteredOprfPublicKey memory) {
        return _keys[id];
    }
}
