// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {WorldIdStateBridge} from "../abstract/WorldIdStateBridge.sol";
import {BabyJubJub} from "lib/oprf-key-registry/src/BabyJubJub.sol";
import {IWorldIDRegistry} from "../../interfaces/IWorldIdRegistry.sol";
import {ICredentialSchemaIssuerRegistry} from "../../interfaces/ICredentialSchemaIssuerRegistry.sol";
import {OprfKeyGen} from "lib/oprf-key-registry/src/OprfKeyGen.sol";
import {IL1Block} from "../vendored/optimism/IL1Block.sol";

interface IOprfKeyRegistry {
    function getOprfPublicKeyAndEpoch(uint160) external view returns (OprfKeyGen.RegisteredOprfPublicKey memory);
}

/// @title WorldChainStateAdapter
/// @author World Contributors
/// @notice World Chain source-of-truth adapter. Reads WC registries directly via `propagateRoot`,
///   `propagateIssuerPubkey`, and `propagateOprfKey`, extends the rolling keccak state chain, and
///   dispatches chained commits to destination adapters.
contract WorldChainStateAdapter is WorldIdStateBridge {
    /// @notice The WorldIDRegistry contract on World Chain.
    IWorldIDRegistry public immutable WORLD_CHAIN_REGISTRY;

    /// @notice The CredentialSchemaIssuerRegistry contract on World Chain.
    ICredentialSchemaIssuerRegistry public immutable WORLD_CHAIN_ISSUER_REGISTRY;

    /// @notice The OprfKeyRegistry contract on World Chain.
    IOprfKeyRegistry public immutable WORLD_CHAIN_OPRF_REGISTRY;

    constructor(
        address worldChainRegistry,
        address worldChainIssuerRegistry,
        address worldChainOprfRegistry,
        uint256 rootValidityWindow_,
        uint256 treeDepth_,
        uint64 minExpirationThreshold_,
        address l1Bridge,
        address l1BlockHashOracle
    )
        WorldIdStateBridge(
            rootValidityWindow_, treeDepth_, minExpirationThreshold_, IL1Block(l1BlockHashOracle), l1Bridge
        )
    {
        WORLD_CHAIN_REGISTRY = IWorldIDRegistry(worldChainRegistry);
        WORLD_CHAIN_ISSUER_REGISTRY = ICredentialSchemaIssuerRegistry(worldChainIssuerRegistry);
        WORLD_CHAIN_OPRF_REGISTRY = IOprfKeyRegistry(worldChainOprfRegistry);
    }

    /// @notice Reads the latest Merkle root from WC's WorldIDRegistry and propagates it
    ///   into bridge state, extending the state chain and dispatching to adapters.
    /// @dev Permissionless — anyone can call. Reverts if root hasn't changed.
    function propagateRoot() external {
        uint256 root = WORLD_CHAIN_REGISTRY.getLatestRoot();
        if (root == latestRoot) revert RootNotChanged();

        Commitment memory commit = Commitment({
            blockHash: L1_BLOCK_HASH_ORACLE.hash(),
            data: abi.encodeWithSelector(
                WorldIdStateBridge.UPDATE_ROOT_SELECTOR, root, block.timestamp, bytes32(block.number)
            )
        });

        keccakChain = commitChain(commit);
    }

    /// @notice Reads an issuer public key from WC's CredentialSchemaIssuerRegistry and
    ///   propagates it into bridge state.
    ///
    /// @dev Reverts if the pubkey hasn't changed since the last propagation.
    function propagateIssuerPubkey(uint64 issuerSchemaId) external {
        ICredentialSchemaIssuerRegistry.Pubkey memory key =
            WORLD_CHAIN_ISSUER_REGISTRY.issuerSchemaIdToPubkey(issuerSchemaId);

        if (
            key.x == _issuerSchemaIdToPubkeyAndProofId[issuerSchemaId].pubKey.x
                && key.y == _issuerSchemaIdToPubkeyAndProofId[issuerSchemaId].pubKey.y
        ) revert IssuerPubkeyNotChanged();

        Commitment memory commit = Commitment({
            blockHash: L1_BLOCK_HASH_ORACLE.hash(),
            data: abi.encodeWithSelector(
                WorldIdStateBridge.SET_ISSUER_PUBKEY_SELECTOR, issuerSchemaId, key.x, key.y, bytes32(block.number)
            )
        });

        keccakChain = commitChain(commit);
    }

    /// @notice Reads an OPRF public key from WC's OprfKeyRegistry and propagates it into
    ///   bridge state.
    /// @dev Reverts if the key hasn't changed since the last propagation.
    function propagateOprfKey(uint160 oprfKeyId) external {
        OprfKeyGen.RegisteredOprfPublicKey memory key = WORLD_CHAIN_OPRF_REGISTRY.getOprfPublicKeyAndEpoch(oprfKeyId);
        if (
            key.key.x == _oprfKeyIdToPubkeyAndProofId[oprfKeyId].pubKey.x
                && key.key.y == _oprfKeyIdToPubkeyAndProofId[oprfKeyId].pubKey.y
        ) {
            revert OprfKeyNotChanged();
        }

        Commitment memory commit = Commitment({
            blockHash: L1_BLOCK_HASH_ORACLE.hash(),
            data: abi.encodeWithSelector(
                WorldIdStateBridge.SET_OPRF_KEY_SELECTOR, oprfKeyId, key.key.x, key.key.y, bytes32(block.number)
            )
        });

        keccakChain = commitChain(commit);
    }
}
