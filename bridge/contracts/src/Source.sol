// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ICredentialSchemaIssuerRegistry, IWorldIDRegistry, OprfKeyRegistry, OprfKeyGen} from "@common/Common.sol";
import {IERC7786GatewaySource} from "@openzeppelin/contracts/interfaces/draft-IERC7786.sol";
import {IStateBridge} from "@core/types/IStateBridge.sol";
import {Lib} from "@lib-core/Lib.sol";
import {StateBridge} from "@lib-core/StateBridge.sol";
import {ZeroAddress, NothingChanged} from "./Error.sol";

/// @title WorldIDSource
/// @author World Contributors
/// @notice World Chain Cannon State Bridge.
contract WorldIDSource is StateBridge {
    using Lib for *;

    /// @dev The contract version.
    /// @custom:semver v1.0.0
    uint8 public constant override VERSION = 1;

    /// @notice The WorldIDRegistry contract on World Chain.
    IWorldIDRegistry internal immutable WORLD_CHAIN_REGISTRY;

    /// @notice The CredentialSchemaIssuerRegistry contract on World Chain.
    ICredentialSchemaIssuerRegistry internal immutable WORLD_CHAIN_ISSUER_REGISTRY;

    /// @notice The OprfKeyRegistry contract on World Chain.
    OprfKeyRegistry internal immutable WORLD_CHAIN_OPRF_REGISTRY;

    constructor(address worldChainRegistry, address worldChainIssuerRegistry, address worldChainOprfRegistry) {
        if (worldChainRegistry == address(0)) revert ZeroAddress();
        if (worldChainIssuerRegistry == address(0)) revert ZeroAddress();
        if (worldChainOprfRegistry == address(0)) revert ZeroAddress();

        WORLD_CHAIN_REGISTRY = IWorldIDRegistry(worldChainRegistry);
        WORLD_CHAIN_ISSUER_REGISTRY = ICredentialSchemaIssuerRegistry(worldChainIssuerRegistry);
        WORLD_CHAIN_OPRF_REGISTRY = OprfKeyRegistry(worldChainOprfRegistry);

        _disableInitializers();
    }

    /// @dev Initializes the contract with the given configuration. Can only be called once.
    function initialize(IStateBridge.InitConfig memory cfg) external reinitializer(VERSION) {
        _initialize(cfg);
    }

    /// @notice Reads all relevant state from WC registries and propagates any changes
    ///   into bridge state as a single batched chain extension.
    /// @param issuerSchemaIds The issuer schema IDs whose pubkeys should be checked.
    /// @param oprfKeyIds The OPRF key IDs whose pubkeys should be checked.
    /// @dev Emits `ChainCommitted` with the new chain head and the commitment data for L1 verification via MPT.
    function propagateState(uint64[] calldata issuerSchemaIds, uint160[] calldata oprfKeyIds) external virtual {
        (Lib.Commitment[] memory commits, uint256 count) = _buildCommitments(issuerSchemaIds, oprfKeyIds);
        if (count == 0) revert NothingChanged();
        _applyAndCommit(commits);
    }

    /// @dev Reads WC registries and builds commitments for any detected changes.
    /// @return commits The commitment array (trimmed to actual count).
    /// @return count The number of commitments produced.
    function _buildCommitments(uint64[] calldata issuerSchemaIds, uint160[] calldata oprfKeyIds)
        internal
        view
        returns (Lib.Commitment[] memory commits, uint256 count)
    {
        // Worst-case: root + all issuers + all OPRFs
        commits = new Lib.Commitment[](1 + issuerSchemaIds.length + oprfKeyIds.length);

        bytes32 blockHash = blockhash(block.number - 1);
        bytes32 proofId = bytes32(block.number);

        count = _propagateRoot(commits, 0, blockHash, proofId);
        count = _propagateIssuerPubkeys(commits, count, issuerSchemaIds, blockHash, proofId);
        count = _propagateOprfKeys(commits, count, oprfKeyIds, blockHash, proofId);

        // store count at length
        assembly ("memory-safe") {
            mstore(commits, count)
        }
    }

    /// @dev Checks if the root has changed on WC and, if so, writes state and appends a commitment.
    function _propagateRoot(Lib.Commitment[] memory commits, uint256 count, bytes32 blockHash, bytes32 proofId)
        internal
        view
        returns (uint256)
    {
        uint256 root = WORLD_CHAIN_REGISTRY.getLatestRoot();
        if (root != LATEST_ROOT()) {
            commits[count++] = Lib.Commitment({
                blockHash: blockHash, data: abi.encodeWithSelector(UPDATE_ROOT_SELECTOR, root, block.timestamp, proofId)
            });
        }
        return count;
    }

    /// @dev Checks each issuer pubkey for changes and appends commitments for any that differ.
    function _propagateIssuerPubkeys(
        Lib.Commitment[] memory commits,
        uint256 count,
        uint64[] calldata issuerSchemaIds,
        bytes32 blockHash,
        bytes32 proofId
    ) internal view returns (uint256) {
        for (uint256 i; i < issuerSchemaIds.length; ++i) {
            uint64 id = issuerSchemaIds[i];
            ICredentialSchemaIssuerRegistry.Pubkey memory key = WORLD_CHAIN_ISSUER_REGISTRY.issuerSchemaIdToPubkey(id);
            ProvenPubKeyInfo memory stored = issuerSchemaIdToPubkeyAndProofId(id);

            if (key.x != stored.pubKey.x || key.y != stored.pubKey.y) {
                commits[count++] = Lib.Commitment({
                    blockHash: blockHash,
                    data: abi.encodeWithSelector(SET_ISSUER_PUBKEY_SELECTOR, id, key.x, key.y, proofId)
                });
            }
        }
        return count;
    }

    /// @dev Checks each OPRF key for changes and appends commitments for any that differ.
    function _propagateOprfKeys(
        Lib.Commitment[] memory commits,
        uint256 count,
        uint160[] calldata oprfKeyIds,
        bytes32 blockHash,
        bytes32 proofId
    ) internal view returns (uint256) {
        for (uint256 i; i < oprfKeyIds.length; ++i) {
            uint160 id = oprfKeyIds[i];
            OprfKeyGen.RegisteredOprfPublicKey memory key = WORLD_CHAIN_OPRF_REGISTRY.getOprfPublicKeyAndEpoch(id);
            ProvenPubKeyInfo memory stored = oprfKeyIdToPubkeyAndProofId(id);

            if (key.key.x != stored.pubKey.x || key.key.y != stored.pubKey.y) {
                commits[count++] = Lib.Commitment({
                    blockHash: blockHash,
                    data: abi.encodeWithSelector(SET_OPRF_KEY_SELECTOR, id, key.key.x, key.key.y, proofId)
                });
            }
        }
        return count;
    }
}
