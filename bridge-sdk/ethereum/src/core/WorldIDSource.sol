// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IWorldIDRegistry} from "@world-id/interfaces/IWorldIDRegistry.sol";
import {ICredentialSchemaIssuerRegistry} from "@world-id/interfaces/ICredentialSchemaIssuerRegistry.sol";
import {OprfKeyGen} from "lib/oprf-key-registry/src/OprfKeyGen.sol";
import {IERC7786GatewaySource} from "@openzeppelin/contracts/interfaces/draft-IERC7786.sol";
import {StateBridge} from "./lib/StateBridge.sol";
import {IStateBridge} from "./interfaces/IStateBridge.sol";
import {ZeroAddress, NothingChanged} from "./Error.sol";
import {ProofsLib} from "./lib/ProofsLib.sol";
import {IOprfKeyRegistry} from "../interfaces/IOprfKeyRegistry.sol";

/// @title WorldIDSource
/// @author World Contributors
/// @notice World Chain source-of-truth state. Reads WC registries directly via `propagateState`,
///   extends the rolling keccak state chain, and marks new chain heads as valid for L1 verification via MPT.
///   This is NOT a verifier — it only produces state for downstream consumption.
contract WorldIDSource is StateBridge {
    using ProofsLib for *;

    /// @notice The WorldIDRegistry contract on World Chain.
    IWorldIDRegistry public immutable WC_REGISTRY;

    /// @notice The CredentialSchemaIssuerRegistry contract on World Chain.
    ICredentialSchemaIssuerRegistry public immutable WC_ISSUER_REGISTRY;

    /// @notice The OprfKeyRegistry contract on World Chain.
    IOprfKeyRegistry public immutable WC_OPRF_REGISTRY;

    ////////////////////////////////////////////////////////////
    //                      CONSTRUCTOR                       //
    ////////////////////////////////////////////////////////////

    constructor(address worldChainRegistry, address worldChainIssuerRegistry, address worldChainOprfRegistry) {
        if (worldChainRegistry == address(0)) revert ZeroAddress();
        if (worldChainIssuerRegistry == address(0)) revert ZeroAddress();
        if (worldChainOprfRegistry == address(0)) revert ZeroAddress();

        WC_REGISTRY = IWorldIDRegistry(worldChainRegistry);
        WC_ISSUER_REGISTRY = ICredentialSchemaIssuerRegistry(worldChainIssuerRegistry);
        WC_OPRF_REGISTRY = IOprfKeyRegistry(worldChainOprfRegistry);

        _disableInitializers();
    }

    /// @notice Reads all relevant state from WC registries and propagates any changes
    ///   into bridge state as a single batched chain extension.
    /// @param issuerSchemaIds The issuer schema IDs whose pubkeys should be checked.
    /// @param oprfKeyIds The OPRF key IDs whose pubkeys should be checked.
    /// @dev Emits `ChainCommitted` with the new chain head and the commitment data for L1 verification via MPT.
    function propagateState(uint64[] calldata issuerSchemaIds, uint160[] calldata oprfKeyIds) external virtual {
        (ProofsLib.Commitment[] memory commits, uint256 count) = _buildCommitments(issuerSchemaIds, oprfKeyIds);
        if (count == 0) revert NothingChanged();
        _applyAndCommit(commits);
    }

    ////////////////////////////////////////////////////////////
    //                       INTERNAL                         //
    ////////////////////////////////////////////////////////////

    /// @dev Reads WC registries and builds commitments for any detected changes.
    /// @return commits The commitment array (trimmed to actual count).
    /// @return count The number of commitments produced.
    function _buildCommitments(uint64[] calldata issuerSchemaIds, uint160[] calldata oprfKeyIds)
        internal
        view
        returns (ProofsLib.Commitment[] memory commits, uint256 count)
    {
        // Worst-case: root + all issuers + all OPRFs
        commits = new ProofsLib.Commitment[](1 + issuerSchemaIds.length + oprfKeyIds.length);

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
    function _propagateRoot(ProofsLib.Commitment[] memory commits, uint256 count, bytes32 blockHash, bytes32 proofId)
        internal
        view
        returns (uint256)
    {
        uint256 root = WC_REGISTRY.getLatestRoot();
        if (root != LATEST_ROOT()) {
            commits[count++] = ProofsLib.Commitment({
                blockHash: blockHash,
                data: abi.encodeWithSelector(ProofsLib.UPDATE_ROOT_SELECTOR, root, block.timestamp, proofId)
            });
        }
        return count;
    }

    /// @dev Checks each issuer pubkey for changes and appends commitments for any that differ.
    function _propagateIssuerPubkeys(
        ProofsLib.Commitment[] memory commits,
        uint256 count,
        uint64[] calldata issuerSchemaIds,
        bytes32 blockHash,
        bytes32 proofId
    ) internal view returns (uint256) {
        for (uint256 i; i < issuerSchemaIds.length; ++i) {
            uint64 id = issuerSchemaIds[i];
            ICredentialSchemaIssuerRegistry.Pubkey memory key = WC_ISSUER_REGISTRY.issuerSchemaIdToPubkey(id);
            ProvenPubKeyInfo memory stored = issuerSchemaIdToPubkeyAndProofId(id);

            if (key.x != stored.pubKey.x || key.y != stored.pubKey.y) {
                commits[count++] = ProofsLib.Commitment({
                    blockHash: blockHash,
                    data: abi.encodeWithSelector(ProofsLib.SET_ISSUER_PUBKEY_SELECTOR, id, key.x, key.y, proofId)
                });
            }
        }
        return count;
    }

    /// @dev Checks each OPRF key for changes and appends commitments for any that differ.
    function _propagateOprfKeys(
        ProofsLib.Commitment[] memory commits,
        uint256 count,
        uint160[] calldata oprfKeyIds,
        bytes32 blockHash,
        bytes32 proofId
    ) internal view returns (uint256) {
        for (uint256 i; i < oprfKeyIds.length; ++i) {
            uint160 id = oprfKeyIds[i];
            OprfKeyGen.RegisteredOprfPublicKey memory key = WC_OPRF_REGISTRY.getOprfPublicKeyAndEpoch(id);
            ProvenPubKeyInfo memory stored = oprfKeyIdToPubkeyAndProofId(id);

            if (key.key.x != stored.pubKey.x || key.key.y != stored.pubKey.y) {
                commits[count++] = ProofsLib.Commitment({
                    blockHash: blockHash,
                    data: abi.encodeWithSelector(ProofsLib.SET_OPRF_KEY_SELECTOR, id, key.key.x, key.key.y, proofId)
                });
            }
        }
        return count;
    }
}
