// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IWorldIDRegistry} from "@world-id/interfaces/IWorldIDRegistry.sol";
import {ICredentialSchemaIssuerRegistry} from "@world-id/interfaces/ICredentialSchemaIssuerRegistry.sol";
import {OprfKeyGen} from "lib/oprf-key-registry/src/OprfKeyGen.sol";
import {IL1Block} from "../vendored/optimism/IL1Block.sol";
import {WorldIdBridge} from "./lib/WorldIdBridge.sol";
import {ProofsLib} from "../lib/ProofsLib.sol";
import {IOprfKeyRegistry} from "../interfaces/IOprfKeyRegistry.sol";
import {ProvenPubKeyInfo} from "../lib/BridgeTypes.sol";
import {NothingChanged, UnsupportedOperation} from "../lib/BridgeErrors.sol";
import {ChainCommitted} from "../lib/BridgeEvents.sol";

/// @title WorldChainSource
/// @author World Contributors
/// @notice World Chain source-of-truth context. Reads WC registries directly via `propagateState`,
///   extends the rolling keccak state chain, and marks new chain heads as valid for L1 verification via MPT.
contract WorldChainWorldId is WorldIdBridge {
    using ProofsLib for ProofsLib.Chain;

    IL1Block public constant L1_BLOCK = IL1Block(address(0));

    /// @notice The WorldIDRegistry contract on World Chain.
    IWorldIDRegistry public immutable WC_REGISTRY;

    /// @notice The CredentialSchemaIssuerRegistry contract on World Chain.
    ICredentialSchemaIssuerRegistry public immutable WC_ISSUER_REGISTRY;

    /// @notice The OprfKeyRegistry contract on World Chain.
    IOprfKeyRegistry public immutable WC_OPRF_REGISTRY;

    ////////////////////////////////////////////////////////////
    //                      CONSTRUCTOR                       //
    ////////////////////////////////////////////////////////////

    constructor(
        address worldChainRegistry,
        address worldChainIssuerRegistry,
        address worldChainOprfRegistry,
        uint256 rootValidityWindow_,
        uint256 treeDepth_,
        uint64 minExpirationThreshold_
    ) WorldIdBridge(rootValidityWindow_, treeDepth_, minExpirationThreshold_) {
        WC_REGISTRY = IWorldIDRegistry(worldChainRegistry);
        WC_ISSUER_REGISTRY = ICredentialSchemaIssuerRegistry(worldChainIssuerRegistry);
        WC_OPRF_REGISTRY = IOprfKeyRegistry(worldChainOprfRegistry);
    }

    /// @dev World Chain is the source of truth — it does not accept inbound chained commits.
    function commitChained(ProofsLib.CommitmentWithProof calldata) external pure override {
        revert UnsupportedOperation();
    }

    /// @notice Reads all relevant state from WC registries and propagates any changes
    ///   into bridge state as a single batched chain extension.
    /// @param issuerSchemaIds The issuer schema IDs whose pubkeys should be checked.
    /// @param oprfKeyIds The OPRF key IDs whose pubkeys should be checked.
    function propagateState(uint64[] calldata issuerSchemaIds, uint160[] calldata oprfKeyIds) external {
        // Worst-case: root + all issuers + all OPRFs
        ProofsLib.Commitment[] memory commits =
            new ProofsLib.Commitment[](1 + issuerSchemaIds.length + oprfKeyIds.length);

        bytes32 blockHash = L1_BLOCK.hash();
        bytes32 proofId = bytes32(block.number);

        uint256 count;
        count = _propagateRoot(commits, count, blockHash, proofId);
        count = _propagateIssuerPubkeys(commits, count, issuerSchemaIds, blockHash, proofId);
        count = _propagateOprfKeys(commits, count, oprfKeyIds, blockHash, proofId);

        if (count == 0) revert NothingChanged();

        // Trim to actual count
        assembly {
            mstore(commits, count)
        }

        // Extend the hash chain (state already written directly above)
        keccakChain.commitChained(commits);

        emit ChainCommitted(keccakChain.head, block.number, abi.encode(commits));
    }

    ////////////////////////////////////////////////////////////
    //                       INTERNAL                         //
    ////////////////////////////////////////////////////////////

    /// @dev Checks if the root has changed on WC and, if so, writes state and appends a commitment.
    /// @param commits The commitment array to append to.
    /// @param count The current number of commitments in the array.
    /// @param blockHash The L1 block hash for the commitment.
    /// @param proofId The proof ID for the commitment.
    /// @return The updated count.
    function _propagateRoot(ProofsLib.Commitment[] memory commits, uint256 count, bytes32 blockHash, bytes32 proofId)
        private
        returns (uint256)
    {
        uint256 root = WC_REGISTRY.getLatestRoot();
        if (root != latestRoot) {
            updateRoot(root, block.timestamp, proofId);
            commits[count++] = ProofsLib.Commitment({
                blockHash: blockHash,
                data: abi.encodeWithSelector(ProofsLib.UPDATE_ROOT_SELECTOR, root, block.timestamp, proofId)
            });
        }
        return count;
    }

    /// @dev Checks each issuer pubkey for changes and appends commitments for any that differ.
    /// @param commits The commitment array to append to.
    /// @param count The current number of commitments in the array.
    /// @param issuerSchemaIds The issuer schema IDs to check.
    /// @param blockHash The L1 block hash for the commitment.
    /// @param proofId The proof ID for the commitment.
    /// @return The updated count.
    function _propagateIssuerPubkeys(
        ProofsLib.Commitment[] memory commits,
        uint256 count,
        uint64[] calldata issuerSchemaIds,
        bytes32 blockHash,
        bytes32 proofId
    ) private returns (uint256) {
        for (uint256 i; i < issuerSchemaIds.length; ++i) {
            uint64 id = issuerSchemaIds[i];
            ICredentialSchemaIssuerRegistry.Pubkey memory key = WC_ISSUER_REGISTRY.issuerSchemaIdToPubkey(id);
            ProvenPubKeyInfo storage stored = issuerSchemaIdToPubkeyAndProofId[id];

            if (key.x != stored.pubKey.x || key.y != stored.pubKey.y) {
                setIssuerPubkey(id, key.x, key.y, proofId);
                commits[count++] = ProofsLib.Commitment({
                    blockHash: blockHash,
                    data: abi.encodeWithSelector(ProofsLib.SET_ISSUER_PUBKEY_SELECTOR, id, key.x, key.y, proofId)
                });
            }
        }
        return count;
    }

    /// @dev Checks each OPRF key for changes and appends commitments for any that differ.
    /// @param commits The commitment array to append to.
    /// @param count The current number of commitments in the array.
    /// @param oprfKeyIds The OPRF key IDs to check.
    /// @param blockHash The L1 block hash for the commitment.
    /// @param proofId The proof ID for the commitment.
    /// @return The updated count.
    function _propagateOprfKeys(
        ProofsLib.Commitment[] memory commits,
        uint256 count,
        uint160[] calldata oprfKeyIds,
        bytes32 blockHash,
        bytes32 proofId
    ) private returns (uint256) {
        for (uint256 i; i < oprfKeyIds.length; ++i) {
            uint160 id = oprfKeyIds[i];
            OprfKeyGen.RegisteredOprfPublicKey memory key = WC_OPRF_REGISTRY.getOprfPublicKeyAndEpoch(id);
            ProvenPubKeyInfo storage stored = oprfKeyIdToPubkeyAndProofId[id];

            if (key.key.x != stored.pubKey.x || key.key.y != stored.pubKey.y) {
                setOprfKey(id, key.key.x, key.key.y, proofId);
                commits[count++] = ProofsLib.Commitment({
                    blockHash: blockHash,
                    data: abi.encodeWithSelector(ProofsLib.SET_OPRF_KEY_SELECTOR, id, key.key.x, key.key.y, proofId)
                });
            }
        }
        return count;
    }
}
