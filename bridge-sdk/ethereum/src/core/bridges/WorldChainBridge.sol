// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IWorldIDRegistry} from "@world-id/interfaces/IWorldIDRegistry.sol";
import {ICredentialSchemaIssuerRegistry} from "@world-id/interfaces/ICredentialSchemaIssuerRegistry.sol";
import {OprfKeyGen} from "lib/oprf-key-registry/src/OprfKeyGen.sol";
import {StateBridgeBase} from "../lib/StateBridgeBase.sol";
import {ProofsLib} from "../lib/ProofsLib.sol";
import {IOprfKeyRegistry} from "../../interfaces/IOprfKeyRegistry.sol";
import {ProvenPubKeyInfo, NothingChanged, ZeroAddress} from "../interfaces/IWorldIDBridge.sol";

/// @title WorldChainBridge
/// @author World Contributors
/// @notice World Chain source-of-truth state. Reads WC registries directly via `propagateState`,
///   extends the rolling keccak state chain, and marks new chain heads as valid for L1 verification via MPT.
///   This is NOT a verifier — it only produces state for downstream consumption.
contract WorldChainBridge is StateBridgeBase {
    using ProofsLib for *;

    /// @dev The deployment version of the bridge. Used for reinitialization checks.
    uint64 public constant VERSION = 1;

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
    }

    ////////////////////////////////////////////////////////////
    //                      INITIALIZER                       //
    ////////////////////////////////////////////////////////////

    /// @notice Initializes the World Chain source bridge proxy.
    function initialize(string memory name_, string memory version_, address owner_, address[] memory initialGateways_)
        public
        virtual
        reinitializer(VERSION)
    {
        __StateBridgeBase_init(
            InitConfig({name: name_, version: version_, owner: owner_, authorizedGateways: initialGateways_})
        );
    }

    ////////////////////////////////////////////////////////////
    //                    PROPAGATE STATE                     //
    ////////////////////////////////////////////////////////////

    /// @notice Reads all relevant state from WC registries and propagates any changes
    ///   into bridge state as a single batched chain extension.
    /// @param issuerSchemaIds The issuer schema IDs whose pubkeys should be checked.
    /// @param oprfKeyIds The OPRF key IDs whose pubkeys should be checked.
    function propagateState(uint64[] calldata issuerSchemaIds, uint160[] calldata oprfKeyIds) external virtual {
        // Worst-case: root + all issuers + all OPRFs
        ProofsLib.Commitment[] memory commits =
            new ProofsLib.Commitment[](1 + issuerSchemaIds.length + oprfKeyIds.length);

        bytes32 blockHash = blockhash(block.number - 1);
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

        _applyAndCommit(commits);
    }

    ////////////////////////////////////////////////////////////
    //                       INTERNAL                         //
    ////////////////////////////////////////////////////////////

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
