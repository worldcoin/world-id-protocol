// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {WorldIdStateBridge} from "./abstract/WorldIdStateBridge.sol";
import {BabyJubJub} from "lib/oprf-key-registry/src/BabyJubJub.sol";
import {IWorldIDRegistry} from "../interfaces/IWorldIDRegistry.sol";
import {ICredentialSchemaIssuerRegistry} from "../interfaces/ICredentialSchemaIssuerRegistry.sol";
import {OprfKeyGen} from "lib/oprf-key-registry/src/OprfKeyGen.sol";
import {IL1Block} from "./vendored/optimism/IL1Block.sol";
import {ProofsLib} from "./libraries/Proofs.sol";
import {IWorldIdStateBridge} from "./interfaces/IWorldIdStateBridge.sol";

interface IOprfKeyRegistry {
    function getOprfPublicKeyAndEpoch(uint160) external view returns (OprfKeyGen.RegisteredOprfPublicKey memory);
}

/// @title SourceContext
/// @author World Contributors
/// @notice World Chain source-of-truth context. Reads WC registries directly via `propagateRoot`,
///   `propagateIssuerPubkey`, and `propagateOprfKey`, extends the rolling keccak state chain, and
///   marks new chain heads as valid for L1 verification via MPT.
contract WorldChainStateBridge is WorldIdStateBridge {
    using ProofsLib for ProofsLib.Chain;

    ////////////////////////////////////////////////////////////
    //                       IMMUTABLES                       //
    ////////////////////////////////////////////////////////////

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
        IL1Block l1BlockHashOracle,
        address l1Bridge,
        uint256 rootValidityWindow_,
        uint256 treeDepth_,
        uint64 minExpirationThreshold_
    ) WorldIdStateBridge(l1BlockHashOracle, l1Bridge, rootValidityWindow_, treeDepth_, minExpirationThreshold_) {
        WC_REGISTRY = IWorldIDRegistry(worldChainRegistry);
        WC_ISSUER_REGISTRY = ICredentialSchemaIssuerRegistry(worldChainIssuerRegistry);
        WC_OPRF_REGISTRY = IOprfKeyRegistry(worldChainOprfRegistry);
    }

    ////////////////////////////////////////////////////////////
    //                    PROPAGATION                         //
    ////////////////////////////////////////////////////////////

    /// @notice Reads the latest Merkle root from WC's WorldIDRegistry and propagates it
    ///   into bridge state, extending the state chain and marking the new head valid.
    /// @dev Permissionless — anyone can call. Reverts if root hasn't changed.
    function propagateRoot() external {
        uint256 root = WC_REGISTRY.getLatestRoot();
        if (root == latestRoot) revert RootNotChanged();

        ProofsLib.Commitment memory commit = ProofsLib.Commitment({
            blockHash: L1_BLOCK_HASH_ORACLE.hash(),
            data: abi.encodeWithSelector(UPDATE_ROOT_SELECTOR, root, block.timestamp, bytes32(block.number))
        });

        applyCommitment(commit);
        keccakChain.commit(commit);

        _validChainHeads[keccakChain.head] = true;

        emit ChainCommitted(keccakChain.head, block.number, abi.encode(commit));
    }

    /// @notice Reads an issuer public key from WC's CredentialSchemaIssuerRegistry and
    ///   propagates it into bridge state.
    /// @dev Reverts if the pubkey hasn't changed since the last propagation.
    function propagateIssuerPubkey(uint64 issuerSchemaId) external {
        ICredentialSchemaIssuerRegistry.Pubkey memory key = WC_ISSUER_REGISTRY.issuerSchemaIdToPubkey(issuerSchemaId);

        if (
            key.x == _issuerSchemaIdToPubkeyAndProofId[issuerSchemaId].pubKey.x
                && key.y == _issuerSchemaIdToPubkeyAndProofId[issuerSchemaId].pubKey.y
        ) revert IssuerPubkeyNotChanged();

        ProofsLib.Commitment memory commit = ProofsLib.Commitment({
            blockHash: L1_BLOCK_HASH_ORACLE.hash(),
            data: abi.encodeWithSelector(
                SET_ISSUER_PUBKEY_SELECTOR, issuerSchemaId, key.x, key.y, bytes32(block.number)
            )
        });

        applyCommitment(commit);
        keccakChain.commit(commit);
        _validChainHeads[keccakChain.head] = true;
    }

    /// @notice Reads an OPRF public key from WC's OprfKeyRegistry and propagates it into
    ///   bridge state.
    /// @dev Reverts if the key hasn't changed since the last propagation.
    function propagateOprfKey(uint160 oprfKeyId) external {
        OprfKeyGen.RegisteredOprfPublicKey memory key = WC_OPRF_REGISTRY.getOprfPublicKeyAndEpoch(oprfKeyId);
        if (
            key.key.x == _oprfKeyIdToPubkeyAndProofId[oprfKeyId].pubKey.x
                && key.key.y == _oprfKeyIdToPubkeyAndProofId[oprfKeyId].pubKey.y
        ) {
            revert OprfKeyNotChanged();
        }

        ProofsLib.Commitment memory commit = ProofsLib.Commitment({
            blockHash: L1_BLOCK_HASH_ORACLE.hash(),
            data: abi.encodeWithSelector(SET_OPRF_KEY_SELECTOR, oprfKeyId, key.key.x, key.key.y, bytes32(block.number))
        });

        applyCommitment(commit);
        keccakChain.commit(commit);
        _validChainHeads[keccakChain.head] = true;
    }
}
