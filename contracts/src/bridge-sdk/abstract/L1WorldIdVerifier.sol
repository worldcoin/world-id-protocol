// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {L1MptStorageProofAdapter} from "./L1MptStorageProofAdapter.sol";
import {IDisputeGameFactory} from "../vendored/optimism/IDisputeGameFactory.sol";

/// @title L1WorldIdVerifier
/// @author World Contributors
/// @notice The L1WorldIdVerifier is the L1 implementation of the World ID verifier
abstract contract L1WorldIdVerifier is L1MptStorageProofAdapter {
    /// @param disputeGameFactory The DisputeGameFactory contract on L1.
    /// @param worldChainRegistry The WorldIDRegistry address on World Chain.
    /// @param worldChainIssuerRegistry The CredentialSchemaIssuerRegistry address on World Chain.
    /// @param worldChainOprfRegistry The OprfKeyRegistry address on World Chain.
    /// @param rootValidityWindow_ The root validity window in seconds.
    constructor(
        IDisputeGameFactory disputeGameFactory,
        address worldChainRegistry,
        address worldChainIssuerRegistry,
        address worldChainOprfRegistry,
        uint256 rootValidityWindow_
    )
        L1MptStorageProofAdapter(
            disputeGameFactory,
            worldChainRegistry,
            worldChainIssuerRegistry,
            worldChainOprfRegistry,
            rootValidityWindow_
        )
    {}

    function receiveRoot(uint256 root, uint256 worldChainTimestamp, uint256 treeDepth, bytes32 proofId)
        public
        virtual
        override
    {}

    function receiveIssuerPubkey(uint64 issuerSchemaId, uint256 x, uint256 y, bytes32 proofId)
        public
        virtual
        override
    {}

    function receiveOprfKey(uint160 oprfKeyId, uint256 x, uint256 y, bytes32 proofId) public virtual override {}
}
