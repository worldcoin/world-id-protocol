// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {CrossDomainWorldIdVerifier} from "./CrossDomainWorldIdVerifier.sol";
import {INativeReceiver} from "../interfaces/INativeReceiver.sol";
import {ProofsLib} from "../../lib/ProofsLib.sol";
import {EmptyChainedCommits, UnsupportedOperation, ChainCommitted} from "../interfaces/IWorldIdBridge.sol";

/// @title BridgeAdapter
/// @author World Contributors
/// @notice Unified abstract base for all bridged World ID adapters. Provides two commit paths:
///   - `commitFromL1`: native L1->L2 messaging (override `_validateCrossChainSender`)
///   - `commitChained`: MPT-proof-based bridging (override with verification logic)
///   Both default to `revert UnsupportedOperation()`.
abstract contract BridgeAdapter is INativeReceiver, CrossDomainWorldIdVerifier {
    using ProofsLib for ProofsLib.Chain;

    /// @notice Human-readable name for this adapter.
    string public NAME;

    constructor(
        string memory name_,
        address verifier,
        uint256 rootValidityWindow_,
        uint256 treeDepth_,
        uint64 minExpirationThreshold_
    ) CrossDomainWorldIdVerifier(verifier, rootValidityWindow_, treeDepth_, minExpirationThreshold_) {
        NAME = name_;
    }

    // -- Native L1->L2 path --

    /// @inheritdoc INativeReceiver
    function commitFromL1(ProofsLib.Commitment[] calldata commits) external virtual {
        _validateCrossChainSender();
        if (commits.length == 0) revert EmptyChainedCommits();

        ProofsLib.Commitment[] memory memCommits = new ProofsLib.Commitment[](commits.length);
        for (uint256 i; i < commits.length; ++i) {
            memCommits[i] = ProofsLib.Commitment({blockHash: commits[i].blockHash, data: commits[i].data});
        }

        _applyAndCommit(memCommits, abi.encode(commits));
    }

    // -- MPT-proof path (default: unsupported) --

    /// @dev Default implementation reverts. Override for MPT-proof-based adapters.
    function commitChained(ProofsLib.CommitmentWithProof calldata) external virtual override {
        revert UnsupportedOperation();
    }

    // -- Internal --

    /// @dev Override to validate cross-chain sender. Default reverts (for non-native adapters).
    function _validateCrossChainSender() internal view virtual {
        revert UnsupportedOperation();
    }

    /// @dev Applies commitments, extends the keccak chain, and emits ChainCommitted.
    function _applyAndCommit(ProofsLib.Commitment[] memory commits, bytes memory eventData) internal {
        applyCommitments(commits);
        keccakChain.commitChained(commits);
        emit ChainCommitted(keccakChain.head, block.number, eventData);
    }
}
