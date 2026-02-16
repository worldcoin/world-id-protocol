// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {CrossDomainWorldIdVerifier} from "./CrossDomainWorldIdVerifier.sol";
import {INativeWorldId} from "../../interfaces/INativeWorldId.sol";
import {ProofsLib} from "../../lib/ProofsLib.sol";
import {EmptyChainedCommits, UnsupportedOperation} from "../../lib/BridgeErrors.sol";
import {ChainCommitted} from "../../lib/BridgeEvents.sol";

/// @title NativeWorldId
/// @author World Contributors
/// @notice Abstract base contract for L2 chains that receive World ID state via native
///   L1→L2 messaging. Validates the cross-chain sender and applies commitments.
///   Inherits `CrossDomainWorldIdVerifier` so end users can verify ZK proofs against the bridged state.
abstract contract NativeWorldId is INativeWorldId, CrossDomainWorldIdVerifier {
    using ProofsLib for ProofsLib.Chain;

    /// @notice The L1StateBridge contract address on Ethereum L1.
    address public immutable L1_STATE_BRIDGE;

    constructor(
        address verifier,
        address l1StateBridge,
        uint256 rootValidityWindow_,
        uint256 treeDepth_,
        uint64 minExpirationThreshold_
    ) CrossDomainWorldIdVerifier(verifier, rootValidityWindow_, treeDepth_, minExpirationThreshold_) {
        L1_STATE_BRIDGE = l1StateBridge;
    }

    /// @inheritdoc INativeWorldId
    function commitFromL1(ProofsLib.Commitment[] calldata commits) external virtual {
        _validateCrossChainSender();
        if (commits.length == 0) revert EmptyChainedCommits();

        // Copy calldata commits to memory for applyCommitments / commitChained
        ProofsLib.Commitment[] memory memCommits = new ProofsLib.Commitment[](commits.length);
        for (uint256 i; i < commits.length; ++i) {
            memCommits[i] = ProofsLib.Commitment({blockHash: commits[i].blockHash, data: commits[i].data});
        }

        applyCommitments(memCommits);
        keccakChain.commitChained(memCommits);

        emit ChainCommitted(keccakChain.head, block.number, abi.encode(commits));
    }

    /// @dev Reverts if the cross-chain message is not from L1_STATE_BRIDGE via the native messenger.
    function _validateCrossChainSender() internal view virtual;

    /// @dev Native receivers do not accept MPT-based commitChained — use commitFromL1 instead.
    function commitChained(ProofsLib.CommitmentWithProof calldata) external pure override {
        revert UnsupportedOperation();
    }
}
