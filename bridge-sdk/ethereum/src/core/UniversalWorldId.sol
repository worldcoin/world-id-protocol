// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ProofsLib} from "../lib/ProofsLib.sol";
import {CrossDomainWorldIdVerifier} from "./lib/CrossDomainWorldIdVerifier.sol";
import {IL1BlockHashOracle} from "../interfaces/IL1BlockHashOracle.sol";
import {EmptyChainedCommits, UnknownL1BlockHash} from "../lib/BridgeErrors.sol";
import {ChainCommitted} from "../lib/BridgeEvents.sol";

/// @title UniversalReceiver
/// @author World Contributors
/// @notice Universally EVM-compatible World ID state bridge.
contract UniversalWorldId is CrossDomainWorldIdVerifier {
    using ProofsLib for ProofsLib.Chain;

    /// @notice The L1StateBridge contract address on Ethereum.
    address public immutable ETHEREUM_STATE_BRIDGE;

    /// @notice The L1 block hash oracle for trust anchoring L1 state.
    IL1BlockHashOracle public immutable ETHEREUM_BLOCK_HASH_ORACLE;

    constructor(
        address verifier,
        address ethereumBlockHashOracle,
        address ethereumStateBridge,
        uint256 rootValidityWindow_,
        uint256 treeDepth_,
        uint64 minExpirationThreshold_
    ) CrossDomainWorldIdVerifier(verifier, rootValidityWindow_, treeDepth_, minExpirationThreshold_) {
        ETHEREUM_BLOCK_HASH_ORACLE = IL1BlockHashOracle(ethereumBlockHashOracle);
        ETHEREUM_STATE_BRIDGE = ethereumStateBridge;
    }

    /// @notice Commits a sequence of state transitions by verifying them against L1 state
    ///   via MPT proof. The L1 block hash is read from the oracle for trust anchoring.
    /// @param commitWithProof The commitment batch with MPT proof data.
    function commitChained(ProofsLib.CommitmentWithProof calldata commitWithProof) external virtual override {
        if (commitWithProof.commits.length == 0) revert EmptyChainedCommits();

        (bytes memory l1HeaderRlp, bytes[] memory l1AccountProof, bytes[] memory chainHeadValidityProof) =
            abi.decode(commitWithProof.mptProof, (bytes, bytes[], bytes[]));

        // Verify L1 block hash once — no need to hash again in extractStateRootFromHeader
        bytes32 blockHash = keccak256(l1HeaderRlp);
        if (!ETHEREUM_BLOCK_HASH_ORACLE.isValid(blockHash)) revert UnknownL1BlockHash();

        // 1. Compute expected chain head from current state + new commits
        ProofsLib.Chain memory chain = keccakChain;
        bytes32 newChainHead = chain.hashChained(commitWithProof.commits);

        // 2. Extract state root from L1 header (hash already verified above)
        bytes32 stateRoot = ProofsLib.extractStateRootFromHeader(l1HeaderRlp);

        // 3. Verify account + storage proof: chain head at slot 0 of L1 bridge matches
        ProofsLib.verifyAccountAndChainStorageProof(
            l1AccountProof, chainHeadValidityProof, stateRoot, ETHEREUM_STATE_BRIDGE, newChainHead
        );

        // 4. Apply state changes and extend chain
        applyCommitments(commitWithProof.commits);
        keccakChain.commitChained(commitWithProof.commits);

        emit ChainCommitted(keccakChain.head, block.number, abi.encode(commitWithProof));
    }
}
