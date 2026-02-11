// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {MptVerifier} from "./MptVerifier.sol";
import {Hashing} from "../vendored/optimism/Hashing.sol";

/// @title ProofsLib
/// @author World Contributors
/// @notice Library for tools for creating, and verifying Bridge proofs.
library ProofsLib {
    error InvalidOutputRootPreimage();
    error InvalidChainHead();
    error UnknownL1BlockHash();

    using ProofsLib for Chain;

    /// @dev Represents a hash chain with a head and length.
    struct Chain {
        /// @param head The current head of the hash chain (the most recent commitment).
        bytes32 head;
        /// @param length The number of commitments in the chain.
        uint64 length;
    }

    /// @dev Represents a single state commitment.
    struct Commitment {
        /// @param blockHash The l2 block hash corresponding to the state commitment.
        bytes32 blockHash;
        /// @param data The state commitment performed.
        bytes data;
    }

    /// @notice A batch of commitments wrapping an associated MPT storage proof.
    struct CommitmentWithProof {
        bytes mptProof;
        Commitment[] commits;
    }

    /// @notice Proves that a given chain head is a valid extension of the contract's state
    ///   by verifying an output root preimage and MPT storage proof against the WC bridge.
    /// @param chain The current chain state (in memory, for hashing).
    /// @param commitment The commitment batch with MPT proof data.
    /// @param l2StateBridge The address of the World Chain state bridge contract.
    /// @param rootClaim The root claim extracted from a validated DisputeGame.
    function verifyL1Proof(
        Chain memory chain,
        CommitmentWithProof calldata commitment,
        address l2StateBridge,
        bytes32 rootClaim
    ) internal pure {
        bytes32 newChainHead = chain.hashChained(commitment.commits);

        bytes calldata proofData = commitment.mptProof;

        (bytes[] memory outputRootProof, bytes[] memory accountProof, bytes[] memory chainHeadValidityProof) =
            abi.decode(proofData, (bytes[], bytes[], bytes[]));

        bytes32 stateRoot = verifyOutputRootPreimage(outputRootProof, rootClaim);

        bytes32 storageRoot = MptVerifier.verifyAccountAndGetStorageRoot(l2StateBridge, accountProof, stateRoot);

        bytes32 validitySlot = MptVerifier._computeMappingSlot(MptVerifier._VALID_CHAIN_KECCAK_CHAIN_SLOT, newChainHead);

        uint256 isValid = MptVerifier.storageFromProof(chainHeadValidityProof, storageRoot, validitySlot);

        if (isValid != 1) revert InvalidChainHead();
    }

    /// @dev Verifies a commitment batch against L1 state via MPT proof.
    /// @param chain The current chain state (in memory, for hashing).
    /// @param commitWithProof The commitment batch with MPT proof.
    /// @param l1StateBridge The address of the L1 relay contract whose state is being proven.
    /// @param trustedL1BlockHash The L1 block hash attested by an oracle (caller must verify).
    function verifyProof(
        Chain memory chain,
        CommitmentWithProof calldata commitWithProof,
        address l1StateBridge,
        bytes32 trustedL1BlockHash
    ) internal pure {
        bytes32 newChain = chain.hashChained(commitWithProof.commits);

        (bytes memory l1HeaderRlp, bytes[] memory l1AccountProof, bytes[] memory chainHeadValidityProof) =
            abi.decode(commitWithProof.mptProof, (bytes, bytes[], bytes[]));

        bytes32 l1BlockHash = keccak256(l1HeaderRlp);

        if (l1BlockHash != trustedL1BlockHash) revert UnknownL1BlockHash();

        bytes32 l1StateRoot = MptVerifier.extractStateRootFromHeader(l1HeaderRlp, l1BlockHash);
        bytes32 storageRoot = MptVerifier.verifyAccountAndGetStorageRoot(l1StateBridge, l1AccountProof, l1StateRoot);

        bytes32 validitySlot = MptVerifier._computeMappingSlot(MptVerifier._VALID_CHAIN_KECCAK_CHAIN_SLOT, newChain);
        uint256 isValid = MptVerifier.storageFromProof(chainHeadValidityProof, storageRoot, validitySlot);

        if (isValid != 1) revert InvalidChainHead();
    }

    /// @dev Appends multiple commitments to the chain sequentially.
    ///      head' = keccak256(... keccak256(head || c[0].blockHash || c[0].data) || c[1].blockHash || c[1].data) ...)
    function commitChained(Chain storage chain, Commitment[] memory commitments) internal {
        for (uint256 i; i < commitments.length; ++i) {
            commit(chain, commitments[i]);
        }
    }

    /// @dev Appends a single commitment to the chain.
    ///      head' = keccak256(head || blockHash || data)
    function commit(Chain storage chain, Commitment memory commitment) internal {
        bytes32 newHead = hash(chain, commitment);
        chain.head = newHead;
        chain.length += 1;
    }

    /// @dev Computes the chained hash of multiple commitments without modifying storage.
    ///      Returns the final chain head after all commitments.
    function hashChained(Chain memory chain, Commitment[] memory commitments) internal pure returns (bytes32 newHead) {
        for (uint256 i; i < commitments.length; ++i) {
            newHead = hash(chain, commitments[i]);
        }
    }

    /// @dev Computes the hash of a single commitment appended to the chain.
    ///      Also updates chain.head and chain.length in memory for loop usage in hashChained.
    function hash(Chain memory chain, Commitment memory commitment) internal pure returns (bytes32 newHead) {
        assembly {
            let fmp := mload(0x40)

            // Build preimage: head (32) || blockHash (32) || data (var)
            mstore(fmp, mload(chain))
            mstore(add(fmp, 0x20), mload(commitment))

            // commitment + 0x20 holds a pointer to the bytes array: [length (32) | content]
            let dataPtr := mload(add(commitment, 0x20))
            let dataLen := mload(dataPtr)
            mcopy(add(fmp, 0x40), add(dataPtr, 0x20), dataLen)

            // Compute the new chain head
            newHead := keccak256(fmp, add(0x40, dataLen))

            // Update chain.head and chain.length in memory (for hashChained loop)
            mstore(chain, newHead)
            mstore(add(chain, 0x20), add(mload(add(chain, 0x20)), 1))
        }
    }

    /// @dev Verifies the output root preimage against the root claim and extracts the L2 state root.
    function verifyOutputRootPreimage(bytes[] memory outputRootProof_, bytes32 rootClaim_)
        internal
        pure
        returns (bytes32 stateRoot)
    {
        bytes32 version = bytes32(outputRootProof_[0]);
        stateRoot = bytes32(outputRootProof_[1]);
        bytes32 messagePasserStorageRoot = bytes32(outputRootProof_[2]);
        bytes32 latestBlockhash = bytes32(outputRootProof_[3]);

        bytes32 computedRoot =
            Hashing.hashOutputRootProof(version, stateRoot, messagePasserStorageRoot, latestBlockhash);

        if (computedRoot != rootClaim_) revert InvalidOutputRootPreimage();
    }
}
