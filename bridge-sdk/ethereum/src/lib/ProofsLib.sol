// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Hashing} from "../vendor/optimism/Hashing.sol";
import {RLPReader} from "../vendor/optimism/rlp/RLPReader.sol";
import {SecureMerkleTrie} from "../vendor/optimism/trie/SecureMerkleTrie.sol";

/// @dev Thrown when the output root preimage does not match the game's `rootClaim()`.
error InvalidOutputRootPreimage();

/// @dev Thrown when the computed chain head is not valid.
error InvalidChainHead();

/// @dev Thrown when the MPT account proof returns an empty RLP result.
error EmptyAccountProof();

/// @dev Thrown when the RLP-decoded account does not have exactly 4 fields.
error InvalidAccountFields();

/// @dev Thrown when a decoded storage value exceeds 32 bytes.
error StorageValueTooLarge();

/// @dev Thrown when a block header has fewer fields than required.
error InvalidBlockHeader();

/// @title ProofsLib
/// @author World Contributors
/// @notice Library for tools for creating, and verifying Bridge proofs.
library ProofsLib {
    using ProofsLib for *;

    /// @dev Maximum storage value size in bytes. MPT proofs can encode values up to 32 bytes, but larger values would be invalid.
    uint256 internal constant MAX_STORAGE_VALUE_BYTES = 32;

    /// @dev Index of the storage root in an RLP-encoded account's field list.
    uint256 internal constant ACCOUNT_STORAGE_ROOT_INDEX = 2;

    /// @dev Number of fields in an RLP-encoded account (nonce, balance, storageRoot, codeHash).
    uint256 internal constant ACCOUNT_RLP_FIELD_COUNT = 4;

    /// @dev Minimum number of fields in an RLP-encoded block header (depends on the presence of optional fields).
    uint256 internal constant MIN_BLOCK_HEADER_FIELDS = 15;

    /// @dev Index of the state root in an RLP-encoded block header's field list.
    uint256 internal constant BLOCK_HEADER_STATE_ROOT_INDEX = 3;

    /// @dev Action: a new Merkle root was proven. Data: `abi.encode(root, timestamp, proofId)`.
    bytes4 internal constant UPDATE_ROOT_SELECTOR = bytes4(keccak256("updateRoot(uint256,uint256,bytes32)"));

    /// @dev Selector for the `setIssuerPubkey`
    bytes4 internal constant SET_ISSUER_PUBKEY_SELECTOR =
        bytes4(keccak256("setIssuerPubkey(uint64,uint256,uint256,bytes32)"));

    /// @dev Selector for the `setOprfKey`
    bytes4 internal constant SET_OPRF_KEY_SELECTOR = bytes4(keccak256("setOprfKey(uint160,uint256,uint256,bytes32)"));

    /// @dev Selector for the `invalidateProofId`
    bytes4 internal constant INVALIDATE_PROOF_ID_SELECTOR = bytes4(keccak256("invalidateProofId(bytes32)"));

    /// @dev Slot for the `keccakChain` struct which holds the head and length of the hash chain.
    bytes32 internal constant _KECCAK_HASH_ACCUMULATOR_SLOT = bytes32(uint256(0));

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
        /// @param mptProof The MPT proof data needed to verify the commitments.
        bytes mptProof;
        /// @param commits The batch of commitments to be verified and applied.
        Commitment[] commits;
    }

    /// @notice Verifies an account proof and asserts that the stored chain head matches the expected value.
    /// @dev Combines `verifyAccountAndGetStorageRoot` and `storageFromProof` to check that the
    ///   `keccakChain.head` at slot 0 of `account` equals `chainHead`.
    /// @param accountProof The MPT account proof nodes.
    /// @param storageProof The MPT storage proof nodes for slot 0.
    /// @param stateRoot The L2 state root to verify against.
    /// @param account The contract address whose storage is being proven.
    /// @param chainHead The expected chain head value.
    function verifyAccountAndChainStorageProof(
        bytes[] memory accountProof,
        bytes[] memory storageProof,
        bytes32 stateRoot,
        address account,
        bytes32 chainHead
    ) internal pure {
        bytes32 storageRoot = verifyAccountAndGetStorageRoot(account, accountProof, stateRoot);
        uint256 claim = storageFromProof(storageProof, storageRoot, _KECCAK_HASH_ACCUMULATOR_SLOT);

        if (claim != uint256(chainHead)) revert InvalidChainHead();
    }

    ////////////////////////////////////////////////////////////
    //                  HASHING                               //
    ////////////////////////////////////////////////////////////

    /// @dev Appends multiple commitments to the chain sequentially, writing each new head to storage.
    ///      head' = keccak256(... keccak256(head || c[0].blockHash || c[0].data) || c[1].blockHash || c[1].data) ...)
    /// @param chain The storage-backed chain to extend.
    /// @param commitments The commitments to append.
    function commitChained(Chain storage chain, Commitment[] memory commitments) internal {
        for (uint256 i; i < commitments.length; ++i) {
            commit(chain, commitments[i]);
        }
    }

    /// @dev Appends a single commitment to the chain, writing the new head to storage.
    ///      head' = keccak256(head || blockHash || data)
    /// @param chain The storage-backed chain to extend.
    /// @param commitment The commitment to append.
    function commit(Chain storage chain, Commitment memory commitment) internal {
        bytes32 newHead = hash(chain, commitment);
        chain.head = newHead;
        chain.length += 1;
    }

    /// @dev Computes the chained hash of multiple commitments in memory without modifying storage.
    ///      Returns the final chain head after all commitments.
    /// @param chain The in-memory chain state (head and length are updated in place for loop usage).
    /// @param commitments The commitments to hash.
    /// @return newHead The resulting chain head after all commitments.
    function hashChained(Chain memory chain, Commitment[] memory commitments) internal pure returns (bytes32 newHead) {
        for (uint256 i; i < commitments.length; ++i) {
            newHead = hash(chain, commitments[i]);
        }
    }

    /// @dev Computes the hash of a single commitment appended to the chain.
    ///      Also updates chain.head and chain.length in memory for loop usage in `hashChained`.
    /// @param chain_ The in-memory chain state (head and length are updated in place).
    /// @param commitment_ The commitment to hash.
    /// @return newHead The resulting chain head after the commitment.
    function hash(Chain memory chain_, Commitment memory commitment_) internal pure returns (bytes32 newHead) {
        assembly {
            let fmp := mload(0x40)

            // Build preimage: head (32) || blockHash (32) || data (var)
            /// @dev Memory layout at fmp:
            ///   ┌──────────────┬───────────────┬───────────────────┐
            ///   │ head (32)    │ blockHash(32) │ data (var len)    │
            ///   └──────────────┴───────────────┴───────────────────┘
            mstore(fmp, mload(chain_))
            mstore(add(fmp, 0x20), mload(commitment_))

            // commitment + 0x20 holds a pointer to the bytes array: [length (32) | content]
            let dataPtr := mload(add(commitment_, 0x20))
            let dataLen := mload(dataPtr)

            // Copy data content into memory at offset fmp + 0x40 (skipping length prefix)
            mcopy(add(fmp, 0x40), add(dataPtr, 0x20), dataLen)

            // Compute the new chain head
            newHead := keccak256(fmp, add(0x40, dataLen))

            mstore(add(chain_, 0x00), newHead) // store new head in bytes [0x00 .. 0x20]
            mstore(add(chain_, 0x20), add(mload(add(chain_, 0x20)), 1)) // store length + 1 at byte offset 0x20
        }
    }

    ////////////////////////////////////////////////////////////
    //                  MPT UTILS                             //
    ////////////////////////////////////////////////////////////

    /// @dev Verifies the output root preimage against the root claim and extracts the L2 state root.
    /// @param outputRootProof_ The output root proof components: [version, stateRoot, messagePasserStorageRoot, latestBlockhash].
    /// @param rootClaim_ The expected root claim from the dispute game.
    /// @return stateRoot The verified L2 state root.
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

    /// @notice Verifies an MPT account proof and extracts the account's storage root.
    /// @param account_ The account address to verify.
    /// @param proof_ The MPT proof nodes for the account.
    /// @param stateRoot_ The state root to verify against.
    /// @return storageRoot The extracted storage root from the account proof.
    function verifyAccountAndGetStorageRoot(address account_, bytes[] memory proof_, bytes32 stateRoot_)
        internal
        pure
        returns (bytes32 storageRoot)
    {
        bytes memory accountRlp = SecureMerkleTrie.get(abi.encodePacked(account_), proof_, stateRoot_);
        if (accountRlp.length == 0) revert EmptyAccountProof();

        RLPReader.RLPItem[] memory accountFields = RLPReader.readList(accountRlp);
        if (accountFields.length != ACCOUNT_RLP_FIELD_COUNT) revert InvalidAccountFields();

        storageRoot = bytes32(RLPReader.readBytes(accountFields[ACCOUNT_STORAGE_ROOT_INDEX]));
    }

    /// @notice Proves a storage value via MPT proof and returns it as uint256.
    /// @dev The storage trie stores RLP-encoded values with leading zeros stripped.
    ///   This function handles the full decode: verify proof → RLP decode → right-align → uint256.
    function storageFromProof(bytes[] memory proof_, bytes32 storageRoot_, bytes32 slot_)
        internal
        pure
        returns (uint256 value)
    {
        bytes memory rlpValue = SecureMerkleTrie.get(abi.encodePacked(slot_), proof_, storageRoot_);
        bytes memory decoded = RLPReader.readBytes(rlpValue);
        uint256 len = decoded.length;
        if (len > MAX_STORAGE_VALUE_BYTES) revert StorageValueTooLarge();
        assembly {
            // Load 32 bytes from the data pointer. For len < 32, the high bytes
            // contain our data and the low bytes are garbage from adjacent memory.
            // Shift right by (32 - len) * 8 bits to right-align and discard garbage.
            // For len == 0 the shift is 256 which yields 0 per EVM spec.
            value := shr(mul(sub(MAX_STORAGE_VALUE_BYTES, len), 8), mload(add(decoded, 0x20)))
        }
    }

    /// @notice Extracts the state root from an RLP-encoded block header.
    /// @dev Callers MUST verify `keccak256(headerRlp)` against a trusted source before calling.
    /// @param headerRlp The RLP-encoded block header.
    /// @return stateRoot The state root from the block header (RLP index 3).
    function extractStateRootFromHeader(bytes memory headerRlp) internal pure returns (bytes32 stateRoot) {
        RLPReader.RLPItem[] memory fields = RLPReader.readList(headerRlp);
        if (fields.length < MIN_BLOCK_HEADER_FIELDS) revert InvalidBlockHeader();

        stateRoot = bytes32(RLPReader.readBytes(fields[BLOCK_HEADER_STATE_ROOT_INDEX]));
    }
}
