// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {RLPReader} from "@optimism-bedrock/src/libraries/rlp/RLPReader.sol";
import {SecureMerkleTrie} from "@optimism-bedrock/src/libraries/trie/SecureMerkleTrie.sol";
import {Hashing} from "@optimism-bedrock/src/libraries/Hashing.sol";

/// @dev Thrown when the computed chain head does not match the expected value.
error InvalidChainHead();

/// @dev Thrown when the MPT account proof returns an empty RLP result.
error EmptyAccountProof();

/// @dev Thrown when the RLP-decoded account does not have exactly 4 fields.
error InvalidAccountFields();

/// @dev Thrown when a decoded storage value exceeds 32 bytes.
error StorageValueTooLarge();

/// @dev Thrown when the dispute game UUID maps to zero (game not found in the factory).
error GameNotFound();

/// @dev Thrown when the output root preimage is invalid.
error InvalidOutputRootPreimage();

/// @title ProofsLib
/// @author World Contributors
/// @notice Library for keccak hash chain operations, MPT proof verification, and commitment encoding/decoding.
library ProofsLib {
    /// @dev Maximum storage value size in bytes.
    uint256 internal constant MAX_STORAGE_VALUE_BYTES = 32;

    /// @dev Index of the storage root in an RLP-encoded account's field list.
    uint256 internal constant ACCOUNT_STORAGE_ROOT_INDEX = 2;

    /// @dev Number of fields in an RLP-encoded account (nonce, balance, storageRoot, codeHash).
    uint256 internal constant ACCOUNT_RLP_FIELD_COUNT = 4;

    /// @dev Selector for `updateRoot(uint256,uint256,bytes32)`.
    bytes4 internal constant UPDATE_ROOT_SELECTOR = bytes4(keccak256("updateRoot(uint256,uint256,bytes32)"));

    /// @dev Selector for `setIssuerPubkey(uint64,uint256,uint256,bytes32)`.
    bytes4 internal constant SET_ISSUER_PUBKEY_SELECTOR =
        bytes4(keccak256("setIssuerPubkey(uint64,uint256,uint256,bytes32)"));

    /// @dev Selector for `setOprfKey(uint160,uint256,uint256,bytes32)`.
    bytes4 internal constant SET_OPRF_KEY_SELECTOR = bytes4(keccak256("setOprfKey(uint160,uint256,uint256,bytes32)"));

    /// @dev Represents a hash chain with a head and length.
    struct Chain {
        bytes32 head;
        uint64 length;
    }

    /// @dev Represents a single state commitment in the keccak chain.
    struct Commitment {
        bytes32 blockHash;
        bytes data;
    }

    ////////////////////////////////////////////////////////////
    //                       HASHING                          //
    ////////////////////////////////////////////////////////////

    /// @dev Appends multiple commitments to the storage chain. Reads storage once at the start
    ///   and writes the final head + length once at the end (2 SSTOREs total, regardless of N).
    function commitChained(Chain storage chain, Commitment[] memory commitments) internal {
        bytes32 head = chain.head;
        uint64 length = chain.length;

        for (uint256 i; i < commitments.length; ++i) {
            head = keccak256(abi.encodePacked(head, commitments[i].blockHash, commitments[i].data));
            ++length;
        }

        chain.head = head;
        chain.length = length;
    }

    /// @dev Computes the chained hash of multiple commitments in memory (pure, no storage writes).
    function hashChained(Chain memory chain, Commitment[] memory commitments) internal pure returns (bytes32) {
        bytes32 head = chain.head;

        for (uint256 i; i < commitments.length; ++i) {
            head = keccak256(abi.encodePacked(head, commitments[i].blockHash, commitments[i].data));
        }

        return head;
    }

    ////////////////////////////////////////////////////////////
    //                      MPT PROOFS                        //
    ////////////////////////////////////////////////////////////

    /// @notice Verifies an MPT account proof against a state root and extracts the account's storage root.
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

    /// @notice Proves a storage slot value via MPT proof and returns it as uint256.
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
            value := shr(mul(sub(MAX_STORAGE_VALUE_BYTES, len), 8), mload(add(decoded, 0x20)))
        }
    }

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
            keccak256(abi.encodePacked(version, stateRoot, messagePasserStorageRoot, latestBlockhash));

        if (computedRoot != rootClaim_) revert InvalidOutputRootPreimage();
    }

    /// @notice Proves a contract's storage slot value via two-step MPT (account proof + storage proof)
    ///   against a state root.
    /// @param account_ The contract address to prove.
    /// @param slot_ The storage slot to read.
    /// @param accountProof_ MPT account proof for the contract.
    /// @param storageProof_ MPT storage proof for the slot.
    /// @param stateRoot_ The execution state root to verify against.
    /// @return value The proven storage slot value as bytes32.
    function proveStorageSlot(
        address account_,
        bytes32 slot_,
        bytes[] memory accountProof_,
        bytes[] memory storageProof_,
        bytes32 stateRoot_
    ) internal pure returns (bytes32 value) {
        bytes32 storageRoot = verifyAccountAndGetStorageRoot(account_, accountProof_, stateRoot_);
        value = bytes32(storageFromProof(storageProof_, storageRoot, slot_));
    }

    ////////////////////////////////////////////////////////////
    //                  COMMITMENT DECODING                   //
    ////////////////////////////////////////////////////////////

    /// @dev Decodes an `updateRoot` commitment payload.
    function decodeUpdateRoot(bytes memory data_) internal pure returns (uint256 root, uint256 ts, bytes32 proofId) {
        (root, ts, proofId) = abi.decode(data_, (uint256, uint256, bytes32));
    }

    /// @dev Decodes a `setIssuerPubkey` commitment payload.
    function decodeSetIssuerPubkey(bytes memory data_)
        internal
        pure
        returns (uint64 issuerSchemaId, uint256 x, uint256 y, bytes32 proofId)
    {
        (issuerSchemaId, x, y, proofId) = abi.decode(data_, (uint64, uint256, uint256, bytes32));
    }

    /// @dev Decodes a `setOprfKey` commitment payload.
    function decodeSetOprfKey(bytes memory data_)
        internal
        pure
        returns (uint160 oprfKeyId, uint256 x, uint256 y, bytes32 proofId)
    {
        (oprfKeyId, x, y, proofId) = abi.decode(data_, (uint160, uint256, uint256, bytes32));
    }
}
