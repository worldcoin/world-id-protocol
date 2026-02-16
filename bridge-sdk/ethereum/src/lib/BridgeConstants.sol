// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title BridgeConstants
/// @author World Contributors

// ── Memory / ABI layout ──

/// @dev Size of one ABI-encoded word (32 bytes).
uint256 constant OneWord = 0x20;

/// @dev Size of two ABI-encoded words (64 bytes).
uint256 constant TwoWords = 0x40;

/// @dev EVM free memory pointer location.
uint256 constant FreeMemoryPointer = 0x40;

// ── Commitment data decode offsets ──
//   Commitment.data layout: [selector (4 bytes) | arg0 (32) | arg1 (32) | arg2 (32) | arg3 (32)]
//   When loaded from a `bytes memory` pointer, the first 32 bytes are the length prefix,
//   so the selector starts at ptr + 0x20.

/// @dev Offset from `bytes memory` data pointer to the 4-byte selector.
uint256 constant CommitmentData_selector_offset = 0x20;

/// @dev Offset from `bytes memory` data pointer to the first ABI argument.
uint256 constant CommitmentData_arg0_offset = 0x24;

/// @dev Offset from `bytes memory` data pointer to the second ABI argument.
uint256 constant CommitmentData_arg1_offset = 0x44;

/// @dev Offset from `bytes memory` data pointer to the third ABI argument.
uint256 constant CommitmentData_arg2_offset = 0x64;

/// @dev Offset from `bytes memory` data pointer to the fourth ABI argument.
uint256 constant CommitmentData_arg3_offset = 0x84;

// ── Chain struct offsets ──
//   ProofsLib.Chain { bytes32 head; uint64 length; }

/// @dev Offset of `head` within a Chain struct in memory.
uint256 constant Chain_head_offset = 0x00;

/// @dev Offset of `length` within a Chain struct in memory.
uint256 constant Chain_length_offset = 0x20;

// ── Wormhole wire format ──

/// @dev Size of the Wormhole payload header: version(1) + action(1) + numCommits(2).
uint256 constant WormholeHeader_size = 4;

/// @dev Per-commit overhead in the Wormhole wire format: blockHash(32) + dataLen(2).
uint256 constant WormholeCommit_overhead = 34;

// ── Storage proof helpers ──

/// @dev Maximum size of a storage value in bytes (one EVM word).
uint256 constant MaxStorageValueBytes = 32;

/// @dev Number of bits per byte, used in right-alignment shifts.
uint256 constant BitsPerByte = 8;

/// @dev Expected number of fields in an RLP-encoded Ethereum account (nonce, balance, storageRoot, codeHash).
uint256 constant AccountRlpFieldCount = 4;

/// @dev Index of the storage root in an RLP-encoded account's field list.
uint256 constant AccountStorageRootIndex = 2;

/// @dev Minimum number of fields in an RLP-encoded block header to contain the state root.
uint256 constant MinBlockHeaderFields = 4;

/// @dev Index of the state root in an RLP-encoded block header's field list.
uint256 constant BlockHeaderStateRootIndex = 3;
