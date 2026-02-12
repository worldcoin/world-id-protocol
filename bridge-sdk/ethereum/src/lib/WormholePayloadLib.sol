// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ProofsLib} from "./ProofsLib.sol";
import {TooManyCommits, PayloadTooShort, UnsupportedPayloadVersion, UnknownPayloadAction} from "./BridgeErrors.sol";

/// @title WormholePayloadLib
/// @author World Contributors
/// @notice Encoding and decoding library for World ID Wormhole message payloads.
/// @dev Defines the wire format used by the WormholeBridgeAdapter (EVM sender) and the
///   Solana bridge program (receiver). Uses a compact big-endian binary format that both
///   EVM and Solana can efficiently produce and consume.
///
///   Wire format (big-endian):
///   ┌──────────────────────────────────────────────────┐
///   │ version       (1 byte)   = 0x01                  │
///   │ action        (1 byte)   = 0x01 (COMMIT_FROM_L1) │
///   │ num_commits   (2 bytes)  = number of commitments │
///   │ For each commitment:                              │
///   │   block_hash  (32 bytes)                          │
///   │   data_len    (2 bytes)  = length of data field   │
///   │   data        (N bytes)  = selector + ABI params  │
///   └──────────────────────────────────────────────────┘
library WormholePayloadLib {
    /// @dev Payload version for future-proofing.
    uint8 internal constant VERSION = 0x01;

    /// @dev Action type: deliver a batch of commitments (mirrors commitFromL1).
    uint8 internal constant ACTION_COMMIT_FROM_L1 = 0x01;

    /// @notice Encodes a batch of commitments into the Wormhole wire format.
    /// @dev Assembly writes the header then iterates commitments, packing each as:
    ///   ┌──────────────────┬───────────────┬──────────────┐
    ///   │ blockHash (32)   │ dataLen (2)   │ data (N)     │
    ///   └──────────────────┴───────────────┴──────────────┘
    /// @param commits The commitments to encode.
    /// @return payload The packed binary payload.
    function encode(ProofsLib.Commitment[] memory commits) internal pure returns (bytes memory payload) {
        if (commits.length > type(uint16).max) revert TooManyCommits();

        // Calculate total size.
        uint256 size = 4;
        for (uint256 i; i < commits.length; ++i) {
            size += 34 + commits[i].data.length;
        }

        payload = new bytes(size);
        uint256 offset;

        assembly {
            let ptr := add(payload, 0x20) // skip length prefix

            // version (1 byte)
            mstore8(ptr, VERSION)
            ptr := add(ptr, 1)

            // action (1 byte)
            mstore8(ptr, ACTION_COMMIT_FROM_L1)
            ptr := add(ptr, 1)

            // num_commits (2 bytes, big-endian)
            let n := mload(commits)
            mstore8(ptr, shr(8, n))
            mstore8(add(ptr, 1), and(n, 0xff))
            ptr := add(ptr, 2)

            offset := ptr
        }

        for (uint256 i; i < commits.length; ++i) {
            bytes32 blockHash = commits[i].blockHash;
            bytes memory data = commits[i].data;

            assembly {
                // block_hash (32 bytes)
                mstore(offset, blockHash)
                offset := add(offset, 0x20)

                // data_len (2 bytes, big-endian)
                let dLen := mload(data)
                mstore8(offset, shr(8, dLen))
                mstore8(add(offset, 1), and(dLen, 0xff))
                offset := add(offset, 2)

                // data (N bytes)
                let src := add(data, 0x20)
                for { let j := 0 } lt(j, dLen) { j := add(j, 0x20) } {
                    mstore(add(offset, j), mload(add(src, j)))
                }
                offset := add(offset, dLen)
            }
        }
    }

    /// @notice Decodes a Wormhole wire payload into a batch of commitments.
    /// @dev Reads the 4-byte header, validates version and action, then iterates to extract
    ///   each commitment's blockHash and variable-length data.
    /// @param payload The packed binary payload.
    /// @return commits The decoded commitments.
    function decode(bytes memory payload) internal pure returns (ProofsLib.Commitment[] memory commits) {
        if (payload.length < 4) revert PayloadTooShort();

        uint8 version;
        uint8 action;
        uint16 numCommits;

        assembly {
            let ptr := add(payload, 0x20)
            version := byte(0, mload(ptr))
            action := byte(0, mload(add(ptr, 1)))
            numCommits := or(shl(8, byte(0, mload(add(ptr, 2)))), byte(0, mload(add(ptr, 3))))
        }

        if (version != VERSION) revert UnsupportedPayloadVersion();
        if (action != ACTION_COMMIT_FROM_L1) revert UnknownPayloadAction();

        commits = new ProofsLib.Commitment[](numCommits);
        uint256 offset = 0x20 + 0x04; // payload memory start (32 length prefix + 4 header)

        for (uint256 i; i < numCommits; ++i) {
            bytes32 blockHash;
            uint16 dataLen;

            assembly {
                blockHash := mload(add(payload, offset))
                offset := add(offset, 0x20)
                dataLen := or(
                    shl(8, byte(0, mload(add(payload, offset)))),
                    byte(0, mload(add(payload, add(offset, 1))))
                )
                offset := add(offset, 2)
            }

            bytes memory data = new bytes(dataLen);
            assembly {
                let src := add(payload, offset)
                let dst := add(data, 0x20)
                for { let j := 0 } lt(j, dataLen) { j := add(j, 0x20) } {
                    mstore(add(dst, j), mload(add(src, j)))
                }
                offset := add(offset, dataLen)
            }

            commits[i] = ProofsLib.Commitment({blockHash: blockHash, data: data});
        }
    }
}
