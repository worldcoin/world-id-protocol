// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title IWormhole
/// @notice Minimal interface for the Wormhole Core Bridge contract.
/// @dev See https://github.com/wormhole-foundation/wormhole/blob/main/ethereum/contracts/interfaces/IWormhole.sol
interface IWormhole {
    struct Signature {
        bytes32 r;
        bytes32 s;
        uint8 v;
        uint8 guardianIndex;
    }

    struct VM {
        uint8 version;
        uint32 timestamp;
        uint32 nonce;
        uint16 emitterChainId;
        bytes32 emitterAddress;
        uint64 sequence;
        uint8 consistencyLevel;
        bytes payload;
        uint32 guardianSetIndex;
        Signature[] signatures;
        bytes32 hash;
    }

    /// @notice Publishes a message to be attested by the Wormhole Guardian network.
    /// @param nonce Application-specific nonce for deduplication.
    /// @param payload Arbitrary bytes payload.
    /// @param consistencyLevel Desired finality level (1 = finalized).
    /// @return sequence The sequence number for this emitter.
    function publishMessage(uint32 nonce, bytes memory payload, uint8 consistencyLevel)
        external
        payable
        returns (uint64 sequence);

    /// @notice Returns the fee required for publishing a message.
    function messageFee() external view returns (uint256);

    /// @notice Parses and verifies a VAA.
    /// @param encodedVM The encoded VAA bytes.
    /// @return vm The parsed VAA struct.
    /// @return valid Whether the VAA signatures are valid.
    /// @return reason Human-readable error reason if invalid.
    function parseAndVerifyVM(bytes calldata encodedVM)
        external
        view
        returns (VM memory vm, bool valid, string memory reason);

    /// @notice Returns the current guardian set index.
    function getCurrentGuardianSetIndex() external view returns (uint32);

    /// @notice Wormhole chain ID for this chain.
    function chainId() external view returns (uint16);
}
