// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ITransport} from "../../../interfaces/ITransport.sol";
import {IWormhole} from "../../../vendor/wormhole/IWormhole.sol";
import {WormholePayloadLib} from "../../../lib/WormholePayloadLib.sol";
import {ProofsLib} from "../../../lib/ProofsLib.sol";

/// @notice Emitted when commitments are published via Wormhole.
event WormholeMessagePublished(uint64 indexed sequence, uint32 nonce, uint256 numCommits);

/// @title WormholeAdapter
/// @author World Contributors
/// @notice Concrete `ITransport` for Wormhole-connected chains (e.g. Solana).
///
/// @dev Uses Wormhole Core Bridge (`publishMessage`) rather than the Standard Relayer,
///   since the Standard Relayer only supports EVM-to-EVM delivery.
///
///   Message flow:
///   1. L1Relay calls `sendMessage(abi.encodeCall(INativeReceiver.commitFromL1, (commits)))`
///   2. This adapter decodes the commitments from the ABI-encoded calldata
///   3. Re-encodes them using the compact `WormholePayloadLib` wire format
///   4. Publishes the payload via `IWormhole.publishMessage`
///   5. Wormhole Guardians observe the message and produce a signed VAA
///   6. The off-chain relay fetches the VAA and submits it to the destination program
///
///   The destination (e.g. Solana bridge program) verifies the VAA signatures, checks the
///   emitter chain/address, and decodes the `WormholePayloadLib` to extract commitments.
contract WormholeAdapter is ITransport {
    /// @notice The Wormhole Core Bridge contract.
    IWormhole public immutable WORMHOLE;

    /// @notice Wormhole consistency level (1 = finalized).
    uint8 public immutable CONSISTENCY_LEVEL;

    /// @notice Monotonically increasing nonce for Wormhole messages.
    uint32 public nonce;

    constructor(IWormhole wormhole, uint8 consistencyLevel) {
        WORMHOLE = wormhole;
        CONSISTENCY_LEVEL = consistencyLevel;
    }

    /// @inheritdoc ITransport
    /// @dev Expects `message` to be `abi.encodeCall(INativeReceiver.commitFromL1, (commits))`.
    ///   Decodes the commitments, re-encodes them using the compact Wormhole wire format,
    ///   and publishes via Wormhole Core. Any excess `msg.value` beyond the message fee
    ///   is left in this contract (caller should send exact fee).
    function sendMessage(bytes calldata message) external payable virtual {
        // Decode commitments from the ABI-encoded INativeReceiver.commitFromL1 calldata.
        // Layout: 4-byte selector + abi.encode(Commitment[])
        ProofsLib.Commitment[] memory commits = abi.decode(message[4:], (ProofsLib.Commitment[]));

        // Encode into the compact Wormhole payload format.
        bytes memory payload = WormholePayloadLib.encode(commits);

        // Publish via Wormhole Core Bridge.
        uint32 currentNonce = nonce++;
        uint64 sequence = WORMHOLE.publishMessage{value: msg.value}(currentNonce, payload, CONSISTENCY_LEVEL);

        emit WormholeMessagePublished(sequence, currentNonce, commits.length);
    }
}
