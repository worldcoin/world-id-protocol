// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC7786GatewaySource, IERC7786Recipient} from "@openzeppelin/contracts/interfaces/draft-IERC7786.sol";
import {InteroperableAddress} from "openzeppelin-contracts/contracts/utils/draft-InteroperableAddress.sol";
import {IGateway} from "../interfaces/IGateway.sol";
import "../Error.sol";

/// @title Gateway
/// @author World Contributors
/// @notice Abstract ERC-7786 source gateway for World ID state bridging. Serves as the entrypoint
///   into the `StateBridge` for cross-chain messages. Subclasses define the verification logic
///   (owner attestation, dispute game, ZK proof), allowing the trust model to be swapped by
///   changing the gateway.
abstract contract Gateway is IGateway {
    using InteroperableAddress for bytes;

    /// @dev Storage slot in the ANCHOR_BRIDGE for which MPT storage proofs are generated.
    bytes32 public constant _HASH_CHAIN_SLOT = 0x8ea751544b8bbcbc8929c26e76fb7b6c3629dd0f7da849a522d50f1a3c170d00;

    /// @notice The WorldIDBridge (destination) contract on this chain.
    address public immutable STATE_BRIDGE;

    /// @notice The WorldIDSource address on World Chain.
    address public immutable ANCHOR_BRIDGE;

    /// @notice The World Chain chain ID.
    uint256 public immutable ANCHOR_CHAIN_ID;

    /// @dev Counter for generating unique receiveIds for ERC-7786 delivery.
    uint256 internal _messageNonce;

    constructor(address bridge_, address anchorBridge_, uint256 anchorChainId_) {
        if (bridge_ == address(0)) revert ZeroAddress();
        if (anchorBridge_ == address(0)) revert ZeroAddress();

        STATE_BRIDGE = bridge_;
        ANCHOR_BRIDGE = anchorBridge_;
        ANCHOR_CHAIN_ID = anchorChainId_;
    }

    /// @inheritdoc IERC7786GatewaySource
    function sendMessage(bytes calldata recipient, bytes calldata payload, bytes[] calldata attributes)
        external
        payable
        virtual
        returns (bytes32 sendId)
    {
        // Validate recipient is the configured bridge
        (bool ok,, address target) = recipient.tryParseEvmV1Calldata();
        if (!ok || target != STATE_BRIDGE) revert InvalidRecipient();
        if (payload.length == 0) revert EmptyPayload();

        // Subclass verifies proofs and extracts the proven chain head
        bytes32 chainHead = _verifyAndExtract(payload, attributes);

        // Deliver to bridge via ERC-7786 receiveMessage
        _deliver(chainHead, payload);

        // Emit standard ERC-7786 event (sendId=0 means delivery is immediate)
        emit MessageSent(
            bytes32(0),
            InteroperableAddress.formatEvmV1(ANCHOR_CHAIN_ID, ANCHOR_BRIDGE),
            recipient,
            payload,
            msg.value,
            attributes
        );

        return bytes32(0);
    }

    /// @inheritdoc IERC7786GatewaySource
    function supportsAttribute(bytes4) external view virtual returns (bool);

    /// @dev Verifies the provided payload and attributes, ensuring they meet the gateway's access control requirements, and extracts the proven chain head.
    /// @param payload The commit payload (ABI-encoded Commitment[]).
    /// @param attributes Gateway-specific proof/auth data.
    /// @return chainHead The verified keccak chain head.
    function _verifyAndExtract(bytes calldata payload, bytes[] calldata attributes)
        internal
        virtual
        returns (bytes32 chainHead);

    ////////////////////////////////////////////////////////////
    //                       DELIVERY                         //
    ////////////////////////////////////////////////////////////

    /// @dev Delivers a proven chain head + commit payload to the destination bridge via ERC-7786.
    /// @param chainHead The proven keccak chain head from WorldIDSource.
    /// @param commitPayload ABI-encoded `ProofsLib.Commitment[]` to apply.
    function _deliver(bytes32 chainHead, bytes calldata commitPayload) internal virtual {
        bytes memory sender = InteroperableAddress.formatEvmV1(ANCHOR_CHAIN_ID, ANCHOR_BRIDGE);
        bytes memory payload = abi.encode(chainHead, commitPayload);
        bytes32 receiveId = bytes32(++_messageNonce);

        bytes4 ret = IERC7786Recipient(STATE_BRIDGE).receiveMessage(receiveId, sender, payload);
        if (ret != IERC7786Recipient.receiveMessage.selector) revert InvalidRecipientResponse();

        emit StateDelivered(receiveId, chainHead);
    }
}
