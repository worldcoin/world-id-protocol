// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC7786GatewaySource, IERC7786Recipient} from "@openzeppelin/contracts/interfaces/draft-IERC7786.sol";
import {InteroperableAddress} from "openzeppelin-contracts/contracts/utils/draft-InteroperableAddress.sol";
import {IGateway} from "../interfaces/IGateway.sol";
import "../Error.sol";

/// @title Gateway
/// @author World Contributors
/// @notice Abstract ERC-7786 source gateway for World ID state bridging. Serves as the entrypoint
///   into the `StateBridge` for cross-chain messaging.
abstract contract WorldIDGateway is IGateway {
    using InteroperableAddress for bytes;

    /// @dev 4-byte selector for `chainHead(bytes32)` attribute, which carries the proven World Chain head for the message.
    bytes4 internal constant OWNED_GATEWAY_ATTRIBUTES = bytes4(keccak256("chainHead(bytes32)"));

    /// @dev 4-byte selector for `l1ProofAttributes(uint32,bytes,bytes32[4],bytes[],bytes[])`
    bytes4 internal constant L1_GATEWAY_ATTRIBUTES =
        bytes4(keccak256("l1ProofAttributes(uint32,bytes,bytes32[4],bytes[],bytes[])"));

    /// @dev 4-byte selector for ZKGateway SP1 Helios + MPT proof attributes.
    bytes4 internal constant ZK_GATEWAY_ATTRIBUTES = bytes4(
        keccak256("zkProofGatewayAttributes(bytes,uint256,bytes32,bytes32,uint256,bytes32,bytes32,bytes[],bytes[])")
    );

    /// @notice The WorldIDBridge (destination) contract on this chain.
    address public immutable STATE_BRIDGE;

    /// @notice The Source Bridge address.
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
        // validate recipient is the configured bridge
        (bool ok,, address target) = recipient.tryParseEvmV1Calldata();
        if (!ok || target != STATE_BRIDGE) revert InvalidRecipient();
        if (payload.length == 0) revert EmptyPayload();

        // extract the proven (or attested) chain head.
        bytes32 chainHead = _verifyAndExtract(payload, attributes);

        bytes memory sender = InteroperableAddress.formatEvmV1(ANCHOR_CHAIN_ID, ANCHOR_BRIDGE);
        bytes memory encoded = abi.encode(chainHead, payload);

        bytes32 receiveId = bytes32(++_messageNonce);

        require(
            IERC7786Recipient(STATE_BRIDGE).receiveMessage(receiveId, sender, encoded)
                == IERC7786Recipient.receiveMessage.selector,
            InvalidRecipientResponse()
        );

        sendId = bytes32(_messageNonce);

        emit MessageSent(
            sendId, InteroperableAddress.formatEvmV1(ANCHOR_CHAIN_ID, ANCHOR_BRIDGE), recipient, payload, 0, attributes
        );
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

    /// @dev Splits a calldata attribute into its selector and data components.
    function split(bytes calldata attribute) internal pure returns (bytes4 selector, bytes memory data) {
        require(attribute.length >= 4, "Attribute too short");
        selector = bytes4(attribute[:4]);
        data = attribute[4:];
    }
}
