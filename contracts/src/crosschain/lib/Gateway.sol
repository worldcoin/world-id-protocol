// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC7786GatewaySource, IERC7786Recipient} from "@openzeppelin/contracts/interfaces/draft-IERC7786.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import {IGateway} from "@world-id-bridge/interfaces/IGateway.sol";
import {Lib} from "@world-id-bridge/lib/Lib.sol";

import "@world-id-bridge/Error.sol";

/// @title Gateway
/// @author World Contributors
/// @notice Abstract ERC-7786 source gateway for World ID state bridging. Serves as the entrypoint
///   into the `StateBridge` for cross-chain messaging.
abstract contract WorldIDGateway is IGateway {
    using InteroperableAddress for bytes;

    /// @notice The Destination Bridge address.
    address public immutable STATE_BRIDGE;

    /// @notice The Bridge which the Satellite should use as the source of truth.
    address public immutable ANCHOR_BRIDGE;

    /// @notice The Chain ID which the Destination should use to verify provided proofs/attestations.
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

    /// @inheritdoc IGateway
    function ATTRIBUTE() external view virtual override returns (bytes4);

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

        // pre-flight check the attributes.
        bytes memory attributeData = validateAttributes(attributes);

        // extract the proven (or attested) chain head.
        bytes32 chainHead = _verifyAndExtract(payload, attributeData);

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
    function supportsAttribute(bytes4 selector) public view virtual returns (bool) {
        return selector == this.ATTRIBUTE();
    }

    /// @dev Verifies the provided payload and attributes, ensuring they meet the gateway's access control requirements, and extracts the proven chain head.
    /// @param payload The commit payload (ABI-encoded Commitment[]).
    /// @param proof Gateway-specific proof/auth data.
    /// @return chainHead The verified keccak chain head.
    function _verifyAndExtract(bytes calldata payload, bytes memory proof) internal virtual returns (bytes32 chainHead);

    /// @dev Validates that the required attributes are present and correctly formatted for this gateway.
    function validateAttributes(bytes[] calldata attributes) internal view virtual returns (bytes memory) {
        if (attributes.length == 0) revert InvalidAttribute();

        (bytes4 selector, bytes memory data) = Lib.splitSelectorAndData(attributes[0]);

        if (!supportsAttribute(selector)) revert UnsupportedAttribute(selector);

        return data;
    }
}
