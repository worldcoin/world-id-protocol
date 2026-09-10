// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ICrossDomainMessenger} from "interfaces/universal/ICrossDomainMessenger.sol";
import {WorldIDGateway} from "@world-id-bridge/lib/Gateway.sol";
import "@world-id-bridge/Error.sol";

/// @title OpStackGatewayAdapter
/// @author World Contributors
/// @notice Native OP Stack L1->L2 verification adapter. Receives the proven L1 `StateBridge`
///   chain head pushed natively from L1 through the OP Stack deposit path
///   (`L1CrossDomainMessenger` -> `OptimismPortal` -> `L2CrossDomainMessenger`).
///
///   Trust derives entirely from the canonical rollup messaging: this adapter only accepts calls
///   relayed by the local `L2CrossDomainMessenger` whose L1 cross-domain sender is the configured
///   `L1_SENDER` (the `EthereumMPTGatewayAdapter`). No proof is verified locally — the L1 sender
///   has already verified World Chain state against the L1 dispute game before forwarding.
///
///   This is a drop-in alternative to the `LightClientGatewayAdapter`: same role (anchor is the
///   L1 `StateBridge`, deployed on the destination L2, delivers to the local `WorldIDSatellite`),
///   but L1 state arrives via native rollup messaging instead of an SP1 light-client proof.
contract OpStackGatewayAdapter is WorldIDGateway {
    /// @inheritdoc WorldIDGateway
    bytes4 public constant override ATTRIBUTE = bytes4(keccak256("chainHead(bytes32)"));

    /// @notice The local `L2CrossDomainMessenger` predeploy
    ///   (`0x4200000000000000000000000000000000000007` on OP Stack chains).
    ICrossDomainMessenger public immutable MESSENGER;

    /// @notice The trusted L1 sender (the `EthereumMPTGatewayAdapter`) authorized to push state.
    address public immutable L1_SENDER;

    /// @param messenger_ The `L2CrossDomainMessenger` predeploy address on this chain.
    /// @param l1Sender_ The trusted L1 gateway (`EthereumMPTGatewayAdapter`) address.
    /// @param bridge_ The `WorldIDSatellite` contract on this chain.
    /// @param l1Bridge_ The L1 `StateBridge` address (anchor / source of truth).
    /// @param l1ChainId_ The L1 chain ID (e.g. 1 for mainnet).
    constructor(address messenger_, address l1Sender_, address bridge_, address l1Bridge_, uint256 l1ChainId_)
        WorldIDGateway(bridge_, l1Bridge_, l1ChainId_)
    {
        if (messenger_ == address(0)) revert ZeroAddress();
        if (l1Sender_ == address(0)) revert ZeroAddress();
        MESSENGER = ICrossDomainMessenger(messenger_);
        L1_SENDER = l1Sender_;
    }

    /// @dev Authenticates the native cross-domain message and extracts the proven chain head.
    ///   Reverts unless the call was relayed by `MESSENGER` and originated from `L1_SENDER` on L1.
    ///   Expects a single attribute: `chainHead(bytes32)`.
    function _verifyAndExtract(bytes calldata, bytes memory proofData)
        internal
        virtual
        override
        returns (bytes32 chainHead)
    {
        if (msg.sender != address(MESSENGER)) revert InvalidCrossDomainSender();
        if (MESSENGER.xDomainMessageSender() != L1_SENDER) revert InvalidCrossDomainSender();

        (chainHead) = abi.decode(proofData, (bytes32));
    }
}
