// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ITransport} from "../../../interfaces/ITransport.sol";
import {IMailbox} from "../../../vendor/zksync/IMailbox.sol";

/// @title ZkSyncAdapter
/// @author World Contributors
/// @notice Concrete `ITransport` for ZkSync Era. Wraps the ZkSync Mailbox to request
///   L2 transactions that deliver encoded `commitFromL1` calls to the L2 receiver.
/// @dev Permissionless — auth is enforced on the L2 side via address aliasing.
contract ZkSyncAdapter is ITransport {
    /// @notice The ZkSync Era Mailbox contract on L1.
    IMailbox public immutable MAILBOX;

    /// @notice The target contract on ZkSync L2 (ZkSyncReceiver).
    address public immutable TARGET;

    /// @notice Gas limit for the L2 execution.
    uint256 public immutable GAS_LIMIT;

    /// @notice Gas cost per pubdata byte on L2.
    uint256 public immutable GAS_PER_PUBDATA;

    constructor(IMailbox mailbox, address target, uint256 gasLimit, uint256 gasPerPubdata) {
        MAILBOX = mailbox;
        TARGET = target;
        GAS_LIMIT = gasLimit;
        GAS_PER_PUBDATA = gasPerPubdata;
    }

    /// @inheritdoc ITransport
    function sendMessage(bytes calldata message) external payable virtual {
        MAILBOX.requestL2Transaction{value: msg.value}(
            TARGET,
            0, // l2Value
            message,
            GAS_LIMIT,
            GAS_PER_PUBDATA,
            new bytes[](0), // no factory deps
            msg.sender // refundRecipient
        );
    }
}
