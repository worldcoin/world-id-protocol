// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IMailbox
/// @notice Minimal interface for the ZkSync Era Mailbox contract on L1.
///   Used to request L2 transactions from L1.
interface IMailbox {
    /// @notice Requests execution of an L2 transaction from L1.
    /// @param _contractL2 The L2 contract address to call.
    /// @param _l2Value The msg.value for the L2 transaction (in wei).
    /// @param _calldata The calldata for the L2 transaction.
    /// @param _l2GasLimit The gas limit for the L2 transaction.
    /// @param _l2GasPerPubdataByteLimit The gas cost per pubdata byte on L2.
    /// @param _factoryDeps Factory dependencies (bytecodes) needed on L2.
    /// @param _refundRecipient The L2 address to receive refunds.
    /// @return The canonical transaction hash.
    function requestL2Transaction(
        address _contractL2,
        uint256 _l2Value,
        bytes calldata _calldata,
        uint256 _l2GasLimit,
        uint256 _l2GasPerPubdataByteLimit,
        bytes[] calldata _factoryDeps,
        address _refundRecipient
    ) external payable returns (bytes32);
}
