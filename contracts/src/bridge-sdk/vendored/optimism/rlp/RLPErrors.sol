// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Vendored from optimism/packages/contracts-bedrock/src/libraries/rlp/RLPErrors.sol
/// @notice Only import paths have been modified.

/// @notice The length of an RLP item must be greater than zero to be decodable
error EmptyItem();

/// @notice The decoded item type for list is not a list item
error UnexpectedString();

/// @notice The RLP item has an invalid data remainder
error InvalidDataRemainder();

/// @notice Decoded item type for bytes is not a string item
error UnexpectedList();

/// @notice The length of the content must be greater than the RLP item length
error ContentLengthMismatch();

/// @notice Invalid RLP header for RLP item
error InvalidHeader();
