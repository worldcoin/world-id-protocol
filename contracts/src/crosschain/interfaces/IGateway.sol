// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC7786GatewaySource} from "@openzeppelin/contracts/interfaces/draft-IERC7786.sol";

/// @title IGateway
/// @author World Contributors
/// @notice Public interface for World ID ERC-7786 source gateways. A gateway verifies proof of
///   World Chain state and delivers proven commitments to the local `StateBridge`. Concrete
///   implementations define the verification logic (owner attestation, dispute game, ZK proof).
interface IGateway is IERC7786GatewaySource {
    /// @notice The local `StateBridge` contract that receives proven state.
    // solhint-disable-next-line func-name-mixedcase
    function STATE_BRIDGE() external view returns (address);

    /// @notice The `StateBridge` address on the anchor chain (World Chain for destination gateways,
    ///   or the L1 bridge for L1 gateways).
    // solhint-disable-next-line func-name-mixedcase
    function ANCHOR_BRIDGE() external view returns (address);

    /// @notice The chain ID of the anchor chain.
    // solhint-disable-next-line func-name-mixedcase
    function ANCHOR_CHAIN_ID() external view returns (uint256);

    /// @notice Returns this gateway's supported authentication strategy.
    // solhint-disable-next-line func-name-mixedcase
    function ATTRIBUTE() external returns (bytes4);
}
