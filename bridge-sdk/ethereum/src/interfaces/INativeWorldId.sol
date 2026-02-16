// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ProofsLib} from "../lib/ProofsLib.sol";

/// @title INativeReceiver
/// @author World Contributors
/// @notice Interface for L2 contracts that receive World ID state via native L1→L2 messaging.
interface INativeWorldId {
    /// @notice Receives and applies a batch of commitments from the L1 state bridge
    ///   via the chain's native cross-domain messenger.
    /// @param commits The batch of commitments to apply.
    function commitFromL1(ProofsLib.Commitment[] calldata commits) external;
}
