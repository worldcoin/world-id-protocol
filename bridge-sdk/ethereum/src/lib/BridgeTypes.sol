// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BabyJubJub} from "lib/oprf-key-registry/src/BabyJubJub.sol";

/// @title BridgeTypes
/// @notice Shared struct definitions for the World ID state bridge.
struct ProvenRootInfo {
    uint256 timestamp;
    bytes32 proofId;
}

struct ProvenPubKeyInfo {
    BabyJubJub.Affine pubKey;
    bytes32 proofId;
}
