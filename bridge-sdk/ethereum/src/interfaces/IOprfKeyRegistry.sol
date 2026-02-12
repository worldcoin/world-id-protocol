// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {OprfKeyGen} from "lib/oprf-key-registry/src/OprfKeyGen.sol";

/// @title IOprfKeyRegistry
/// @notice Interface for the OPRF key registry on World Chain.
interface IOprfKeyRegistry {
    function getOprfPublicKeyAndEpoch(uint160) external view returns (OprfKeyGen.RegisteredOprfPublicKey memory);
}
