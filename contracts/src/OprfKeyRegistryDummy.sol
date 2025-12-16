// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Verifier as VerifierKeyGen13} from "oprf-service/src/VerifierKeyGen13.sol";
import {BabyJubJub} from "oprf-service/src/BabyJubJub.sol";

// This file exists just to force Forge to compile dependencies of OprfKeyRegistry.sol
contract __Foundry_Compile_OprfKeyRegistry_Dummy {}
