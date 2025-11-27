// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {OprfKeyRegistry} from "nullifier-oracle-service/src/OprfKeyRegistry.sol";
import {Groth16Verifier as Groth16VerifierKeyGen13} from "nullifier-oracle-service/src/Groth16VerifierKeyGen13.sol";
import {BabyJubJub} from "nullifier-oracle-service/src/BabyJubJub.sol";

// This file exists just to force Forge to compile LibToken.sol from some-dependency.
contract __Foundry_Compile_OprfKeyRegistry_Dummy {}