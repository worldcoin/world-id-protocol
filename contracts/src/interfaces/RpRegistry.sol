// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {CredentialSchemaIssuerRegistry} from "../CredentialSchemaIssuerRegistry.sol";

library Types {
    struct Groth16Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }
}

interface IRpRegistry {
    function verifyNullifierProof(
        uint256 nullifier,
        uint256 nullifierAction,
        uint128 rpId,
        uint256 accountCommitment,
        uint256 nonce,
        uint256 signalHash,
        uint256 authenticatorMerkleRoot,
        uint256 proofTimestamp,
        CredentialSchemaIssuerRegistry.Pubkey calldata credentialPublicKey,
        Types.Groth16Proof calldata proof
    ) external view returns (bool);
}
