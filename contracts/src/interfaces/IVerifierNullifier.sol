// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title IVerifierNullifier
 * @author Remco Bloemen
 * @notice Interface for Groth16 verifier supporting compressed and uncompressed proofs
 */
interface IVerifierNullifier {
    // ========================================
    // ERRORS
    // ========================================

    /// Some of the provided public input values are larger than the field modulus.
    error PublicInputNotInField();

    /// The proof is invalid.
    error ProofInvalid();

    // ========================================
    // VIEW FUNCTIONS
    // ========================================

    /// Compress a proof.
    /// @notice Will revert with InvalidProof if the curve points are invalid,
    /// but does not verify the proof itself.
    /// @param proof The uncompressed Groth16 proof. Elements are in the same order as for
    /// verifyProof. I.e. Groth16 points (A, B, C) encoded as in EIP-197.
    /// @return compressed The compressed proof. Elements are in the same order as for
    /// verifyCompressedProof. I.e. points (A, B, C) in compressed format.
    function compressProof(uint256[8] calldata proof) external view returns (uint256[4] memory compressed);

    /// Verify a Groth16 proof with compressed points.
    /// @notice Reverts with InvalidProof if the proof is invalid or
    /// with PublicInputNotInField the public input is not reduced.
    /// @notice There is no return value. If the function does not revert, the
    /// proof was successfully verified.
    /// @param compressedProof the points (A, B, C) in compressed format
    /// matching the output of compressProof.
    /// @param input the public input field elements in the scalar field Fr.
    /// Elements must be reduced.
    function verifyCompressedProof(uint256[4] calldata compressedProof, uint256[15] calldata input) external view;

    /// Verify an uncompressed Groth16 proof.
    /// @notice Reverts with InvalidProof if the proof is invalid or
    /// with PublicInputNotInField the public input is not reduced.
    /// @notice There is no return value. If the function does not revert, the
    /// proof was successfully verified.
    /// @param proof the points (A, B, C) in EIP-197 format matching the output
    /// of compressProof.
    /// @param input the public input field elements in the scalar field Fr.
    /// Elements must be reduced.
    function verifyProof(uint256[8] calldata proof, uint256[15] calldata input) external view;
}

