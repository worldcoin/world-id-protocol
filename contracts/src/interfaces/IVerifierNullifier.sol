// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title IVerifierNullifier
/// @author Worldcoin
/// @notice Interface for the Groth16 nullifier proof verifier contract.
/// @dev Supports verifying Groth16 proofs in both uncompressed (256 bytes) and compressed (128 bytes) format.
interface IVerifierNullifier {
    ////////////////////////////////////////////////////////////
    //                         ERRORS                         //
    ////////////////////////////////////////////////////////////

    /// @notice Thrown when a public input value is larger than the field modulus.
    /// @dev Public input elements are not automatically reduced, as this can be a dangerous source of bugs.
    error PublicInputNotInField();

    /// @notice Thrown when the proof is invalid.
    /// @dev This can mean that provided Groth16 proof points are not on their curves,
    /// that the pairing equation fails, or that the proof is not for the provided public input.
    error ProofInvalid();

    ////////////////////////////////////////////////////////////
    //                    PUBLIC FUNCTIONS                    //
    ////////////////////////////////////////////////////////////

    /// @notice Compress a Groth16 proof.
    /// @dev Will revert with ProofInvalid if the curve points are invalid,
    /// but does not verify the proof itself.
    /// @param proof The uncompressed Groth16 proof. Elements are in the same order as for
    /// verifyProof. I.e. Groth16 points (A, B, C) encoded as in EIP-197.
    /// @return compressed The compressed proof. Elements are in the same order as for
    /// verifyCompressedProof. I.e. points (A, B, C) in compressed format.
    function compressProof(uint256[8] calldata proof) external view returns (uint256[4] memory compressed);

    /// @notice Verify a Groth16 proof with compressed points.
    /// @dev Reverts with ProofInvalid if the proof is invalid or
    /// with PublicInputNotInField if the public input is not reduced.
    /// There is no return value. If the function does not revert, the proof was successfully verified.
    /// @param compressedProof The points (A, B, C) in compressed format matching the output of compressProof.
    /// @param input The public input field elements in the scalar field Fr. Elements must be reduced.
    function verifyCompressedProof(uint256[4] calldata compressedProof, uint256[15] calldata input) external view;

    /// @notice Verify an uncompressed Groth16 proof.
    /// @dev Reverts with ProofInvalid if the proof is invalid or
    /// with PublicInputNotInField if the public input is not reduced.
    /// There is no return value. If the function does not revert, the proof was successfully verified.
    /// @param proof The points (A, B, C) in EIP-197 format matching the output of compressProof.
    /// @param input The public input field elements in the scalar field Fr. Elements must be reduced.
    function verifyProof(uint256[8] calldata proof, uint256[15] calldata input) external view;
}

