// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Vendored from optimism/packages/contracts-bedrock/src/libraries/Hashing.sol
/// @notice Trimmed to only include hashOutputRootProof. Import paths removed (no external deps).

/// @title Hashing
/// @notice Minimal vendored subset of Optimism's Hashing library. Only includes output root
///         proof hashing needed for state bridge verification.
library Hashing {
    /// @notice Hashes the various elements of an output root proof into an output root hash which
    ///         can be used to check if the proof is valid.
    /// @param _version Output root version.
    /// @param _stateRoot L2 state root.
    /// @param _messagePasserStorageRoot Message passer storage root.
    /// @param _latestBlockhash Latest L2 block hash.
    /// @return Hashed output root proof.
    function hashOutputRootProof(
        bytes32 _version,
        bytes32 _stateRoot,
        bytes32 _messagePasserStorageRoot,
        bytes32 _latestBlockhash
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(_version, _stateRoot, _messagePasserStorageRoot, _latestBlockhash));
    }
}
