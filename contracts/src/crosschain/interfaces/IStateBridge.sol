/// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BabyJubJub} from "oprf-key-registry/src/BabyJubJub.sol";
import {Lib} from "@world-id-bridge/lib/Lib.sol";

/// @title IStateBridge
/// @author World Contributors
/// @notice Public interface for World ID state bridge contracts (`WorldIDSource` and `WorldIDSatellite`).
interface IStateBridge {
    /// @custom:storage-location erc7201:worldid.storage.WorldIDStateBridge
    /// @dev EIP7201 Style Storage for all Bridged State.
    ///      DO __NOT__ REORDER THIS STRUCT
    struct StateBridgeStorage {
        /// @dev A rolling keccak hash accumulator commiting to the history of state changes.
        Lib.Chain keccakChain;
        /// @dev The latest proven Merkle root.
        uint256 latestRoot;
        /// @dev Authorized gateways that can call `receiveMessage`.
        mapping(address gateway => bool authorized) authorizedGateways;
        /// @dev Maps root (as bytes32) to its proven timestamp and proof ID.
        mapping(uint256 root => ProvenRootInfo info) rootToTimestampAndProofId;
        /// @dev Maps issuer schema ID to its proven public key and proof ID.
        mapping(uint64 schemaId => ProvenPubKeyInfo info) issuerSchemaIdToPubkeyAndProofId;
        /// @dev Maps OPRF key ID to its proven public key and proof ID.
        mapping(uint160 oprfKeyId => ProvenPubKeyInfo info) oprfKeyIdToPubkeyAndProofId;
    }

    /// @notice Metadata stored alongside each proven Merkle root.
    /// @param timestamp The block timestamp at which the root was committed on World Chain.
    /// @param proofId An opaque identifier linking this root to its originating proof or batch.
    struct ProvenRootInfo {
        uint256 timestamp;
        bytes32 proofId;
    }

    /// @notice Metadata stored alongside each proven public key (issuer or OPRF).
    /// @param pubKey The BabyJubJub affine point (x, y) of the proven key.
    /// @param proofId An opaque identifier linking this key to its originating proof or batch.
    struct ProvenPubKeyInfo {
        BabyJubJub.Affine pubKey;
        bytes32 proofId;
    }

    /// @dev Config for initializing the state bridge implementation.
    struct InitConfig {
        string name;
        string version;
        address owner;
        address[] authorizedGateways;
    }

    /// @notice Emitted when a new gateway address is authorized to deliver state.
    /// @param gateway The newly authorized gateway address.
    event GatewayAdded(address indexed gateway);

    /// @notice Emitted when a gateway address is deauthorized.
    /// @param gateway The deauthorized gateway address.
    event GatewayRemoved(address indexed gateway);

    /// @notice Emitted after commitments are applied and the keccak chain is extended.
    /// @param keccakChain The new chain head after appending the commitments.
    /// @param blockNumber The block number at which the commit occurred.
    /// @param chainId The chain ID on which the commit occurred.
    /// @param commitment ABI-encoded `ProofsLib.Commitment[]` that were applied.
    event ChainCommitted(
        bytes32 indexed keccakChain, uint256 indexed blockNumber, uint256 indexed chainId, bytes commitment
    );

    /// @dev The contract Version
    /// @custom:semver v1.0.0
    function VERSION() external view returns (uint8);

    /// @notice Returns the current keccak chain state (head hash and length).
    /// @return The chain struct containing the rolling hash head and the number of commitments applied.
    // solhint-disable-next-line func-name-mixedcase
    function KECCAK_CHAIN() external view returns (Lib.Chain memory);

    /// @notice Returns the latest proven World ID Merkle root.
    /// @return The most recently committed Merkle root value.
    // solhint-disable-next-line func-name-mixedcase
    function LATEST_ROOT() external view returns (uint256);

    /// @notice Looks up the proven public key and proof ID for a credential issuer schema.
    /// @param schemaId The issuer schema ID to query.
    /// @return info The proven BabyJubJub public key and associated proof ID, or zero values if unset.
    function issuerSchemaIdToPubkeyAndProofId(uint64 schemaId) external view returns (ProvenPubKeyInfo memory info);

    /// @notice Looks up the proven OPRF key and proof ID for a given OPRF key ID.
    /// @param oprfKeyId The OPRF key ID to query (derived as `uint160(issuerSchemaId)`).
    /// @return info The proven BabyJubJub public key and associated proof ID, or zero values if unset.
    function oprfKeyIdToPubkeyAndProofId(uint160 oprfKeyId) external view returns (ProvenPubKeyInfo memory info);

    /// @notice Looks up the timestamp and proof ID for a previously proven Merkle root.
    /// @param root The Merkle root to query.
    /// @return info The timestamp and proof ID, or zero values if the root was never proven.
    function rootToTimestampAndProofId(uint256 root) external view returns (ProvenRootInfo memory info);
}
