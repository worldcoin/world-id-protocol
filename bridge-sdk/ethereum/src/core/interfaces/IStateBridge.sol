/// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BabyJubJub} from "lib/oprf-key-registry/src/BabyJubJub.sol";
import {ProofsLib} from "../lib/ProofsLib.sol";

/// @title IStateBridge
/// @author World Contributors
/// @notice Public interface for World ID state bridge contracts (`WorldIDSource` and `CrossDomainWorldID`).
///
///   A state bridge maintains a rolling keccak hash chain that commits to the history of World ID
///   state changes (Merkle roots, issuer public keys, OPRF keys). Authorized ERC-7786 gateways
///   deliver proven commitments that advance the chain and update the bridge's view of World ID state.
///
///   Concrete implementations:
///   - `WorldIDSource` — deployed on World Chain; reads state directly from on-chain registries.
///   - `CrossDomainWorldID` — deployed on destination chains; accepts proven state from gateways.
interface IStateBridge {
    ////////////////////////////////////////////////////////////
    //                         STRUCTS                        //
    ////////////////////////////////////////////////////////////

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

    ////////////////////////////////////////////////////////////
    //                         EVENTS                         //
    ////////////////////////////////////////////////////////////

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

    ////////////////////////////////////////////////////////////
    //                       PUBLIC VIEW                      //
    ////////////////////////////////////////////////////////////

    /// @notice Returns the current keccak chain state (head hash and length).
    /// @return The chain struct containing the rolling hash head and the number of commitments applied.
    // solhint-disable-next-line func-name-mixedcase
    function KECCAK_CHAIN() external view returns (ProofsLib.Chain memory);

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
