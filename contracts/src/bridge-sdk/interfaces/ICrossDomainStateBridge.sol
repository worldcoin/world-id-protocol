// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IBridgeAdapter} from "./IBridgeAdapter.sol";
import {ICrossDomainRegistryState} from "./ICrossDomainRegistryState.sol";

/// @title ICrossDomainStateBridge
/// @author World Contributors
/// @notice The singleton dispatch contract on a source chain. Reads state from its
///   `ICrossDomainRegistryState` implementation and batches dispatch to registered adapters.
/// @dev A relayer selects which adapter indices to service per transaction. Each adapter targets
///   a single destination chain via a specific transport (e.g. Hyperlane, LayerZero, canonical
///   L1->L2 bridge). Any chain with a `ICrossDomainRegistryState` can host a state bridge,
///   enabling recursive composition — a digest becomes a source.
interface ICrossDomainStateBridge is ICrossDomainRegistryState {
    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
    ////////////////////////////////////////////////////////////

    /// @notice Emitted when a new bridge adapter is registered.
    /// @param index The index assigned to the adapter in the adapters array.
    /// @param adapter The address of the registered bridge adapter.
    event AdapterRegistered(uint256 indexed index, address adapter);

    /// @notice Emitted when a bridge adapter is removed.
    /// @param index The index of the removed adapter.
    /// @param adapter The address of the removed adapter.
    event AdapterRemoved(uint256 indexed index, address adapter);

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /// @notice Returns the bridge adapter at the given index.
    /// @param index The zero-based index into the adapters array.
    /// @return The `IBridgeAdapter` at the specified index.
    function adapters(uint256 index) external view returns (IBridgeAdapter);

    /// @notice Returns the total number of registered bridge adapters.
    /// @return The count of adapters currently registered.
    function adapterCount() external view returns (uint256);

    ////////////////////////////////////////////////////////////
    //                  DISPATCH FUNCTIONS                    //
    ////////////////////////////////////////////////////////////

    /// @notice Propagates the latest Merkle root to the specified destination adapters.
    /// @dev Reads the latest root, its timestamp, and tree depth from the registry state, then
    ///   dispatches an encoded `receiveRoot` call to each adapter at the given indices.
    /// @param adapterIndices The indices of the adapters to dispatch to. Allows relayers to
    ///   selectively service a subset of destinations per transaction.
    function propagateRoot(uint256[] calldata adapterIndices) external payable;

    /// @notice Propagates a credential issuer public key to the specified destination adapters.
    /// @dev Reads the issuer pubkey for `issuerSchemaId` from the registry state, then dispatches
    ///   an encoded `receiveIssuerPubkey` call to each adapter at the given indices.
    /// @param adapterIndices The indices of the adapters to dispatch to.
    /// @param issuerSchemaId The unique identifier for the credential schema and issuer pair
    ///   whose public key should be propagated.
    function propagateIssuerPubkey(uint256[] calldata adapterIndices, uint64 issuerSchemaId) external payable;

    /// @notice Propagates an OPRF public key to the specified destination adapters.
    /// @dev Reads the OPRF key for `oprfKeyId` from the registry state, then dispatches an
    ///   encoded `receiveOprfKey` call to each adapter at the given indices.
    /// @param adapterIndices The indices of the adapters to dispatch to.
    /// @param oprfKeyId The unique identifier for the OPRF key to propagate.
    function propagateOprfKey(uint256[] calldata adapterIndices, uint160 oprfKeyId) external payable;

    ////////////////////////////////////////////////////////////
    //                    OWNER FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @notice Registers a new bridge adapter for dispatching state to a destination chain.
    /// @dev The adapter is appended to the end of the adapters array. Only callable by the owner.
    /// @param adapter The bridge adapter to register.
    function registerAdapter(IBridgeAdapter adapter) external;

    /// @notice Removes a bridge adapter at the given index using swap-and-pop.
    /// @dev The adapter at `index` is replaced with the last adapter in the array, then the
    ///   array is shortened by one. This means adapter indices may change after removal.
    ///   Only callable by the owner.
    /// @param index The index of the adapter to remove.
    function removeAdapter(uint256 index) external;
}
