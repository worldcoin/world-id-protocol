// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IBridgedStateAdapter
/// @author World Contributors
/// @notice The destination-side receiver for bridged World ID state. A thin authenticated
///   passthrough that validates the transport caller and cross-domain source before forwarding
///   state updates to the `ICrossDomainWorldIdVerifier`.
/// @dev Both `MESSENGER` and `SOURCE_BRIDGE_ADAPTER` are immutable, set at construction.
///   All `receive*()` functions MUST authenticate both the transport caller (e.g. the
///   cross-domain messenger) AND the cross-domain source address before forwarding to the
///   verifier. The authentication mechanism is transport-specific (e.g. `xDomainMessageSender()`
///   for OP Stack, `origin` + `sender` for Hyperlane).
interface IBridgedStateAdapter {
    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    /// @dev Thrown when the caller is not the expected cross-domain messenger.
    error UnauthorizedMessenger();

    /// @dev Thrown when the cross-domain source address does not match the expected
    ///   source bridge adapter.
    error UnauthorizedSourceBridge();

    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
    ////////////////////////////////////////////////////////////

    /// @notice Emitted when a Merkle root is received and forwarded to the verifier.
    /// @param root The received Merkle root.
    /// @param worldChainTimestamp The World Chain timestamp when the root was recorded.
    /// @param treeDepth The depth of the Merkle tree.
    /// @param proofId The opaque proof identifier. `bytes32(0)` for relay paths.
    event RootReceived(uint256 indexed root, uint256 worldChainTimestamp, uint256 treeDepth, bytes32 proofId);

    /// @notice Emitted when a credential issuer public key is received and forwarded to the
    ///   verifier.
    /// @param issuerSchemaId The credential schema and issuer pair identifier.
    /// @param x The x-coordinate of the public key.
    /// @param y The y-coordinate of the public key.
    /// @param proofId The opaque proof identifier. `bytes32(0)` for relay paths.
    event IssuerPubkeyReceived(uint64 indexed issuerSchemaId, uint256 x, uint256 y, bytes32 proofId);

    /// @notice Emitted when an OPRF key is received and forwarded to the verifier.
    /// @param oprfKeyId The OPRF key identifier.
    /// @param x The x-coordinate of the OPRF key.
    /// @param y The y-coordinate of the OPRF key.
    /// @param proofId The opaque proof identifier. `bytes32(0)` for relay paths.
    event OprfKeyReceived(uint160 indexed oprfKeyId, uint256 x, uint256 y, bytes32 proofId);

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /// @notice Returns the address of the cross-domain messenger contract that is authorized
    ///   to deliver messages to this adapter.
    /// @dev This is transport-specific: the OP Stack `L2CrossDomainMessenger`, a Hyperlane
    ///   `Mailbox`, a LayerZero `Endpoint`, a Wormhole relayer, etc.
    /// @return The messenger address (immutable).
    function MESSENGER() external view returns (address);

    /// @notice Returns the address of the source-side bridge adapter on the origin chain that
    ///   is authorized to send messages to this adapter.
    /// @dev Used in conjunction with `MESSENGER` to authenticate both the transport layer and
    ///   the cross-domain origin of received messages.
    /// @return The source bridge adapter address (immutable).
    function SOURCE_BRIDGE_ADAPTER() external view returns (address);
}
