// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {StateBridgeBase} from "../lib/StateBridgeBase.sol";
import {EmptyChainedCommits} from "../interfaces/IWorldIDBridge.sol";
import {ProofsLib, InvalidChainHead} from "../lib/ProofsLib.sol";

/// @dev Thrown when the caller is not an authorized gateway.
error UnauthorizedGateway();

/// @notice Emitted when a new chain head is committed by a gateway.
event ChainCommitted(bytes32 indexed head, uint256 indexed blockNumber, bytes32 indexed receiveId, address sender);

/// @title WorldIDBridge
/// @author World Contributors
/// @notice Destination bridge for receiving World ID state on any chain via authorized gateways.
///   Gateways (e.g. SequencerGateway) prove a chain head from the source chain and submit
///   commitments. This contract verifies chain integrity and applies the state changes.
///
/// @dev Deployed behind an ERC1967 proxy.
contract WorldIDBridge is StateBridgeBase {
    /// @dev The deployment version of the bridge. Used for reinitialization checks.
    uint64 public constant VERSION = 1;

    ////////////////////////////////////////////////////////////
    //                      INITIALIZER                       //
    ////////////////////////////////////////////////////////////

    /// @notice Initializes the bridged World ID proxy.
    // solhint-disable-next-line func-name-mixedcase
    function __WorldIdBridge_init(
        string memory name_,
        string memory version_,
        address owner_,
        address[] memory initialGateways_
    ) internal virtual reinitializer(VERSION) {
        __StateBridgeBase_init(
            InitConfig({name: name_, version: version_, owner: owner_, authorizedGateways: initialGateways_})
        );
    }

    ////////////////////////////////////////////////////////////
    //              GATEWAY COMMIT (SEQUENCER PATH)           //
    ////////////////////////////////////////////////////////////

    /// @dev Receives verified commitments from an authorized gateway.
    function _processGatewayMessage(address gateway, bytes32 receiveId, bytes calldata, bytes calldata payload)
        internal
        virtual
        override
    {
        (bytes32 provenChainHead, bytes memory commitPayload) = abi.decode(payload, (bytes32, bytes));

        ProofsLib.Commitment[] memory commits = abi.decode(commitPayload, (ProofsLib.Commitment[]));
        if (commits.length == 0) revert EmptyChainedCommits();

        // Verify the commitments hash to the proven chain head
        ProofsLib.Chain memory chain = KECCAK_CHAIN();

        bytes32 expectedHead = ProofsLib.hashChained(chain, commits);
        if (expectedHead != provenChainHead) revert InvalidChainHead();

        _applyAndCommit(commits);

        emit ChainCommitted(chain.head, block.number, receiveId, gateway);
    }
}
