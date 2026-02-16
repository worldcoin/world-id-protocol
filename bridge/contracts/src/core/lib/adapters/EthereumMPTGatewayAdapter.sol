// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IDisputeGameFactory} from "interfaces/dispute/IDisputeGameFactory.sol";
import {IDisputeGame} from "interfaces/dispute/IDisputeGame.sol";
import {GameStatus, Claim, GameType} from "@optimism-bedrock/src/dispute/lib/Types.sol";
import {Lib} from "@lib-core/Lib.sol";
import "@lib-core/StateBridge.sol";
import {WorldIDGateway} from "@lib-core/Gateway.sol";
import "../../Error.sol";

/// @title EthereumMPTGatewayAdapter
/// @author World Contributors
/// @notice Trustless L1 verification adapter that authenticates World Chain state via the
///   OP Stack DisputeGameFactory + MPT proofs.
contract EthereumMPTGatewayAdapter is WorldIDGateway, Ownable {
    using Lib for *;

    /// @notice The L1 DisputeGameFactory contract.
    IDisputeGameFactory public immutable DISPUTE_GAME_FACTORY;

    /// @notice Whether to require the dispute game to be finalized (DEFENDER_WINS).
    bool public requireFinalized;

    /// @param owner_ The owner who can update configuration.
    /// @param disputeGameFactory_ The L1 DisputeGameFactory address.
    /// @param requireFinalized_ Whether to require DEFENDER_WINS status.
    /// @param bridge_ The WorldIDBridge contract on this chain.
    /// @param wcSource_ The WorldIDSource address on World Chain.
    /// @param wcChainId_ The World Chain chain ID (e.g. 480).
    constructor(
        address owner_,
        address disputeGameFactory_,
        bool requireFinalized_,
        address bridge_,
        address wcSource_,
        uint256 wcChainId_
    ) WorldIDGateway(bridge_, wcSource_, wcChainId_) Ownable(owner_) {
        if (disputeGameFactory_ == address(0)) revert ZeroAddress();
        DISPUTE_GAME_FACTORY = IDisputeGameFactory(disputeGameFactory_);
        requireFinalized = requireFinalized_;
    }

    /// @inheritdoc WorldIDGateway
    function supportsAttribute(bytes4 selector) public view virtual override returns (bool) {
        return selector == L1_GATEWAY_ATTRIBUTES;
    }

    /// @dev Verifies dispute game + MPT proofs and extracts the proven WC chain head.
    function _verifyAndExtract(bytes calldata, bytes[] calldata attributes)
        internal
        virtual
        override
        returns (bytes32 chainHead)
    {
        (bytes4 selector, bytes memory data) = split(attributes[0]);

        if (!supportsAttribute(selector)) revert MissingAttribute(L1_GATEWAY_ATTRIBUTES);

        (
            uint32 gameType,
            bytes memory extraData,
            bytes32[4] memory outputRootPreimage,
            bytes[] memory wcAccountProof,
            bytes[] memory wcStorageProof
        ) = abi.decode(data, (uint32, bytes, bytes32[4], bytes[], bytes[]));

        bytes32 outputRoot = keccak256(
            abi.encodePacked(
                outputRootPreimage[0], // version
                outputRootPreimage[1], // stateRoot
                outputRootPreimage[2], // messagePasserStorageRoot
                outputRootPreimage[3] // latestBlockHash
            )
        );

        (IDisputeGame game,) = DISPUTE_GAME_FACTORY.games(GameType.wrap(gameType), Claim.wrap(outputRoot), extraData);
        if (address(game) == address(0)) revert InvalidOutputRoot();

        GameStatus status = game.status();
        if (status == GameStatus.CHALLENGER_WINS) revert InvalidOutputRoot();
        if (requireFinalized && status != GameStatus.DEFENDER_WINS) revert GameNotFinalized();

        bytes32 wcStateRoot = outputRootPreimage[1];

        chainHead =
            Lib.proveStorageSlot(ANCHOR_BRIDGE, STATE_BRIDGE_STORAGE_SLOT, wcAccountProof, wcStorageProof, wcStateRoot);
    }

    ////////////////////////////////////////////////////////////
    //                    ADMIN FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @notice Updates whether dispute game finalization is required.
    function setRequireFinalized(bool required) external virtual onlyOwner {
        requireFinalized = required;
    }
}
