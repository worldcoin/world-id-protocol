// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IDisputeGameFactory} from "interfaces/dispute/IDisputeGameFactory.sol";
import {IDisputeGame} from "interfaces/dispute/IDisputeGame.sol";
import {GameStatus, Claim, GameType} from "@optimism-bedrock/src/dispute/lib/Types.sol";
import {ProofsLib} from "../lib/ProofsLib.sol";
import {Gateway} from "./Gateway.sol";
import {Attributes} from "./Attributes.sol";
import "../Error.sol";

/// @title L1Gateway
/// @author World Contributors
/// @notice Trustless ERC-7786 gateway on L1 that authenticates World Chain state via the
///   OP Stack DisputeGameFactory. Verification pipeline:
///
///   1. Read dispute game from DisputeGameFactory (direct on-chain call)
///   2. Verify output root preimage matches the game's root claim
///   3. Extract WC state root from output root decomposition
///   4. MPT prove WorldIDSource's keccak chain head from WC state root
///   5. Deliver to destination bridge via ERC-7786
///
/// @dev Trust model:
///   - Dispute game finalization: configurable (can require DEFENDER_WINS or accept any status)
///   - WC state: proven via MPT against the output root's state root
///   - Permissionless: anyone with valid proofs can relay
contract L1Gateway is Gateway, Ownable {
    ////////////////////////////////////////////////////////////
    //                       IMMUTABLES                       //
    ////////////////////////////////////////////////////////////

    /// @notice The L1 DisputeGameFactory contract.
    IDisputeGameFactory public immutable DISPUTE_GAME_FACTORY;

    ////////////////////////////////////////////////////////////
    //                         STATE                          //
    ////////////////////////////////////////////////////////////

    /// @notice Whether to require the dispute game to be finalized (DEFENDER_WINS).
    bool public requireFinalized;

    ////////////////////////////////////////////////////////////
    //                      CONSTRUCTOR                       //
    ////////////////////////////////////////////////////////////

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
    ) Gateway(bridge_, wcSource_, wcChainId_) Ownable(owner_) {
        if (disputeGameFactory_ == address(0)) revert ZeroAddress();
        DISPUTE_GAME_FACTORY = IDisputeGameFactory(disputeGameFactory_);
        requireFinalized = requireFinalized_;
    }

    ////////////////////////////////////////////////////////////
    //                     ERC-7786 SOURCE                    //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc Gateway
    function supportsAttribute(bytes4 selector) external view virtual override returns (bool) {
        return selector == Attributes.L1_GATEWAY_ATTRIBUTES;
    }

    /// @dev Verifies dispute game + MPT proofs and extracts the proven WC chain head.
    function _verifyAndExtract(bytes calldata, bytes[] calldata attributes)
        internal
        virtual
        override
        returns (bytes32 chainHead)
    {
        (bytes4 selector, bytes memory data) = Attributes.split(attributes[0]);

        if (selector != Attributes.L1_GATEWAY_ATTRIBUTES) revert MissingAttribute(Attributes.L1_GATEWAY_ATTRIBUTES);

        (
            uint32 gameType,
            bytes memory extraData,
            bytes32[4] memory outputRootPreimage,
            bytes[] memory wcAccountProof,
            bytes[] memory wcStorageProof
        ) = abi.decode(data, (uint32, bytes, bytes32[4], bytes[], bytes[]));

        // 1. Compute output root from preimage
        bytes32 outputRoot = keccak256(
            abi.encodePacked(
                outputRootPreimage[0], // version
                outputRootPreimage[1], // stateRoot
                outputRootPreimage[2], // messagePasserStorageRoot
                outputRootPreimage[3] // latestBlockHash
            )
        );

        // 2. Look up dispute game by UUID (gameType, rootClaim, extraData).
        //    The lookup itself verifies the preimage — rootClaim is part of the UUID key.
        (IDisputeGame game,) = DISPUTE_GAME_FACTORY.games(GameType.wrap(gameType), Claim.wrap(outputRoot), extraData);
        if (address(game) == address(0)) revert InvalidOutputRoot();

        // 3. Optionally check game finalization
        if (requireFinalized && game.status() != GameStatus.DEFENDER_WINS) {
            revert GameNotFinalized();
        }

        bytes32 wcStateRoot = outputRootPreimage[1];

        // 4. MPT prove WorldIDSource's chain head from WC state root
        chainHead =
            ProofsLib.proveStorageSlot(ANCHOR_BRIDGE, _HASH_CHAIN_SLOT, wcAccountProof, wcStorageProof, wcStateRoot);
    }

    ////////////////////////////////////////////////////////////
    //                    ADMIN FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @notice Updates whether dispute game finalization is required.
    function setRequireFinalized(bool required) external virtual onlyOwner {
        requireFinalized = required;
    }
}
