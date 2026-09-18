// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC7786GatewaySource} from "@openzeppelin/contracts/interfaces/draft-IERC7786.sol";
import {IDisputeGameFactory} from "interfaces/dispute/IDisputeGameFactory.sol";
import {IDisputeGame} from "interfaces/dispute/IDisputeGame.sol";
import {ICrossDomainMessenger} from "interfaces/universal/ICrossDomainMessenger.sol";
import {GameStatus, Claim, GameType} from "@optimism-bedrock/src/dispute/lib/Types.sol";
import {Lib} from "@world-id-bridge/lib/Lib.sol";
import "@world-id-bridge/lib/StateBridge.sol";
import {WorldIDGateway} from "@world-id-bridge/lib/Gateway.sol";
import "@world-id-bridge/Error.sol";

/// @notice Emitted when verified World Chain state is forwarded to a native OP Stack L2 gateway
///   through the `L1CrossDomainMessenger`.
event ForwardedToL2(address indexed messenger, address indexed l2Adapter, bytes32 chainHead);

/// @title EthereumMPTGatewayAdapter
/// @author World Contributors
/// @notice Trustless L1 verification adapter that authenticates World Chain state via the
///   OP Stack DisputeGameFactory + MPT proofs.
contract EthereumMPTGatewayAdapter is WorldIDGateway, Ownable {
    using Lib for *;

    /// @inheritdoc WorldIDGateway
    bytes4 public constant override ATTRIBUTE =
        bytes4(keccak256("l1ProofAttributes(uint32,bytes,bytes32[4],bytes[],bytes[])"));

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

    /// @dev Verifies dispute game + MPT proofs and extracts the proven WC chain head.
    function _verifyAndExtract(bytes calldata, bytes memory proof)
        internal
        virtual
        override
        returns (bytes32 chainHead)
    {
        (
            uint32 gameType,
            bytes memory extraData,
            bytes32[4] memory outputRootPreimage,
            bytes[] memory wcAccountProof,
            bytes[] memory wcStorageProof
        ) = abi.decode(proof, (uint32, bytes, bytes32[4], bytes[], bytes[]));

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

    /// @notice Verifies World Chain state (dispute game + MPT), then forwards the proven chain
    ///   head to a native OP Stack L2 gateway through the `L1CrossDomainMessenger`.
    /// @dev This adapter is the L1 cross-domain sender that the destination `OpStackGatewayAdapter`
    ///   trusts: the L2 message is delivered with this contract as `xDomainMessageSender`. The
    ///   proof is re-verified here so only authentic chain heads can ever be forwarded, making the
    ///   call permissionless like `sendMessage`. The same `payload` (commitment delta) is delivered
    ///   to L2; the destination satellite checks it hashes to `chainHead`.
    /// @param messenger The `L1CrossDomainMessenger` for the destination rollup.
    /// @param l2Adapter The `OpStackGatewayAdapter` address on the destination L2.
    /// @param recipient ERC-7930 interoperable address of the destination `WorldIDSatellite`.
    /// @param payload ABI-encoded `Lib.Commitment[]` delta to apply on L2.
    /// @param attributes Gateway attributes carrying the MPT proof (`l1ProofAttributes`).
    /// @param minGasLimit Minimum L2 gas for the relayed `sendMessage` call.
    function forwardToL2(
        address messenger,
        address l2Adapter,
        bytes calldata recipient,
        bytes calldata payload,
        bytes[] calldata attributes,
        uint32 minGasLimit
    ) external virtual {
        if (messenger == address(0) || l2Adapter == address(0)) revert ZeroAddress();
        if (payload.length == 0) revert EmptyPayload();

        bytes memory attributeData = validateAttributes(attributes);
        bytes32 chainHead = _verifyAndExtract(payload, attributeData);

        bytes[] memory l2Attributes = new bytes[](1);
        l2Attributes[0] = abi.encodePacked(bytes4(keccak256("chainHead(bytes32)")), abi.encode(chainHead));

        bytes memory message = abi.encodeCall(IERC7786GatewaySource.sendMessage, (recipient, payload, l2Attributes));

        ICrossDomainMessenger(messenger).sendMessage(l2Adapter, message, minGasLimit);

        emit ForwardedToL2(messenger, l2Adapter, chainHead);
    }

    ////////////////////////////////////////////////////////////
    //                    ADMIN FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @notice Updates whether dispute game finalization is required.
    function setRequireFinalized(bool required) external virtual onlyOwner {
        requireFinalized = required;
    }
}
