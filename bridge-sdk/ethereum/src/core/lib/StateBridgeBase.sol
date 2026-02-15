// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {
    ERC7786RecipientUpgradeable
} from "@openzeppelin/contracts-upgradeable/crosschain/ERC7786RecipientUpgradeable.sol";

import {ProvenRootInfo, ProvenPubKeyInfo, UnknownAction, ChainCommitted} from "../interfaces/IWorldIDBridge.sol";
import {BabyJubJub} from "lib/oprf-key-registry/src/BabyJubJub.sol";
import {ProofsLib} from "./ProofsLib.sol";
import {Verifier} from "@world-id/Verifier.sol";

/// @title StateBridgeBase
/// @author World Contributors
/// TODO: Good Description
abstract contract StateBridgeBase is
    ERC7786RecipientUpgradeable,
    UUPSUpgradeable,
    OwnableUpgradeable,
    EIP712Upgradeable
{
    using ProofsLib for *;

    /// @notice Emitted when a gateway is authorized.
    event GatewayAdded(address indexed gateway);

    /// @notice Emitted when a gateway is deauthorized.
    event GatewayRemoved(address indexed gateway);

    /// @dev Thrown when the storage layout has changed after a contract upgrade.
    error StorageLayoutChanged();

    /// @dev keccak256("worldid.storage.WorldIDStateBridgeStorage")
    bytes32 private constant _STATE_BRIDGE_STORAGE_SLOT =
        0x8ea751544b8bbcbc8929c26e76fb7b6c3629dd0f7da849a522d50f1a3c170d00;

    /// @custom:storage-location erc7201:worldid.storage.WorldIDStateBridge
    struct StateBridgeStorage {
        /// @dev A rolling keccak hash accumulator commiting to the history of state changes.
        ///       keccakChain is intentionally immutable as overriding it would mean losing the entire history of changes.
        ProofsLib.Chain keccakChain;
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

    constructor() {
        _disableInitializers();
    }

    /// @dev Configuration for proxy initialization.
    struct InitConfig {
        string name;
        string version;
        address owner;
        address[] authorizedGateways;
    }

    /// @dev Internal initializer called by concrete subclass `initialize()` functions.
    // solhint-disable-next-line func-name-mixedcase
    function __StateBridgeBase_init(InitConfig memory cfg) internal onlyInitializing {
        require(cfg.owner != address(0), "Owner cannot be zero address");
        require(bytes(cfg.name).length > 0, "Name cannot be empty");
        require(bytes(cfg.version).length > 0, "Version cannot be empty");

        StateBridgeStorage storage $ = _worldIDStateBridgeStorage();

        __Ownable_init(cfg.owner);
        __EIP712_init(cfg.name, cfg.version);

        for (uint256 i; i < cfg.authorizedGateways.length; ++i) {
            $.authorizedGateways[cfg.authorizedGateways[i]] = true;
        }
    }

    ///////////////////////////////////////////////////////////
    //                     ERC-7786                          //
    ///////////////////////////////////////////////////////////

    /// @dev Abstract function to apply a gateway commit. The `commitPayload` is ABI-encoded to allow flexibility in the
    function _processGatewayMessage(address gateway, bytes32 receiveId, bytes calldata sender, bytes calldata payload)
        internal
        virtual {}

    /// @inheritdoc ERC7786RecipientUpgradeable
    function _isAuthorizedGateway(address gateway, bytes calldata) internal view virtual override returns (bool) {
        return _worldIDStateBridgeStorage().authorizedGateways[gateway];
    }

    /// @inheritdoc ERC7786RecipientUpgradeable
    function _processMessage(address gateway, bytes32 receiveId, bytes calldata sender, bytes calldata payload)
        internal
        virtual
        override
    {
        _processGatewayMessage(gateway, receiveId, sender, payload);
    }

    /// @notice Authorizes a gateway for receiving cross-chain messages.
    function addGateway(address gateway) external virtual onlyOwner {
        _worldIDStateBridgeStorage().authorizedGateways[gateway] = true;
        emit GatewayAdded(gateway);
    }

    /// @notice Deauthorizes a gateway.
    function removeGateway(address gateway) external virtual onlyOwner {
        _worldIDStateBridgeStorage().authorizedGateways[gateway] = false;
        emit GatewayRemoved(gateway);
    }

    ////////////////////////////////////////////////////////////
    //                     Storage                            //
    ///////////////////////////////////////////////////////////

    /// @dev Returns a pointer to the main storage struct.
    function _worldIDStateBridgeStorage() private pure returns (StateBridgeStorage storage $) {
        assembly {
            $.slot := _STATE_BRIDGE_STORAGE_SLOT
        }
    }

    ////////////////////////////////////////////////////////////////
    //                      State Commitments                     //
    ////////////////////////////////////////////////////////////////

    /// @dev Applies commitments, extends keccak chain, and emits `ChainCommitted`.
    function _applyAndCommit(ProofsLib.Commitment[] memory commits) internal virtual {
        ProofsLib.Chain storage chain = _worldIDStateBridgeStorage().keccakChain;

        _applyCommitments(commits);
        chain.commitChained(commits);

        emit ChainCommitted(chain.head, block.number, abi.encode(commits));
    }

    /// @dev Applies an array of commitments in order.
    function _applyCommitments(ProofsLib.Commitment[] memory commits) internal {
        for (uint256 i; i < commits.length; ++i) {
            _applyCommitment(commits[i]);
        }
    }

    /// @dev Applies a single commitment's state change based on its action selector.
    function _applyCommitment(ProofsLib.Commitment memory commit) private {
        (bytes4 sel, bytes memory payload) = ProofsLib.stripSelector(commit.data);

        if (sel == ProofsLib.UPDATE_ROOT_SELECTOR) {
            (uint256 root, uint256 timestamp, bytes32 proofId) = payload.decodeUpdateRoot();
            _updateRoot(root, timestamp, proofId);
        } else if (sel == ProofsLib.SET_ISSUER_PUBKEY_SELECTOR) {
            (uint64 issuerSchemaId, uint256 x, uint256 y, bytes32 proofId) = payload.decodeSetIssuerPubkey();
            _setIssuerPubkey(issuerSchemaId, x, y, proofId);
        } else if (sel == ProofsLib.SET_OPRF_KEY_SELECTOR) {
            (uint160 oprfKeyId, uint256 x, uint256 y, bytes32 proofId) = payload.decodeSetOprfKey();
            _setOprfKey(oprfKeyId, x, y, proofId);
        } else {
            revert UnknownAction(uint8(uint32(sel)));
        }
    }

    /// @dev Writes a proven root into bridge state.
    function _updateRoot(uint256 root, uint256 timestamp, bytes32 proofId) private {
        StateBridgeStorage storage $ = _worldIDStateBridgeStorage();
        $.latestRoot = root;
        $.rootToTimestampAndProofId[root] = ProvenRootInfo({timestamp: timestamp, proofId: proofId});
    }

    /// @dev Writes a proven issuer public key into bridge state.
    function _setIssuerPubkey(uint64 issuerSchemaId, uint256 x, uint256 y, bytes32 proofId) private {
        _worldIDStateBridgeStorage().issuerSchemaIdToPubkeyAndProofId[issuerSchemaId] =
            ProvenPubKeyInfo({pubKey: BabyJubJub.Affine({x: x, y: y}), proofId: proofId});
    }

    /// @dev Writes a proven OPRF key into bridge state.
    function _setOprfKey(uint160 oprfKeyId, uint256 x, uint256 y, bytes32 proofId) private {
        _worldIDStateBridgeStorage().oprfKeyIdToPubkeyAndProofId[oprfKeyId] =
            ProvenPubKeyInfo({pubKey: BabyJubJub.Affine({x: x, y: y}), proofId: proofId});
    }

    ////////////////////////////////////////////////////////////
    //                    Public View                         //
    ////////////////////////////////////////////////////////////

    /// @notice Returns the keccak chain state.
    // solhint-disable-next-line func-name-mixedcase
    function KECCAK_CHAIN() public view returns (ProofsLib.Chain memory) {
        return _worldIDStateBridgeStorage().keccakChain;
    }

    /// @notice Returns the latest proven Merkle root.
    // solhint-disable-next-line func-name-mixedcase
    function LATEST_ROOT() public view returns (uint256) {
        return _worldIDStateBridgeStorage().latestRoot;
    }

    /// @notice Returns the proven info for a given issuer schema ID.
    function issuerSchemaIdToPubkeyAndProofId(uint64 schemaId) public view returns (ProvenPubKeyInfo memory info) {
        info = _worldIDStateBridgeStorage().issuerSchemaIdToPubkeyAndProofId[schemaId];
    }

    /// @notice Returns the proven info for a given OPRF key ID.
    function oprfKeyIdToPubkeyAndProofId(uint160 oprfKeyId) public view returns (ProvenPubKeyInfo memory info) {
        info = _worldIDStateBridgeStorage().oprfKeyIdToPubkeyAndProofId[oprfKeyId];
    }

    /// @notice Returns the proven root info for a given root.
    function rootToTimestampAndProofId(uint256 root) public view returns (ProvenRootInfo memory info) {
        info = _worldIDStateBridgeStorage().rootToTimestampAndProofId[root];
    }

    ////////////////////////////////////////////////////////////
    //                   UPGRADE AUTHORIZATION                //
    ////////////////////////////////////////////////////////////

    /// @dev Authorizes a UUPS upgrade. Only callable by the proxy owner.
    function _authorizeUpgrade(address) internal virtual override onlyProxy onlyOwner {}
}
