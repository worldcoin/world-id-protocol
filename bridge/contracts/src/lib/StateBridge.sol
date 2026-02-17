// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "../Error.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {BabyJubJub} from "@common/Common.sol";
import {Lib} from "@lib-core/Lib.sol";
import {IStateBridge} from "@core/types/IStateBridge.sol";

/// @dev The ERC-7201 storage slot for StateBridge state.
/// @custom:storage-location erc7201:worldid.storage.WorldIDStateBridge
bytes32 constant STATE_BRIDGE_STORAGE_SLOT = 0x8ea751544b8bbcbc8929c26e76fb7b6c3629dd0f7da849a522d50f1a3c170d00;

/// @title StateBridge
/// @author World Contributors
/// @notice Abstract upgradeable base for all World ID bridge contracts. Manages a keccak hash chain
///   accumulator, proven root/pubkey state, and gateway authorization. Concrete subclasses
///   (`WorldIDSource`, `Satellite`) extend this with their own state ingestion logic.
abstract contract StateBridge is IStateBridge, UUPSUpgradeable, OwnableUpgradeable {
    using Lib for *;

    /// @dev Selector for `updateRoot(uint256,uint256,bytes32)`.
    bytes4 internal constant _UPDATE_ROOT_SELECTOR = bytes4(keccak256("updateRoot(uint256,uint256,bytes32)"));

    /// @dev Selector for `setIssuerPubkey(uint64,uint256,uint256,bytes32)`.
    bytes4 internal constant _SET_ISSUER_PUBKEY_SELECTOR =
        bytes4(keccak256("setIssuerPubkey(uint64,uint256,uint256,bytes32)"));

    /// @dev Selector for `setOprfKey(uint160,uint256,uint256,bytes32)`.
    bytes4 internal constant _SET_OPRF_KEY_SELECTOR = bytes4(keccak256("setOprfKey(uint160,uint256,uint256,bytes32)"));

    /// @dev Initializes `StateBridge` with the given configuration. Only callable once.
    function _initialize(InitConfig memory cfg) internal {
        require(cfg.owner != address(0), "Owner cannot be zero address");
        require(bytes(cfg.name).length > 0, "Name cannot be empty");
        require(bytes(cfg.version).length > 0, "Version cannot be empty");

        StateBridgeStorage storage $ = __storage();

        __Ownable_init(cfg.owner);

        for (uint256 i; i < cfg.authorizedGateways.length; ++i) {
            $.authorizedGateways[cfg.authorizedGateways[i]] = true;
        }
    }

    /// @dev Returns a pointer to the main storage struct.
    function __storage() private pure returns (StateBridgeStorage storage $) {
        assembly {
            $.slot := STATE_BRIDGE_STORAGE_SLOT
        }
    }

    /// @dev Returns whether the given gateway is authorized.
    function _authorized(address gateway) internal view virtual returns (bool) {
        return __storage().authorizedGateways[gateway];
    }

    /// @dev Adds a gateway to the authorized list.
    function _addGateway(address gateway) internal {
        StateBridgeStorage storage $ = __storage();
        $.authorizedGateways[gateway] = true;
        emit GatewayAdded(gateway);
    }

    /// @dev Removes a gateway from the authorized list.
    function _removeGateway(address gateway) internal {
        StateBridgeStorage storage $ = __storage();
        $.authorizedGateways[gateway] = false;
        emit GatewayRemoved(gateway);
    }

    /// @dev Applies commitments, extends keccak chain, and emits `ChainCommitted`.
    function _applyAndCommit(Lib.Commitment[] memory commits) internal virtual {
        Lib.Chain storage chain = __storage().keccakChain;

        _applyCommitments(commits);

        chain.commitChained(commits);

        emit ChainCommitted(chain.head, block.number, block.chainid, abi.encode(commits));
    }

    /// @dev Applies an array of commitments in order.
    function _applyCommitments(Lib.Commitment[] memory commits) internal {
        for (uint256 i; i < commits.length; ++i) {
            _applyCommitment(commits[i]);
        }
    }

    /// @dev Applies a single commitment's state change based on its action selector.
    function _applyCommitment(Lib.Commitment memory commit) private {
        (bytes4 sel, bytes memory payload) = commit.data.splitSelectorAndData();

        if (sel == _UPDATE_ROOT_SELECTOR) {
            (uint256 root, uint256 timestamp, bytes32 proofId) = payload.decodeUpdateRoot();
            _updateRoot(root, timestamp, proofId);
        } else if (sel == _SET_ISSUER_PUBKEY_SELECTOR) {
            (uint64 issuerSchemaId, uint256 x, uint256 y, bytes32 proofId) = payload.decodeSetIssuerPubkey();
            _setIssuerPubkey(issuerSchemaId, x, y, proofId);
        } else if (sel == _SET_OPRF_KEY_SELECTOR) {
            (uint160 oprfKeyId, uint256 x, uint256 y, bytes32 proofId) = payload.decodeSetOprfKey();
            _setOprfKey(oprfKeyId, x, y, proofId);
        } else {
            revert InvalidCommitmentSelector(sel);
        }
    }

    /// @dev Writes a proven root into bridge state.
    function _updateRoot(uint256 root, uint256 timestamp, bytes32 proofId) private {
        StateBridgeStorage storage $ = __storage();
        $.latestRoot = root;
        $.rootToTimestampAndProofId[root] = ProvenRootInfo({timestamp: timestamp, proofId: proofId});
    }

    /// @dev Writes a proven issuer public key into bridge state.
    function _setIssuerPubkey(uint64 issuerSchemaId, uint256 x, uint256 y, bytes32 proofId) private {
        __storage().issuerSchemaIdToPubkeyAndProofId[issuerSchemaId] =
            ProvenPubKeyInfo({pubKey: BabyJubJub.Affine({x: x, y: y}), proofId: proofId});
    }

    /// @dev Writes a proven OPRF key into bridge state.
    function _setOprfKey(uint160 oprfKeyId, uint256 x, uint256 y, bytes32 proofId) private {
        __storage().oprfKeyIdToPubkeyAndProofId[oprfKeyId] =
            ProvenPubKeyInfo({pubKey: BabyJubJub.Affine({x: x, y: y}), proofId: proofId});
    }

    ////////////////////////////////////////////////////////////
    //                      PUBLIC VIEW                       //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IStateBridge
    function VERSION() external view virtual returns (uint8);

    /// @inheritdoc IStateBridge
    function KECCAK_CHAIN() public view returns (Lib.Chain memory) {
        return __storage().keccakChain;
    }

    /// @inheritdoc IStateBridge
    function LATEST_ROOT() public view returns (uint256) {
        return __storage().latestRoot;
    }

    /// @inheritdoc IStateBridge
    function issuerSchemaIdToPubkeyAndProofId(uint64 schemaId) public view returns (ProvenPubKeyInfo memory info) {
        info = __storage().issuerSchemaIdToPubkeyAndProofId[schemaId];
    }

    /// @inheritdoc IStateBridge
    function oprfKeyIdToPubkeyAndProofId(uint160 oprfKeyId) public view returns (ProvenPubKeyInfo memory info) {
        info = __storage().oprfKeyIdToPubkeyAndProofId[oprfKeyId];
    }

    /// @inheritdoc IStateBridge
    function rootToTimestampAndProofId(uint256 root) public view returns (ProvenRootInfo memory info) {
        info = __storage().rootToTimestampAndProofId[root];
    }

    ////////////////////////////////////////////////////////////
    //                         ADMIN                          //
    ////////////////////////////////////////////////////////////

    /// @dev Authorizes a UUPS upgrade. Only callable by the proxy owner.
    function _authorizeUpgrade(address) internal virtual override onlyProxy onlyOwner {}
}
