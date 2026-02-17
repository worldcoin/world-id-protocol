// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {EthereumMPTGatewayAdapter} from "../../../src/crosschain/adapters/EthereumMPTGatewayAdapter.sol";
import {IDisputeGameFactory} from "interfaces/dispute/IDisputeGameFactory.sol";
import {IDisputeGame} from "interfaces/dispute/IDisputeGame.sol";
import {GameStatus, Claim, GameType, Timestamp} from "@optimism-bedrock/src/dispute/lib/Types.sol";
import {Lib} from "../../../src/crosschain/lib/Lib.sol";
// ─── Mock Registries ────────────────────────────────────────────────────────

contract MockRegistry {
    uint256 public latestRoot = 42;

    function getLatestRoot() external view returns (uint256) {
        return latestRoot;
    }

    function setLatestRoot(uint256 root) external {
        latestRoot = root;
    }
}

contract MockIssuerRegistry {
    struct Pubkey {
        uint256 x;
        uint256 y;
    }

    mapping(uint64 => Pubkey) internal _keys;

    function issuerSchemaIdToPubkey(uint64 id) external view returns (Pubkey memory) {
        return _keys[id];
    }

    function setPubkey(uint64 id, uint256 x, uint256 y) external {
        _keys[id] = Pubkey(x, y);
    }
}

contract MockOprfRegistry {
    struct RegisteredOprfPublicKey {
        Key key;
        uint256 epoch;
    }

    struct Key {
        uint256 x;
        uint256 y;
    }

    mapping(uint160 => RegisteredOprfPublicKey) internal _keys;

    function getOprfPublicKeyAndEpoch(uint160 id) external view returns (RegisteredOprfPublicKey memory) {
        return _keys[id];
    }

    function setKey(uint160 id, uint256 x, uint256 y) external {
        _keys[id] = RegisteredOprfPublicKey(Key(x, y), 1);
    }
}

// ─── Mock DisputeGameFactory + Game ──────────────────────────────────────────

contract MockDisputeGame {
    GameStatus public status;

    constructor(GameStatus status_) {
        status = status_;
    }
}

contract MockDisputeGameFactory {
    mapping(bytes32 => address) internal _games;

    function registerGame(GameType gameType, Claim rootClaim, bytes memory extraData, address game) external {
        bytes32 key = keccak256(abi.encode(GameType.unwrap(gameType), Claim.unwrap(rootClaim), extraData));
        _games[key] = game;
    }

    function games(GameType gameType, Claim rootClaim, bytes memory extraData)
        external
        view
        returns (IDisputeGame proxy_, Timestamp timestamp_)
    {
        bytes32 key = keccak256(abi.encode(GameType.unwrap(gameType), Claim.unwrap(rootClaim), extraData));
        proxy_ = IDisputeGame(_games[key]);
        timestamp_ = Timestamp.wrap(uint64(block.timestamp));
    }
}

// ─── EthereumMPTGatewayAdapter test harness that bypasses MPT ────────────────

contract TestableEthereumMPTAdapter is EthereumMPTGatewayAdapter {
    bytes32 private _overrideChainHead;
    bool private _useOverride;

    constructor(
        address owner_,
        address disputeGameFactory_,
        bool requireFinalized_,
        address bridge_,
        address wcSource_,
        uint256 wcChainId_
    ) EthereumMPTGatewayAdapter(owner_, disputeGameFactory_, requireFinalized_, bridge_, wcSource_, wcChainId_) {}

    /// @dev Set a chain head to return from _verifyAndExtract, bypassing MPT proof verification.
    function setOverrideChainHead(bytes32 head_) external {
        _overrideChainHead = head_;
        _useOverride = true;
    }

    function _verifyAndExtract(bytes calldata payload, bytes memory attributes)
        internal
        override
        returns (bytes32 chainHead)
    {
        if (_useOverride) {
            return _overrideChainHead;
        }
        // Still validate the attribute selector so the test exercises the attribute format
        return super._verifyAndExtract(payload, attributes);
    }
}
