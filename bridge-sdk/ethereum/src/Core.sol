// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// ── Ethereum L1 ──
import {EthereumWorldIdVerifier} from "./core/EthereumWorldIdVerifier.sol";

// ── Universal (any EVM chain with L1 block hash oracle) ──
import {UniversalWorldIdVerifier} from "./core/UniversalWorldIdVerifier.sol";

// ── Native L1→L2 receivers ──
import {ArbitrumReceiver} from "./core/adapters/arbitrum/ArbitrumReceiver.sol";
import {ScrollReceiver} from "./core/adapters/scroll/ScrollReceiver.sol";
import {ZkSyncReceiver} from "./core/adapters/zksync/ZkSyncReceiver.sol";

// ── L1 dispatch adapters ──
import {ArbitrumAdapter} from "./core/adapters/arbitrum/ArbitrumAdapter.sol";
import {ScrollAdapter} from "./core/adapters/scroll/ScrollAdapter.sol";
import {ZkSyncAdapter} from "./core/adapters/zksync/ZkSyncAdapter.sol";
import {OpStackAdapter} from "./core/adapters/op/OpStackAdapter.sol";
import {WormholeAdapter} from "./core/adapters/wormhole/WormholeAdapter.sol";

// -- World Chain Bridge --
import {WorldChainBridge} from "./core/WorldChainBridge.sol";
