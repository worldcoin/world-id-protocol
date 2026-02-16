// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title World ID Bridge SDK — Core Re-exports
/// @notice Single-import entrypoint for all Bridge SDK contracts, interfaces, and libraries.
///
/// @dev Architecture overview:
///
///   ┌──────────────────────────────────────────────────────────────────────┐
///   │                         World Chain (source)                        │
///   │                                                                    │
///   │  WorldIDSource ← reads WC registries, extends keccak hash chain    │
///   └──────────────────────────┬─────────────────────────────────────────┘
///                              │  propagateState() emits ChainCommitted
///                              ▼
///   ┌──────────────────────────────────────────────────────────────────────┐
///   │                          L1 (Ethereum)                             │
///   │                                                                    │
///   │  L1Gateway ─── verifies WC state via DisputeGameFactory + MPT ──►  │
///   │                delivers chain head to L1 CrossDomainWorldID         │
///   └──────────────────────────┬─────────────────────────────────────────┘
///                              │  L1 StateBridge stores proven chain head
///                              ▼
///   ┌──────────────────────────────────────────────────────────────────────┐
///   │                     Destination Chain (L2/L3)                       │
///   │                                                                    │
///   │  ZKGateway ─── ZK-proves L1 consensus + MPT proves L1 bridge ──►   │
///   │  OwnedGateway ── owner-attested (day-1 trust model) ──────────►    │
///   │                delivers chain head to local CrossDomainWorldID      │
///   │                                                                    │
///   │  CrossDomainWorldID ── verifies commitments against chain head,     │
///   │                        verifies Groth16 proofs for World ID        │
///   └──────────────────────────────────────────────────────────────────────┘
///
///   Trust models (by gateway):
///     • OwnedGateway  — trusted owner (multisig/bot)
///     • L1Gateway     — OP Stack DisputeGame + MPT (configurable finalization)
///     • ZKGateway     — SP1 Helios ZK proof of L1 consensus + MPT
///
///   State flow:
///     1. WorldIDSource.propagateState() reads WC registries, appends to keccak chain
///     2. Gateway verifies chain head authenticity (per its trust model)
///     3. Gateway delivers (chainHead, commitments) to CrossDomainWorldID via ERC-7786
///     4. CrossDomainWorldID verifies commitments hash to chainHead, applies state
///     5. Users verify World ID proofs against the bridged Merkle root

// ── Interfaces ──
import {IStateBridge} from "./core/interfaces/IStateBridge.sol";
import {IGateway} from "./core/interfaces/IGateway.sol";
import {IWorldID} from "./core/interfaces/IWorldID.sol";

// ── Core base ──
import {StateBridge} from "./core/lib/StateBridge.sol";
import {ProofsLib} from "./core/lib/ProofsLib.sol";

// ── Source (World Chain) ──
import {WorldIDSource} from "./core/WorldIDSource.sol";

// ── Destination (cross-chain verifier) ──
import {CrossDomainWorldID} from "./core/CrossDomainWorldID.sol";

// ── Gateways ──
import {Gateway} from "./core/gateways/Gateway.sol";
import {Attributes} from "./core/gateways/Attributes.sol";
import {OwnedGateway} from "./core/gateways/OwnedGateway.sol";
import {L1Gateway} from "./core/gateways/L1Gateway.sol";
import {ZKGateway} from "./core/gateways/ZKGateway.sol";
