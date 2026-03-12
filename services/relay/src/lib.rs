#![cfg_attr(not(test), warn(unused_crate_dependencies))]

//! # World ID Relay
//!
//! Off-chain service that bridges World ID state from **World Chain** (the
//! source of truth) to satellite chains (Ethereum L1, L2 rollups, Alt L1s).
//!
//! ## Architecture
//!
//! The relay follows a **source → log → fan-out** pipeline:
//!
//! ```text
//!  World Chain registries          CommitmentLog           Satellite tasks
//! ┌──────────────────────┐     ┌──────────────────┐     ┌───────────────────┐
//! │ WorldIDRegistry      │     │                  │     │ EthereumMpt       │
//! │ IssuerSchemaRegistry │────▶│  append-only log  │────▶│   (L1 via MPT)   │
//! │ OprfKeyRegistry      │     │  + keccak chain  │     ├───────────────────┤
//! │ WorldIDSource        │     │   verification   │     │ MultiChain Fan-out│
//!         ▲                            │                └───────────────────┘
//!         │                            │
//!     propagateState()           watch::Receiver
//!     (periodic tick)            (new chain heads)
//! ```
//!
//! ### Data flow
//!
//! 1. **[`stream`]** — Watches World Chain registry contracts for events
//!    (`RootRecorded`, `ChainCommitted`, issuer/OPRF key updates) and back-fills
//!    historical events on startup.
//!
//! 2. **[`CommitmentLog`]** — An append-only, hash-chain-verified log of all
//!    observed commitments. Each `ChainCommitted` event is verified against a
//!    local keccak chain replica before acceptance. Pending key updates and root
//!    updates are tracked separately for `propagateState()` calls.
//!
//! 3. **[`Engine`]** — The top-level coordinator. Consumes the event stream,
//!    feeds the log, periodically calls `propagateState()` on WorldIDSource to
//!    finalize pending updates, and manages satellite task lifecycles.
//!
//! 4. **[`Satellite`]** — A trait for destination-chain relayers. Each
//!    implementation subscribes to the log's chain-head watch channel, merges
//!    any un-relayed commitments into a single delta via [`primitives::reduce`],
//!    builds a chain-specific proof, and submits a relay transaction through an
//!    ERC-7786 gateway.
//!
//! ### Key types
//!
//! - [`ChainCommitment`] — A decoded `ChainCommitted` event with the keccak
//!   chain head, block metadata, and raw ABI-encoded commitment payload.
//! - [`KeccakChain`] — Local replica of the on-chain keccak hash chain, used
//!   to verify commitment integrity before accepting entries into the log.
//! - [`StateCommitment`] — Union of all commitment variants the relay tracks
//!   (chain commits, root updates, issuer keys, OPRF keys).
//!
//! ### Satellite implementations
//!
//! - **[`satellite::EthereumMptSatellite`]** — Bridges to Ethereum L1 using
//!   OP Stack dispute games and Merkle Patricia Trie (MPT) storage proofs
//!   against the L2 state root.

use config as _;
use dotenvy as _;
use serde_json as _;
use telemetry_batteries as _;

// ---------------------------------------------------------------------------
// Internal modules
// ---------------------------------------------------------------------------

/// MPT storage proof construction for cross-chain verification.
pub(crate) mod proof;

/// Event stream plumbing: registry watchers and historical backfill.
pub(crate) mod stream;

// ---------------------------------------------------------------------------
// Public modules
// ---------------------------------------------------------------------------

/// Alloy `sol!` bindings for every on-chain interface the relay interacts with.
///
/// Includes World ID registries, ERC-7786 gateway, OP Stack dispute game
/// contracts, and well-known event signature / storage slot constants.
pub mod bindings;

/// CLI entry point and per-chain configuration structs.
///
/// [`Cli`] is the top-level clap parser. [`WorldChainConfig`] and
/// [`SatelliteConfig`] carry the addresses, RPC endpoints, and tuning
/// knobs for each chain the relay connects to.
pub mod cli;

/// The relay engine — event loop, propagation ticks, and satellite management.
mod engine;

/// Append-only, hash-chain-verified commitment log with watch-based fan-out.
mod log;

/// Core domain types: commitments, keccak chain, key identifiers.
pub mod primitives;

/// Low-level relay transaction submission via ERC-7786 gateways.
///
/// Handles ERC-7930 interoperable address encoding and `sendMessage` calls.
pub mod relay;

/// Satellite chain trait and task spawner.
///
/// A [`Satellite`] knows how to build a proof for a given commitment and send
/// the relay transaction to its destination chain. The [`spawn_satellite`]
/// helper runs the subscribe → merge → prove → relay loop.
pub mod satellite;

// ---------------------------------------------------------------------------
// Convenience re-exports
// ---------------------------------------------------------------------------

// -- Primitives --
pub use primitives::{
    ChainCommitment, CommitmentKey, KeccakChain, RootCommitment, StateCommitment,
};

// -- Bindings --
pub use bindings::{
    CHAIN_COMMITTED_EVENTS, ICommitment, IWorldIDRegistry, IWorldIDSatellite, IWorldIDSource,
    OPRF_REGISTRY_EVENTS, STATE_BRIDGE_STORAGE_SLOT, WORLD_ID_REGISTRY_EVENTS,
};

// -- Engine & satellite --
pub use engine::Engine;
pub use satellite::{PermissionedSatellite, Satellite, spawn_satellite};

// -- CLI --
pub use cli::{
    Cli, EthereumMptGatewayConfig, PermissionedGatewayConfig, RelayConfig, SourceConfig,
    WorldChainConfig,
};

// -- Log --
pub use log::CommitmentLog;
