//! Metrics definitions and helpers for the world-id-relay.
//!
//! All metric names are declared as `pub const` so call sites are typo-proof
//! and the dashboard/alert spec lives in one place. Convenience setter/recorder
//! functions wrap the `metrics::` macros so business modules never import the
//! `metrics` crate directly.

use std::{sync::Arc, time::Duration};

use alloy::providers::{DynProvider, Provider};
use alloy_primitives::Address;

use crate::{log::CommitmentLog, primitives::StateCommitment};

/// Cadence at which the background wallet metrics task refreshes the per-chain
/// `balance_wei` and `nonce` gauges. Chosen to be fast enough for low-balance
/// alerting while staying well below provider rate limits across all chains.
pub const WALLET_METRICS_INTERVAL: Duration = Duration::from_secs(30);

// ── Metric name constants ───────────────────────────────────────────────────

/// Wallet native-token balance, in wei (`f64`-encoded for OTLP / Datadog).
pub const METRICS_WALLET_BALANCE_WEI: &str = "relay.wallet.balance_wei";

/// Latest read transaction count (nonce) for the relay wallet.
pub const METRICS_WALLET_NONCE: &str = "relay.wallet.nonce";

/// `propagateState` attempt outcomes from the World Chain source contract.
pub const METRICS_PROPAGATE_STATE_ATTEMPTS: &str = "relay.propagate_state.attempts";

/// End-to-end latency of a single `Engine::propagate` tick.
pub const METRICS_PROPAGATE_STATE_DURATION: &str = "relay.propagate_state.duration_seconds";

/// Per-satellite relay attempt outcomes.
pub const METRICS_SATELLITE_RELAY_ATTEMPTS: &str = "relay.satellite.relay.attempts";

/// Per-satellite relay attempt duration, including proof construction.
pub const METRICS_SATELLITE_RELAY_DURATION: &str = "relay.satellite.relay.duration_seconds";

/// Pending update queue depth in [`CommitmentLog`], split by kind.
pub const METRICS_LOG_PENDING_COUNT: &str = "relay.log.pending_count";

/// Latency of the one-shot historical `ChainCommitted` backfill at startup.
pub const METRICS_BACKFILL_DURATION: &str = "relay.backfill.duration_seconds";

/// Number of registry events received from World Chain, by event kind.
pub const METRICS_EVENTS_RECEIVED: &str = "relay.events.received";

// ── Label keys ──────────────────────────────────────────────────────────────

const LABEL_CHAIN_ID: &str = "chain_id";
const LABEL_OUTCOME: &str = "outcome";
const LABEL_SATELLITE: &str = "satellite";
const LABEL_KIND: &str = "kind";
const LABEL_EVENT_KIND: &str = "event_kind";

// ── Outcome constants ───────────────────────────────────────────────────────

/// Outcomes for `propagateState` and satellite relay counters. Using shared
/// string constants keeps cardinality fixed and the dashboard query stable.
pub mod outcome {
    pub const SUCCESS: &str = "success";
    pub const NOTHING_CHANGED: &str = "nothing_changed";
    pub const REVERT_ON_CHAIN: &str = "revert_on_chain";
    pub const SIMULATION_REVERT: &str = "simulation_revert";
    pub const RPC_ERROR: &str = "rpc_error";
    pub const NOOP: &str = "noop";
    pub const RELAY_FAILED: &str = "relay_failed";
    pub const TIMEOUT: &str = "timeout";
}

/// Kinds for the pending-count gauge.
pub mod pending_kind {
    pub const ISSUER: &str = "issuer";
    pub const OPRF: &str = "oprf";
    pub const ROOT: &str = "root";
}

// ── Describe ────────────────────────────────────────────────────────────────

/// Register metadata for all relay metrics. Call once after
/// `telemetry_batteries::init()`.
pub fn describe_metrics() {
    ::metrics::describe_gauge!(
        METRICS_WALLET_BALANCE_WEI,
        ::metrics::Unit::Count,
        "Relay wallet native-token balance, in wei."
    );
    ::metrics::describe_gauge!(
        METRICS_WALLET_NONCE,
        ::metrics::Unit::Count,
        "Latest observed transaction count (nonce) for the relay wallet."
    );

    ::metrics::describe_counter!(
        METRICS_PROPAGATE_STATE_ATTEMPTS,
        ::metrics::Unit::Count,
        "World Chain `propagateState` attempts, labelled by outcome."
    );
    ::metrics::describe_histogram!(
        METRICS_PROPAGATE_STATE_DURATION,
        ::metrics::Unit::Seconds,
        "Latency of a single `Engine::propagate` tick."
    );

    ::metrics::describe_counter!(
        METRICS_SATELLITE_RELAY_ATTEMPTS,
        ::metrics::Unit::Count,
        "Satellite relay attempts, labelled by satellite and outcome."
    );
    ::metrics::describe_histogram!(
        METRICS_SATELLITE_RELAY_DURATION,
        ::metrics::Unit::Seconds,
        "Latency of a single satellite relay attempt (proof build + tx submit)."
    );

    ::metrics::describe_gauge!(
        METRICS_LOG_PENDING_COUNT,
        ::metrics::Unit::Count,
        "Pending update queue depth in the commitment log, by kind."
    );

    ::metrics::describe_histogram!(
        METRICS_BACKFILL_DURATION,
        ::metrics::Unit::Seconds,
        "Latency of historical `ChainCommitted` backfill at startup."
    );

    ::metrics::describe_counter!(
        METRICS_EVENTS_RECEIVED,
        ::metrics::Unit::Count,
        "Registry events received from World Chain, by event kind."
    );
}

// ── Setters / recorders ─────────────────────────────────────────────────────

/// Records the wallet's native-token balance (in wei) for the given chain.
pub fn set_wallet_balance_wei(chain_id: u64, balance_wei: f64) {
    ::metrics::gauge!(
        METRICS_WALLET_BALANCE_WEI,
        LABEL_CHAIN_ID => chain_id.to_string(),
    )
    .set(balance_wei);
}

/// Records the wallet's transaction count (nonce) for the given chain.
pub fn set_wallet_nonce(chain_id: u64, nonce: u64) {
    ::metrics::gauge!(
        METRICS_WALLET_NONCE,
        LABEL_CHAIN_ID => chain_id.to_string(),
    )
    .set(nonce as f64);
}

/// Runs a background task that periodically refreshes the (`balance_wei`,
/// `nonce`) wallet gauges for a single chain. Intended to be `tokio::spawn`ed
/// once per chain at startup and then dropped — the task is fire-and-forget.
///
/// This MUST stay off the propagate/relay hot paths: observability code must
/// never pay network-latency tax on the critical path. Errors are demoted to
/// `warn!`; the task never returns and never panics.
///
/// The first tick fires immediately so dashboards aren't blank during the
/// first interval after process start.
pub async fn run_wallet_metrics_task(
    provider: Arc<DynProvider>,
    chain_id: u64,
    wallet_address: Address,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    // Skip missed ticks rather than burst — if the provider stalls for a
    // minute we don't want to fire several back-to-back refreshes when it
    // recovers.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match provider.get_balance(wallet_address).await {
            Ok(balance) => set_wallet_balance_wei(chain_id, f64::from(balance)),
            Err(e) => tracing::warn!(error = %e, chain_id, "failed to read wallet balance"),
        }
        match provider.get_transaction_count(wallet_address).await {
            Ok(nonce) => set_wallet_nonce(chain_id, nonce),
            Err(e) => tracing::warn!(error = %e, chain_id, "failed to read wallet nonce"),
        }
    }
}

/// Increments the `propagateState` attempt counter with the given outcome.
pub fn inc_propagate_outcome(outcome: &'static str) {
    ::metrics::counter!(
        METRICS_PROPAGATE_STATE_ATTEMPTS,
        LABEL_OUTCOME => outcome,
    )
    .increment(1);
}

/// Records the latency of a single `propagateState` tick.
pub fn record_propagate_duration(duration_seconds: f64) {
    ::metrics::histogram!(METRICS_PROPAGATE_STATE_DURATION).record(duration_seconds);
}

/// Increments a satellite relay attempt counter with the given outcome.
pub fn inc_satellite_relay_outcome(satellite: &str, outcome: &'static str) {
    ::metrics::counter!(
        METRICS_SATELLITE_RELAY_ATTEMPTS,
        LABEL_SATELLITE => satellite.to_owned(),
        LABEL_OUTCOME => outcome,
    )
    .increment(1);
}

/// Records the latency of a single satellite relay attempt.
pub fn record_satellite_relay_duration(satellite: &str, duration_seconds: f64) {
    ::metrics::histogram!(
        METRICS_SATELLITE_RELAY_DURATION,
        LABEL_SATELLITE => satellite.to_owned(),
    )
    .record(duration_seconds);
}

/// Records the historical backfill latency. Called once per process.
pub fn record_backfill_duration(duration_seconds: f64) {
    ::metrics::histogram!(METRICS_BACKFILL_DURATION).record(duration_seconds);
}

/// Increments the event-received counter using the [`StateCommitment`]
/// variant as the `event_kind` label.
pub fn inc_event_received(commitment: &StateCommitment) {
    let kind = event_kind(commitment);
    ::metrics::counter!(
        METRICS_EVENTS_RECEIVED,
        LABEL_EVENT_KIND => kind,
    )
    .increment(1);
}

/// Returns the static label value for a [`StateCommitment`] variant.
pub fn event_kind(commitment: &StateCommitment) -> &'static str {
    match commitment {
        StateCommitment::ChainCommitted(_) => "chain_committed",
        StateCommitment::RootCommitment(_) => "root_commitment",
        StateCommitment::IssuerPubKey(_) => "issuer_pub_key",
        StateCommitment::OprfPubKey(_) => "oprf_pub_key",
    }
}

/// Snapshots the log's pending queue depths and publishes them as gauges.
///
/// Cheap: each call acquires the log's internal locks briefly. Intended to be
/// called from `Engine` after every state-changing log operation.
pub fn record_pending_counts(log: &CommitmentLog) {
    let counts = log.pending_counts();
    ::metrics::gauge!(
        METRICS_LOG_PENDING_COUNT,
        LABEL_KIND => pending_kind::ISSUER,
    )
    .set(counts.issuers as f64);
    ::metrics::gauge!(
        METRICS_LOG_PENDING_COUNT,
        LABEL_KIND => pending_kind::OPRF,
    )
    .set(counts.oprfs as f64);
    ::metrics::gauge!(
        METRICS_LOG_PENDING_COUNT,
        LABEL_KIND => pending_kind::ROOT,
    )
    .set(counts.roots as f64);
}
