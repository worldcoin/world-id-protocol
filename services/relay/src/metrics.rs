//! Metrics definitions and helpers for the world-id-relay.
//!
//! All metric names are declared as `pub const` so call sites are typo-proof
//! and the dashboard/alert spec lives in one place. Convenience setter/recorder
//! functions wrap the `metrics::` macros so business modules never import the
//! `metrics` crate directly.
//!
//! Only metrics whose alert would justify paging an on-call engineer live
//! here. Latency/timing signals belong in traces, not metrics.

use std::{sync::Arc, time::Duration};

use alloy::providers::{DynProvider, Provider};
use alloy_primitives::Address;

use crate::log::CommitmentLog;

/// Cadence at which the background wallet metrics task refreshes the per-chain
/// `balance_wei` gauge. Chosen to be fast enough for low-balance alerting
/// while staying well below provider rate limits across all chains.
pub const WALLET_METRICS_INTERVAL: Duration = Duration::from_secs(30);

// ── Metric name constants ───────────────────────────────────────────────────

/// Wallet native-token balance, in wei (`f64`-encoded for OTLP / Datadog).
pub const METRICS_WALLET_BALANCE_WEI: &str = "relay.wallet.balance_wei";

/// `propagateState` attempt outcomes from the World Chain source contract.
pub const METRICS_PROPAGATE_STATE_ATTEMPTS: &str = "relay.propagate_state.attempts";

/// Per-satellite relay attempt outcomes.
pub const METRICS_SATELLITE_RELAY_ATTEMPTS: &str = "relay.satellite.relay.attempts";

/// Pending update queue depth in [`CommitmentLog`], split by kind.
pub const METRICS_LOG_PENDING_COUNT: &str = "relay.log.pending_count";

// ── Label keys ──────────────────────────────────────────────────────────────

const LABEL_CHAIN_ID: &str = "chain_id";
const LABEL_OUTCOME: &str = "outcome";
const LABEL_SATELLITE: &str = "satellite";
const LABEL_KIND: &str = "kind";

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

    ::metrics::describe_counter!(
        METRICS_PROPAGATE_STATE_ATTEMPTS,
        ::metrics::Unit::Count,
        "World Chain `propagateState` attempts, labelled by outcome."
    );

    ::metrics::describe_counter!(
        METRICS_SATELLITE_RELAY_ATTEMPTS,
        ::metrics::Unit::Count,
        "Satellite relay attempts, labelled by satellite and outcome."
    );

    ::metrics::describe_gauge!(
        METRICS_LOG_PENDING_COUNT,
        ::metrics::Unit::Count,
        "Pending update queue depth in the commitment log, by kind."
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

/// Runs a background task that periodically refreshes the `balance_wei`
/// wallet gauge for a single chain. Intended to be `tokio::spawn`ed once per
/// chain at startup and then dropped — the task is fire-and-forget.
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

/// Increments a satellite relay attempt counter with the given outcome.
pub fn inc_satellite_relay_outcome(satellite: &str, outcome: &'static str) {
    ::metrics::counter!(
        METRICS_SATELLITE_RELAY_ATTEMPTS,
        LABEL_SATELLITE => satellite.to_owned(),
        LABEL_OUTCOME => outcome,
    )
    .increment(1);
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
