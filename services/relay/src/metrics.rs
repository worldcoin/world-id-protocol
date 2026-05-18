//! Service-level metrics for the world-id-relay.

use std::{sync::Arc, time::Duration};

use alloy::providers::{DynProvider, Provider};
use alloy_primitives::Address;

use crate::log::CommitmentLog;

pub const WALLET_METRICS_INTERVAL: Duration = Duration::from_secs(30);

pub const METRICS_WALLET_BALANCE_WEI: &str = "relay.wallet.balance_wei";
pub const METRICS_PROPAGATE_STATE_ATTEMPTS: &str = "relay.propagate_state.attempts";
pub const METRICS_SATELLITE_RELAY_ATTEMPTS: &str = "relay.satellite.relay.attempts";
pub const METRICS_LOG_PENDING_COUNT: &str = "relay.log.pending_count";

const LABEL_CHAIN_ID: &str = "chain_id";
const LABEL_OUTCOME: &str = "outcome";
const LABEL_SATELLITE: &str = "satellite";
const LABEL_KIND: &str = "kind";

/// Shared outcome labels — kept in one place so cardinality stays bounded.
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

pub mod pending_kind {
    pub const ISSUER: &str = "issuer";
    pub const OPRF: &str = "oprf";
}

/// Register metadata; call once after `telemetry_batteries::init()`.
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

pub fn set_wallet_balance_wei(chain_id: u64, balance_wei: f64) {
    ::metrics::gauge!(
        METRICS_WALLET_BALANCE_WEI,
        LABEL_CHAIN_ID => chain_id.to_string(),
    )
    .set(balance_wei);
}

/// Periodically refreshes the `balance_wei` gauge; kept off the relay hot
/// path. Errors are warned; the task never returns.
pub async fn run_wallet_metrics_task(
    provider: Arc<DynProvider>,
    chain_id: u64,
    wallet_address: Address,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    // Skip missed ticks so a stalled provider doesn't cause a burst on recovery.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match provider.get_balance(wallet_address).await {
            Ok(balance) => set_wallet_balance_wei(chain_id, f64::from(balance)),
            Err(e) => tracing::warn!(error = %e, chain_id, "failed to read wallet balance"),
        }
    }
}

pub fn inc_propagate_outcome(outcome: &'static str) {
    ::metrics::counter!(
        METRICS_PROPAGATE_STATE_ATTEMPTS,
        LABEL_OUTCOME => outcome,
    )
    .increment(1);
}

pub fn inc_satellite_relay_outcome(satellite: &str, outcome: &'static str) {
    ::metrics::counter!(
        METRICS_SATELLITE_RELAY_ATTEMPTS,
        LABEL_SATELLITE => satellite.to_owned(),
        LABEL_OUTCOME => outcome,
    )
    .increment(1);
}

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
}
