//! Service-level metrics for world-id-billing.

/// Finalization backlog: number of closed-but-unfinalized epochs. 0 means
/// fully caught up; sustained growth means the finalizer is falling behind
/// (or its gas key ran dry) and RP debt / blocking state is going stale.
pub const METRICS_FINALIZER_EPOCH_LAG: &str = "billing.finalizer.epoch_lag";

/// `finalizeEpochs` transaction attempts, labelled by outcome.
pub const METRICS_FINALIZER_FINALIZE_ATTEMPTS: &str = "billing.finalizer.finalize_attempts";

/// Failed finalizer cycles (a cursor/deadline read or a `finalizeEpochs`
/// drain), retried next cycle from fresh on-chain state.
pub const METRICS_FINALIZER_TICK_FAILURES: &str = "billing.finalizer.tick_failures";

/// Confirm-loop retry attempts: the finalizer woke at a computed deadline but
/// the chain didn't yet reflect the epoch as closed (RPC lag, clock drift).
/// Rare/occasional retries are expected; a sustained rate signals persistent
/// RPC degradation and precedes a fatal confirm-timeout if it doesn't clear.
pub const METRICS_FINALIZER_CONFIRM_RETRIES: &str = "billing.finalizer.confirm_retries";

pub const LABEL_OUTCOME: &str = "outcome";

/// Shared outcome labels — kept in one place so cardinality stays bounded.
pub mod tx_outcome {
    pub const SUCCESS: &str = "success";
    pub const REVERT_ON_CHAIN: &str = "revert_on_chain";
    pub const RPC_ERROR: &str = "rpc_error";
    pub const TIMEOUT: &str = "timeout";
}

/// Register metadata; call once after `telemetry_batteries::init()`.
pub fn describe_metrics() {
    ::metrics::describe_gauge!(
        METRICS_FINALIZER_EPOCH_LAG,
        ::metrics::Unit::Count,
        "Closed-but-unfinalized Billing Contract epochs (0 = caught up)."
    );

    ::metrics::describe_counter!(
        METRICS_FINALIZER_FINALIZE_ATTEMPTS,
        ::metrics::Unit::Count,
        "Billing `finalizeEpochs` transaction attempts, labelled by outcome."
    );

    ::metrics::describe_counter!(
        METRICS_FINALIZER_TICK_FAILURES,
        ::metrics::Unit::Count,
        "Failed finalizer cycles (cursor/deadline read or a finalizeEpochs drain)."
    );

    ::metrics::describe_counter!(
        METRICS_FINALIZER_CONFIRM_RETRIES,
        ::metrics::Unit::Count,
        "Finalizer confirm-loop retry attempts after waking at a computed deadline."
    );
}
