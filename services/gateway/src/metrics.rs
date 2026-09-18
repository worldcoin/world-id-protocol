//! Metrics definitions and helpers for the world-id-gateway.

// HTTP metrics
pub use world_id_services_common::METRICS_HTTP_LATENCY_MS;

// Root cache metrics
pub const METRICS_ROOT_CACHE_HITS: &str = "root_cache.hits";
pub const METRICS_ROOT_CACHE_MISSES: &str = "root_cache.misses";

// Batcher metrics
pub const METRICS_BATCH_SUBMITTED: &str = "batch.submitted";
pub const METRICS_BATCH_SIZE: &str = "batch.size";
/// Latency from batch creation to on-chain confirmation (success or revert).
pub const METRICS_BATCH_LATENCY_MS: &str = "batch.latency_ms";
/// Latency of the RPC `eth_sendRawTransaction` call only.
pub const METRICS_BATCH_SEND_LATENCY_MS: &str = "batch.send_latency_ms";
/// Incremented when a batch transaction is confirmed on-chain without reverting.
pub const METRICS_BATCH_SUCCESS: &str = "batch.success";
/// Incremented when a batch transaction reverts on-chain OR fails to confirm.
pub const METRICS_BATCH_FAILURE: &str = "batch.failure";
/// Incremented when a batch transaction fails to submit to the RPC node.
pub const METRICS_BATCH_SEND_FAILED: &str = "batch.send_failed";
pub const METRICS_BATCH_POLICY_COST_SCORE: &str = "batch.policy.cost_score";
pub const METRICS_BATCH_POLICY_URGENCY_SCORE: &str = "batch.policy.urgency_score";
pub const METRICS_BATCH_POLICY_DEFER: &str = "batch.policy.defer";
pub const METRICS_BATCH_POLICY_FORCE_SEND: &str = "batch.policy.force_send";
pub const METRICS_BATCH_POLICY_TARGET_SIZE: &str = "batch.policy.target_size";

// Request rejection metrics
pub const METRICS_REQUEST_REJECTED: &str = "request.rejected";

// Wallet lease metrics
pub const METRICS_WALLET_POOL_SIZE: &str = "wallet.pool_size";
pub const METRICS_WALLET_IN_FLIGHT: &str = "wallet.in_flight";
pub const METRICS_WALLET_PARKED: &str = "wallet.parked";
pub const METRICS_WALLET_ACQUIRE_WAIT_MS: &str = "wallet.acquire_wait_ms";
pub const METRICS_WALLET_ACQUIRE_EMPTY: &str = "wallet.acquire_empty";
pub const METRICS_WALLET_OUTCOME: &str = "wallet.outcome";
pub const METRICS_WALLET_TIME_IN_FLIGHT_MS: &str = "wallet.time_in_flight_ms";
pub const METRICS_WALLET_CONFIRMATIONS_AT_RELEASE: &str = "wallet.confirmations_at_release";
pub const METRICS_WALLET_TRACKER_ERRORS: &str = "wallet.tracker_error";

pub fn describe_metrics() {
    world_id_services_common::describe_http_request_metrics();
    world_id_services_common::describe_deprecated_endpoint_metrics();

    ::metrics::describe_counter!(
        METRICS_ROOT_CACHE_HITS,
        ::metrics::Unit::Count,
        "Number of root cache hits."
    );
    ::metrics::describe_counter!(
        METRICS_ROOT_CACHE_MISSES,
        ::metrics::Unit::Count,
        "Number of root cache misses."
    );

    ::metrics::describe_counter!(
        METRICS_BATCH_SUBMITTED,
        ::metrics::Unit::Count,
        "Number of batches successfully submitted to the RPC node."
    );
    ::metrics::describe_histogram!(
        METRICS_BATCH_SIZE,
        ::metrics::Unit::Count,
        "Number of requests per submitted batch."
    );
    ::metrics::describe_histogram!(
        METRICS_BATCH_LATENCY_MS,
        ::metrics::Unit::Milliseconds,
        "End-to-end batch latency from submission to on-chain confirmation in milliseconds."
    );
    ::metrics::describe_histogram!(
        METRICS_BATCH_SEND_LATENCY_MS,
        ::metrics::Unit::Milliseconds,
        "Latency of the RPC eth_sendRawTransaction call in milliseconds."
    );
    ::metrics::describe_counter!(
        METRICS_BATCH_SUCCESS,
        ::metrics::Unit::Count,
        "Number of batches confirmed on-chain successfully (transaction did not revert)."
    );
    ::metrics::describe_counter!(
        METRICS_BATCH_FAILURE,
        ::metrics::Unit::Count,
        "Number of batches that failed on-chain (transaction reverted or confirmation error)."
    );
    ::metrics::describe_counter!(
        METRICS_BATCH_SEND_FAILED,
        ::metrics::Unit::Count,
        "Number of batches that failed to submit to the RPC node."
    );

    ::metrics::describe_histogram!(
        METRICS_BATCH_POLICY_COST_SCORE,
        ::metrics::Unit::Count,
        "Batch policy cost score."
    );
    ::metrics::describe_histogram!(
        METRICS_BATCH_POLICY_URGENCY_SCORE,
        ::metrics::Unit::Count,
        "Batch policy urgency score."
    );
    ::metrics::describe_histogram!(
        METRICS_BATCH_POLICY_TARGET_SIZE,
        ::metrics::Unit::Count,
        "Target batch size chosen by batch policy."
    );
    ::metrics::describe_counter!(
        METRICS_BATCH_POLICY_FORCE_SEND,
        ::metrics::Unit::Count,
        "Number of forced sends triggered by policy."
    );
    ::metrics::describe_counter!(
        METRICS_BATCH_POLICY_DEFER,
        ::metrics::Unit::Count,
        "Number of policy deferrals by reason."
    );

    ::metrics::describe_counter!(
        METRICS_REQUEST_REJECTED,
        ::metrics::Unit::Count,
        "Number of rejected requests by reason."
    );

    ::metrics::describe_gauge!(
        METRICS_WALLET_POOL_SIZE,
        ::metrics::Unit::Count,
        "Number of configured transaction wallets."
    );
    ::metrics::describe_gauge!(
        METRICS_WALLET_IN_FLIGHT,
        ::metrics::Unit::Count,
        "Number of wallets currently holding an outstanding transaction."
    );
    ::metrics::describe_gauge!(
        METRICS_WALLET_PARKED,
        ::metrics::Unit::Count,
        "Number of wallets parked because a transaction's fate could not be decided."
    );
    ::metrics::describe_histogram!(
        METRICS_WALLET_ACQUIRE_WAIT_MS,
        ::metrics::Unit::Milliseconds,
        "Time spent waiting for a free wallet before a batch could be signed."
    );
    ::metrics::describe_counter!(
        METRICS_WALLET_ACQUIRE_EMPTY,
        ::metrics::Unit::Count,
        "Number of times no wallet was free on the first attempt (saturation, not an error)."
    );
    ::metrics::describe_counter!(
        METRICS_WALLET_OUTCOME,
        ::metrics::Unit::Count,
        "Wallet outcomes by kind, including park, which is not a release."
    );
    ::metrics::describe_histogram!(
        METRICS_WALLET_TIME_IN_FLIGHT_MS,
        ::metrics::Unit::Milliseconds,
        "Time a wallet spent out of the pool for one transaction."
    );
    ::metrics::describe_histogram!(
        METRICS_WALLET_CONFIRMATIONS_AT_RELEASE,
        ::metrics::Unit::Count,
        "Confirmations observed when a wallet was released; evidence for the release threshold."
    );
    ::metrics::describe_counter!(
        METRICS_WALLET_TRACKER_ERRORS,
        ::metrics::Unit::Count,
        "Number of errors while resolving wallet transactions."
    );

    world_id_services_common::describe_provider_transport_metrics();
}

pub fn increment_root_cache_hit() {
    ::metrics::counter!(METRICS_ROOT_CACHE_HITS).increment(1);
}

pub fn increment_root_cache_miss() {
    ::metrics::counter!(METRICS_ROOT_CACHE_MISSES).increment(1);
}

pub fn record_batch_submitted(batch_type: &'static str, batch_size: usize) {
    ::metrics::counter!(METRICS_BATCH_SUBMITTED, "type" => batch_type).increment(1);
    ::metrics::histogram!(METRICS_BATCH_SIZE, "type" => batch_type).record(batch_size as f64);
}

/// Records the latency and outcome of the RPC `eth_sendRawTransaction` call.
///
/// This reflects whether the transaction was accepted by the node, **not**
/// whether it was confirmed on-chain. Use [`record_batch_confirmed`] for
/// on-chain outcomes.
pub fn record_batch_send_failed(batch_type: &'static str, send_latency_ms: f64) {
    ::metrics::histogram!(METRICS_BATCH_SEND_LATENCY_MS, "type" => batch_type)
        .record(send_latency_ms);
    ::metrics::counter!(METRICS_BATCH_SEND_FAILED, "type" => batch_type).increment(1);
}

/// Records the RPC send latency after a successful submission to the node.
pub fn record_batch_send_latency(batch_type: &'static str, send_latency_ms: f64) {
    ::metrics::histogram!(METRICS_BATCH_SEND_LATENCY_MS, "type" => batch_type)
        .record(send_latency_ms);
}

/// Records the on-chain confirmation outcome of a previously submitted batch.
///
/// `success` is `true` when the transaction was mined without reverting,
/// `false` when it reverted or could not be confirmed.
/// `latency_ms` is measured from when the batch was first submitted to the
/// RPC node until the receipt was obtained.
pub fn record_batch_confirmed(batch_type: &'static str, success: bool, latency_ms: f64) {
    ::metrics::histogram!(METRICS_BATCH_LATENCY_MS, "type" => batch_type).record(latency_ms);

    if success {
        ::metrics::counter!(METRICS_BATCH_SUCCESS, "type" => batch_type).increment(1);
    } else {
        ::metrics::counter!(METRICS_BATCH_FAILURE, "type" => batch_type).increment(1);
    }
}

pub fn record_policy_scores(
    batch_type: &'static str,
    cost_score: f64,
    urgency_score: f64,
    target_batch_size: usize,
) {
    ::metrics::histogram!(METRICS_BATCH_POLICY_COST_SCORE, "type" => batch_type).record(cost_score);
    ::metrics::histogram!(METRICS_BATCH_POLICY_URGENCY_SCORE, "type" => batch_type)
        .record(urgency_score);
    ::metrics::histogram!(METRICS_BATCH_POLICY_TARGET_SIZE, "type" => batch_type)
        .record(target_batch_size as f64);
}

pub fn increment_policy_force_send(batch_type: &'static str) {
    ::metrics::counter!(METRICS_BATCH_POLICY_FORCE_SEND, "type" => batch_type).increment(1);
}

pub fn increment_policy_defer(batch_type: &'static str, reason: &'static str) {
    ::metrics::counter!(METRICS_BATCH_POLICY_DEFER, "type" => batch_type, "reason" => reason)
        .increment(1);
}

pub fn increment_request_rejected(reason: &'static str) {
    ::metrics::counter!(METRICS_REQUEST_REJECTED, "reason" => reason).increment(1);
}

/// Records the size of the configured wallet pool.
pub fn record_wallet_pool_size(size: usize) {
    ::metrics::gauge!(METRICS_WALLET_POOL_SIZE).set(size as f64);
}

/// Records how many wallets are currently out of the pool.
pub fn record_wallet_pool_state(in_flight: usize, parked: usize) {
    ::metrics::gauge!(METRICS_WALLET_IN_FLIGHT).set(in_flight as f64);
    ::metrics::gauge!(METRICS_WALLET_PARKED).set(parked as f64);
}

/// Records how long a caller waited before a wallet became free.
pub fn record_wallet_acquire_wait(wait_ms: f64) {
    ::metrics::histogram!(METRICS_WALLET_ACQUIRE_WAIT_MS).record(wait_ms);
}

/// Records that a caller found no free wallet before its timeout.
pub fn increment_wallet_acquire_empty() {
    ::metrics::counter!(METRICS_WALLET_ACQUIRE_EMPTY).increment(1);
}

/// Records how a wallet left the pool.
///
/// `outcome` is one of `confirmed`, `reverted`, `replaced` or `parked`; park is
/// deliberately included even though it is not a release.
pub fn record_wallet_outcome(outcome: &'static str) {
    ::metrics::counter!(METRICS_WALLET_OUTCOME, "outcome" => outcome).increment(1);
}

/// Records how long a wallet was out of the pool for one transaction.
pub fn record_wallet_time_in_flight(latency_ms: f64) {
    ::metrics::histogram!(METRICS_WALLET_TIME_IN_FLIGHT_MS).record(latency_ms);
}

/// Records the confirmations observed when a wallet was released.
pub fn record_wallet_confirmations_at_release(confirmations: u64) {
    ::metrics::histogram!(METRICS_WALLET_CONFIRMATIONS_AT_RELEASE).record(confirmations as f64);
}

/// Records an error while resolving wallet transactions.
pub fn increment_wallet_tracker_error() {
    ::metrics::counter!(METRICS_WALLET_TRACKER_ERRORS).increment(1);
}
