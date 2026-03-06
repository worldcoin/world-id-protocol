//! Metrics definitions and helpers for the world-id-gateway.

// HTTP metrics
pub const METRICS_HTTP_LATENCY_MS: &str = "http.latency_ms";

// Root cache metrics
pub const METRICS_ROOT_CACHE_HITS: &str = "root_cache.hits";
pub const METRICS_ROOT_CACHE_MISSES: &str = "root_cache.misses";

// Batcher metrics
pub const METRICS_BATCH_SUBMITTED: &str = "batch.submitted";
pub const METRICS_BATCH_SIZE: &str = "batch.size";
pub const METRICS_BATCH_LATENCY_MS: &str = "batch.latency_ms";
pub const METRICS_BATCH_SUCCESS: &str = "batch.success";
pub const METRICS_BATCH_FAILURE: &str = "batch.failure";
pub const METRICS_BATCH_POLICY_COST_SCORE: &str = "batch.policy.cost_score";
pub const METRICS_BATCH_POLICY_URGENCY_SCORE: &str = "batch.policy.urgency_score";
pub const METRICS_BATCH_POLICY_DEFER: &str = "batch.policy.defer";
pub const METRICS_BATCH_POLICY_FORCE_SEND: &str = "batch.policy.force_send";
pub const METRICS_BATCH_POLICY_TARGET_SIZE: &str = "batch.policy.target_size";

// Simulation metrics
pub const METRICS_SIMULATION_LATENCY_MS: &str = "simulation.latency_ms";
pub const METRICS_SIMULATION_FAILURE: &str = "simulation.failure";

// Receipt confirmation metrics
pub const METRICS_RECEIPT_CONFIRMATION_LATENCY_MS: &str = "receipt.confirmation_latency_ms";
pub const METRICS_RECEIPT_FAILURE: &str = "receipt.failure";

// Request lifecycle metrics
pub const METRICS_REQUEST_FINALIZED: &str = "request.finalized";
pub const METRICS_REQUEST_FINALIZED_BATCH_SIZE: &str = "request.finalized_batch_size";

// Orphan sweeper metrics
pub const METRICS_SWEEPER_CLEANED: &str = "sweeper.cleaned";
pub const METRICS_SWEEPER_PENDING_COUNT: &str = "sweeper.pending_count";

pub fn describe_metrics() {
    ::metrics::describe_histogram!(
        METRICS_HTTP_LATENCY_MS,
        ::metrics::Unit::Milliseconds,
        "Gateway HTTP request latency in milliseconds."
    );

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
        "Number of submitted batches."
    );
    ::metrics::describe_histogram!(
        METRICS_BATCH_SIZE,
        ::metrics::Unit::Count,
        "Number of requests per submitted batch."
    );
    ::metrics::describe_histogram!(
        METRICS_BATCH_LATENCY_MS,
        ::metrics::Unit::Milliseconds,
        "Batch submission latency in milliseconds."
    );
    ::metrics::describe_counter!(
        METRICS_BATCH_SUCCESS,
        ::metrics::Unit::Count,
        "Number of successfully submitted batches."
    );
    ::metrics::describe_counter!(
        METRICS_BATCH_FAILURE,
        ::metrics::Unit::Count,
        "Number of failed batch submissions."
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

    ::metrics::describe_histogram!(
        METRICS_SIMULATION_LATENCY_MS,
        ::metrics::Unit::Milliseconds,
        "Contract simulation (eth_call) latency in milliseconds."
    );
    ::metrics::describe_counter!(
        METRICS_SIMULATION_FAILURE,
        ::metrics::Unit::Count,
        "Number of failed contract simulations."
    );

    ::metrics::describe_histogram!(
        METRICS_RECEIPT_CONFIRMATION_LATENCY_MS,
        ::metrics::Unit::Milliseconds,
        "Time from transaction submission to receipt confirmation in milliseconds."
    );
    ::metrics::describe_counter!(
        METRICS_RECEIPT_FAILURE,
        ::metrics::Unit::Count,
        "Number of receipt polling RPC failures."
    );

    ::metrics::describe_counter!(
        METRICS_REQUEST_FINALIZED,
        ::metrics::Unit::Count,
        "Number of requests reaching a terminal state."
    );
    ::metrics::describe_histogram!(
        METRICS_REQUEST_FINALIZED_BATCH_SIZE,
        ::metrics::Unit::Count,
        "Number of requests resolved per finalization event."
    );

    ::metrics::describe_counter!(
        METRICS_SWEEPER_CLEANED,
        ::metrics::Unit::Count,
        "Number of requests cleaned up by the orphan sweeper."
    );
    ::metrics::describe_gauge!(
        METRICS_SWEEPER_PENDING_COUNT,
        ::metrics::Unit::Count,
        "Number of requests in the pending set at the start of each sweep pass."
    );
}

pub fn record_http_latency_ms(path: &str, status: u16, latency_ms: f64) {
    let status_class = match status / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    };

    ::metrics::histogram!(
        METRICS_HTTP_LATENCY_MS,
        "route" => normalize_path(path),
        "status_class" => status_class
    )
    .record(latency_ms);
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

pub fn record_batch_result(batch_type: &'static str, success: bool, latency_ms: f64) {
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

pub fn record_simulation_latency_ms(kind: &'static str, latency_ms: f64) {
    ::metrics::histogram!(METRICS_SIMULATION_LATENCY_MS, "kind" => kind).record(latency_ms);
}

pub fn increment_simulation_failure(kind: &'static str) {
    ::metrics::counter!(METRICS_SIMULATION_FAILURE, "kind" => kind).increment(1);
}

pub fn record_receipt_confirmation_latency_ms(batch_type: &'static str, latency_ms: f64) {
    ::metrics::histogram!(METRICS_RECEIPT_CONFIRMATION_LATENCY_MS, "type" => batch_type)
        .record(latency_ms);
}

pub fn increment_receipt_failure() {
    ::metrics::counter!(METRICS_RECEIPT_FAILURE).increment(1);
}

pub fn record_request_finalized(outcome: &'static str, count: usize) {
    ::metrics::counter!(METRICS_REQUEST_FINALIZED, "outcome" => outcome).increment(count as u64);
    ::metrics::histogram!(METRICS_REQUEST_FINALIZED_BATCH_SIZE, "outcome" => outcome)
        .record(count as f64);
}

pub fn set_sweeper_pending_count(count: usize) {
    ::metrics::gauge!(METRICS_SWEEPER_PENDING_COUNT).set(count as f64);
}

pub fn increment_sweeper_cleaned(reason: &'static str) {
    ::metrics::counter!(METRICS_SWEEPER_CLEANED, "reason" => reason).increment(1);
}

fn normalize_path(path: &str) -> String {
    // Replace dynamic segments like /status/{id} with /status/:id
    if path.starts_with("/status/") {
        return "/status/:id".to_string();
    }
    path.to_string()
}
