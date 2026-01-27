//! Metrics definitions for the world-id-gateway.

// Request metrics
pub const METRICS_REQUESTS_TOTAL: &str = "gateway.requests.total";
pub const METRICS_REQUESTS_SUCCESS: &str = "gateway.requests.success";
pub const METRICS_REQUESTS_ERROR: &str = "gateway.requests.error";
pub const METRICS_REQUESTS_LATENCY_MS: &str = "gateway.requests.latency_ms";

// Root cache metrics
pub const METRICS_ROOT_CACHE_HITS: &str = "gateway.root_cache.hits";
pub const METRICS_ROOT_CACHE_MISSES: &str = "gateway.root_cache.misses";

// Batcher metrics
pub const METRICS_BATCH_SUBMITTED: &str = "gateway.batch.submitted";
pub const METRICS_BATCH_SIZE: &str = "gateway.batch.size";
pub const METRICS_BATCH_LATENCY_MS: &str = "gateway.batch.latency_ms";
pub const METRICS_BATCH_SUCCESS: &str = "gateway.batch.success";
pub const METRICS_BATCH_FAILURE: &str = "gateway.batch.failure";

pub fn describe_metrics() {
    metrics::describe_counter!(
        METRICS_REQUESTS_TOTAL,
        metrics::Unit::Count,
        "Total number of requests received by endpoint"
    );

    metrics::describe_counter!(
        METRICS_REQUESTS_SUCCESS,
        metrics::Unit::Count,
        "Number of successful requests by endpoint"
    );

    metrics::describe_counter!(
        METRICS_REQUESTS_ERROR,
        metrics::Unit::Count,
        "Number of failed requests by endpoint"
    );

    metrics::describe_counter!(
        METRICS_ROOT_CACHE_HITS,
        metrics::Unit::Count,
        "Number of root validation cache hits"
    );

    metrics::describe_counter!(
        METRICS_ROOT_CACHE_MISSES,
        metrics::Unit::Count,
        "Number of root validation cache misses"
    );

    // Request latency
    metrics::describe_histogram!(
        METRICS_REQUESTS_LATENCY_MS,
        metrics::Unit::Milliseconds,
        "Request latency in milliseconds by endpoint"
    );

    // Batcher metrics
    metrics::describe_counter!(
        METRICS_BATCH_SUBMITTED,
        metrics::Unit::Count,
        "Number of batches submitted by type"
    );

    metrics::describe_histogram!(
        METRICS_BATCH_SIZE,
        metrics::Unit::Count,
        "Number of requests per batch by type"
    );

    metrics::describe_histogram!(
        METRICS_BATCH_LATENCY_MS,
        metrics::Unit::Milliseconds,
        "Batch submission latency in milliseconds by type"
    );

    metrics::describe_counter!(
        METRICS_BATCH_SUCCESS,
        metrics::Unit::Count,
        "Number of successful batch submissions by type"
    );

    metrics::describe_counter!(
        METRICS_BATCH_FAILURE,
        metrics::Unit::Count,
        "Number of failed batch submissions by type"
    );
}
