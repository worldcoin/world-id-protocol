//! Metrics definitions for the world-id-gateway.

// Request metrics
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
pub const METRICS_BATCH_POLICY_COST_SCORE: &str = "gateway.batch.policy.cost_score";
pub const METRICS_BATCH_POLICY_URGENCY_SCORE: &str = "gateway.batch.policy.urgency_score";
pub const METRICS_BATCH_POLICY_DEFER: &str = "gateway.batch.policy.defer";
pub const METRICS_BATCH_POLICY_FORCE_SEND: &str = "gateway.batch.policy.force_send";
pub const METRICS_BATCH_POLICY_TARGET_SIZE: &str = "gateway.batch.policy.target_size";
