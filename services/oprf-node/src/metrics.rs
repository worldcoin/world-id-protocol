//! Metrics definitions for the world-id-oprf-node.
//!
//! This module defines all metrics keys used by the service and
//! provides a helper [`describe_metrics`] to set metadata for
//! each metric using the `metrics` crate.

/// Observed event for start of OprfRequest authentication.
pub const METRICS_ID_NODE_REQUEST_AUTH_START: &str = "taceo.oprf.node.request_auth.start";
/// Observed event for successful verification of OprfRequest authentication.
pub const METRICS_ID_NODE_REQUEST_AUTH_VERIFIED: &str = "taceo.oprf.node.request_auth.verified";
/// Number of stored signatures in the signature history.
pub const METRICS_ID_NODE_SIGNATURE_HISTORY_SIZE: &str = "taceo.oprf.node.signature_history.size";
/// Number of stored roots in the merkle_watcher cache.
pub const METRICS_ID_NODE_MERKLE_WATCHER_CACHE_SIZE: &str =
    "taceo.oprf.node.merkle_watcher_cache.size";
/// Number hits in the merkle_watcher cache.
pub const METRICS_ID_NODE_MERKLE_WATCHER_CACHE_HITS: &str =
    "taceo.oprf.node.merkle_watcher_cache.hits";
/// Number misses in the merkle_watcher cache.
pub const METRICS_ID_NODE_MERKLE_WATCHER_CACHE_MISSES: &str =
    "taceo.oprf.node.merkle_watcher_cache.misses";
/// Number of stored RPs in the rp_registry_watcher cache.
pub const METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE: &str =
    "taceo.oprf.node.rp_registry_watcher_cache.size";
/// Number of hits in the rp_registry_watcher cache.
pub const METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_HITS: &str =
    "taceo.oprf.node.rp_registry_watcher_cache.hits";
/// Number of misses in the rp_registry_watcher cache.
pub const METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_MISSES: &str =
    "taceo.oprf.node.rp_registry_watcher_cache.misses";
/// Number of stored schema issuers in the schema_issuer_registry_watcher cache.
pub const METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_SIZE: &str =
    "taceo.oprf.node.schema_issuer_registry_watcher_cache.size";
/// Number of hits in the schema_issuer_registry_watcher cache.
pub const METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_HITS: &str =
    "taceo.oprf.node.schema_issuer_registry_watcher_cache.hits";
/// Number of misses in the schema_issuer_registry_watcher cache.
pub const METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_MISSES: &str =
    "taceo.oprf.node.schema_issuer_registry_watcher_cache.misses";

/// Describe all metrics used by the service.
///
/// This calls the `describe_*` functions from the `metrics` crate to set metadata on the different metrics.
pub fn describe_metrics() {
    metrics::describe_counter!(
        METRICS_ID_NODE_REQUEST_AUTH_START,
        metrics::Unit::Count,
        "Number of OPRF request authentication attempts started."
    );

    metrics::describe_counter!(
        METRICS_ID_NODE_REQUEST_AUTH_VERIFIED,
        metrics::Unit::Count,
        "Number of OPRF request authentications successfully verified."
    );

    metrics::describe_gauge!(
        METRICS_ID_NODE_SIGNATURE_HISTORY_SIZE,
        metrics::Unit::Count,
        "Number of stored signatures in the signature history."
    );

    metrics::describe_gauge!(
        METRICS_ID_NODE_MERKLE_WATCHER_CACHE_SIZE,
        metrics::Unit::Count,
        "Number of stored roots in the merkle_watcher cache."
    );

    metrics::describe_counter!(
        METRICS_ID_NODE_MERKLE_WATCHER_CACHE_HITS,
        metrics::Unit::Count,
        "Number of hits in the merkle_watcher cache."
    );

    metrics::describe_counter!(
        METRICS_ID_NODE_MERKLE_WATCHER_CACHE_MISSES,
        metrics::Unit::Count,
        "Number of misses in the merkle_watcher cache."
    );

    metrics::describe_gauge!(
        METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE,
        metrics::Unit::Count,
        "Number of stored RPs in the rp_registry_watcher cache."
    );

    metrics::describe_counter!(
        METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_HITS,
        metrics::Unit::Count,
        "Number of hits in the rp_registry_watcher cache."
    );

    metrics::describe_counter!(
        METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_MISSES,
        metrics::Unit::Count,
        "Number of misses in the rp_registry_watcher cache."
    );

    metrics::describe_gauge!(
        METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_SIZE,
        metrics::Unit::Count,
        "Number of stored schema issuers in the schema_issuer_registry_watcher cache."
    );

    metrics::describe_counter!(
        METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_HITS,
        metrics::Unit::Count,
        "Number of hits in the schema_issuer_registry_watcher cache."
    );

    metrics::describe_counter!(
        METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_MISSES,
        metrics::Unit::Count,
        "Number of misses in the schema_issuer_registry_watcher cache."
    );
}
