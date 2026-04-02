//! Metrics definitions for the world-id-oprf-node.
//!
//! This module defines all metrics keys used by the service and
//! provides a helper [`describe_metrics`] to set metadata for
//! each metric using the `metrics` crate.

/// Number of stored nonces in the nonce history.
pub const METRICS_ID_NODE_NONCE_HISTORY_SIZE: &str = "taceo.oprf.node.nonce_history.size";
/// Number of stored roots in the `merkle_watcher` cache.
pub const METRICS_ID_NODE_MERKLE_WATCHER_CACHE_SIZE: &str =
    "taceo.oprf.node.merkle_watcher_cache.size";
/// Number hits in the `merkle_watcher` cache.
pub const METRICS_ID_NODE_MERKLE_WATCHER_CACHE_HITS: &str =
    "taceo.oprf.node.merkle_watcher_cache.hits";
/// Number misses in the `merkle_watcher` cache.
pub const METRICS_ID_NODE_MERKLE_WATCHER_CACHE_MISSES: &str =
    "taceo.oprf.node.merkle_watcher_cache.misses";
/// Number of stored RPs in the `rp_registry_watcher` cache.
pub const METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE: &str =
    "taceo.oprf.node.rp_registry_watcher_cache.size";

/// Number of stored RPs with an EOA signer.
pub const METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_EOA_ACCOUNTS: &str =
    "taceo.oprf.node.rp_registry_watcher_cache.account.eoa";

/// Number of stored RPs with a contract backed signer.
pub const METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_CONTRACT_ACCOUNTS: &str =
    "taceo.oprf.node.rp_registry_watcher_cache.account.contract";

/// Number of stored RPs with a contract backed signer, that does not confirm to WIP101.
pub const METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_CONTRACT_ACCOUNTS_BUT_UNSUPPORTED: &str =
    "taceo.oprf.node.rp_registry_watcher_cache.account.unsupported";

/// Number of hits in the `rp_registry_watcher` cache.
pub const METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_HITS: &str =
    "taceo.oprf.node.rp_registry_watcher_cache.hits";
/// Number of misses in the `rp_registry_watcher` cache.
pub const METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_MISSES: &str =
    "taceo.oprf.node.rp_registry_watcher_cache.misses";
/// Number of stored schema issuers in the `schema_issuer_registry_watcher` cache.
pub const METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_SIZE: &str =
    "taceo.oprf.node.schema_issuer_registry_watcher_cache.size";
/// Number of hits in the `schema_issuer_registry_watcher` cache.
pub const METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_HITS: &str =
    "taceo.oprf.node.schema_issuer_registry_watcher_cache.hits";
/// Number of misses in the `schema_issuer_registry_watcher` cache.
pub const METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_MISSES: &str =
    "taceo.oprf.node.schema_issuer_registry_watcher_cache.misses";

/// Describe all metrics used by the service.
///
/// This calls the `describe_*` functions from the `metrics` crate to set metadata on the different metrics.
pub fn describe_metrics() {
    metrics::describe_gauge!(
        METRICS_ID_NODE_NONCE_HISTORY_SIZE,
        metrics::Unit::Count,
        "Number of stored nonces in the nonce history."
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
        METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_EOA_ACCOUNTS,
        metrics::Unit::Count,
        "Number of cached RPs with an EOA signer."
    );

    metrics::describe_gauge!(
        METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_CONTRACT_ACCOUNTS,
        metrics::Unit::Count,
        "Number of cached RPs with a WIP101-compliant contract signer."
    );

    metrics::describe_gauge!(
        METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_CONTRACT_ACCOUNTS_BUT_UNSUPPORTED,
        metrics::Unit::Count,
        "Number of cached RPs with a contract signer that does not conform to WIP101."
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
