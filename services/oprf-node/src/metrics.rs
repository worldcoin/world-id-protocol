//! Metrics definitions for the world-id-oprf-node.
//!
//! This module defines all metrics keys used by the service and
//! provides a helper [`describe_metrics`] to set metadata for
//! each metric using the `metrics` crate.

/// Attribute ID attached to `METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE`* metrics distinguishing the RP signer type: `EOA`, `contract` vs `unsupported`
pub(crate) const METRICS_ATTRID_RP_TYPE: &str = "type";

/// Attribute value for `METRICS_ATTRID_RP_TYPE` describing an `EOA` signer.
pub(crate) const METRICS_ATTRVAL_RP_TYPE_EOA: &str = "eoa";
/// Attribute value for `METRICS_ATTRID_RP_TYPE` describing an wip101 `CONTRACT` signer.
pub(crate) const METRICS_ATTRVAL_RP_TYPE_CONTRACT: &str = "contract";
/// Attribute value for `METRICS_ATTRID_RP_TYPE` describing an `INCOMPATIBLE_WIP101_CONTRACT` signer. This means that the signer is a deployed contract but does not conform to wip101.
pub(crate) const METRICS_ATTRVAL_RP_TYPE_INCOMPATIBLE_WIP101_CONTRACT: &str = "incompatible_wip101";

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
/// Number of misses in the `rp_registry_watcher` cache.
pub const METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_MISSES: &str =
    "taceo.oprf.node.rp_registry_watcher_cache.misses";
/// Number of hits in the `rp_registry_watcher` cache.
pub const METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_HITS: &str =
    "taceo.oprf.node.rp_registry_watcher_cache.hits";

/// Number of stored schema issuers in the `schema_issuer_registry_watcher` cache.
pub const METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_SIZE: &str =
    "taceo.oprf.node.schema_issuer_registry_watcher_cache.size";
/// Number of misses in the `schema_issuer_registry_watcher` cache.
pub const METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_MISSES: &str =
    "taceo.oprf.node.schema_issuer_registry_watcher_cache.misses";

/// Number of hits in the `schema_issuer_registry_watcher` cache.
pub const METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_HITS: &str =
    "taceo.oprf.node.schema_issuer_registry_watcher_cache.hits";

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
        METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_MISSES,
        metrics::Unit::Count,
        "Number of misses in the rp_registry_watcher cache."
    );

    metrics::describe_counter!(
        METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_HITS,
        metrics::Unit::Count,
        "Number of hits in the rp_registry_watcher cache."
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
