//! Metrics definitions for the world-id-oprf-node.
//!
//! This module defines all metrics keys used by the service and
//! provides a helper [`describe_metrics`] to set metadata for
//! each metric using the `metrics` crate.

/// Describe all metrics used by the service.
///
/// This calls the `describe_*` functions from the `metrics` crate to set metadata on the different metrics.
pub fn describe_metrics() {
    auth_module::describe_metrics();
    nonce_history::describe_metrics();
    merkle_cache::describe_metrics();
    rp_registry_cache::describe_metrics();
    schema_issuer_cache::describe_metrics();

    taceo_oprf::service::metrics::describe_metrics();
}

pub(crate) mod auth_module {

    const METRICS_ID_AUTHENTICATION_COUNTER: &str = "taceo.oprf.node.auth";
    const METRICS_ATTRID_AUTH_MODULE: &str = "auth_module";
    const METRICS_ATTR_NULLIFIER_MODULE: &str = "nullifier";
    const METRICS_ATTR_SESSION_MODULE: &str = "session";
    const METRICS_ATTR_CREDENTIAL_BLINDING: &str = "blinding";

    pub(super) fn describe_metrics() {
        metrics::describe_counter!(
            METRICS_ID_AUTHENTICATION_COUNTER,
            metrics::Unit::Count,
            "Number of times the authentication modules were hit."
        );
    }

    pub(crate) fn inc_nullifier() {
        metrics::counter!(METRICS_ID_AUTHENTICATION_COUNTER, METRICS_ATTRID_AUTH_MODULE => METRICS_ATTR_NULLIFIER_MODULE).increment(1);
    }

    pub(crate) fn inc_session() {
        metrics::counter!(METRICS_ID_AUTHENTICATION_COUNTER, METRICS_ATTRID_AUTH_MODULE => METRICS_ATTR_SESSION_MODULE).increment(1);
    }

    pub(crate) fn inc_issuer_blinding() {
        metrics::counter!(METRICS_ID_AUTHENTICATION_COUNTER, METRICS_ATTRID_AUTH_MODULE => METRICS_ATTR_CREDENTIAL_BLINDING).increment(1);
    }
}

pub(crate) mod nonce_history {

    /// Number of stored nonces in the nonce history.
    const METRICS_ID_NODE_NONCE_HISTORY_SIZE: &str = "taceo.oprf.node.nonce_history.size";

    pub(super) fn describe_metrics() {
        metrics::describe_gauge!(
            METRICS_ID_NODE_NONCE_HISTORY_SIZE,
            metrics::Unit::Count,
            "Number of stored nonces in the nonce history."
        );
    }

    pub(crate) fn reset() {
        metrics::gauge!(METRICS_ID_NODE_NONCE_HISTORY_SIZE).set(0.0);
    }

    pub(crate) fn inc() {
        metrics::gauge!(METRICS_ID_NODE_NONCE_HISTORY_SIZE).increment(1);
    }

    pub(crate) fn dec() {
        metrics::gauge!(METRICS_ID_NODE_NONCE_HISTORY_SIZE).decrement(1);
    }
}

pub(crate) mod merkle_cache {

    /// Number of stored roots in the `merkle_watcher` cache.
    const METRICS_ID_NODE_MERKLE_WATCHER_CACHE_SIZE: &str =
        "taceo.oprf.node.merkle_watcher_cache.size";
    /// Number hits in the `merkle_watcher` cache.
    const METRICS_ID_NODE_MERKLE_WATCHER_CACHE_HITS: &str =
        "taceo.oprf.node.merkle_watcher_cache.hits";
    /// Number misses in the `merkle_watcher` cache.
    const METRICS_ID_NODE_MERKLE_WATCHER_CACHE_MISSES: &str =
        "taceo.oprf.node.merkle_watcher_cache.misses";

    pub(super) fn describe_metrics() {
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
    }

    pub(crate) fn set(val: u64) {
        metrics::gauge!(METRICS_ID_NODE_MERKLE_WATCHER_CACHE_SIZE).set(val as f64);
    }

    pub(crate) fn hit() {
        metrics::counter!(METRICS_ID_NODE_MERKLE_WATCHER_CACHE_HITS).increment(1);
    }

    pub(crate) fn miss() {
        metrics::counter!(METRICS_ID_NODE_MERKLE_WATCHER_CACHE_MISSES).increment(1);
    }
}

pub(crate) mod rp_registry_cache {

    /// Number of stored RPs in the `rp_registry_watcher` cache.
    const METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE: &str =
        "taceo.oprf.node.rp_registry_watcher_cache.size";
    /// Number of misses in the `rp_registry_watcher` cache.
    const METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_MISSES: &str =
        "taceo.oprf.node.rp_registry_watcher_cache.misses";
    /// Number of hits in the `rp_registry_watcher` cache.
    const METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_HITS: &str =
        "taceo.oprf.node.rp_registry_watcher_cache.hits";
    /// Number of event-driven invalidations of the `rp_registry_watcher` cache.
    const METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_INVALIDATIONS: &str =
        "taceo.oprf.node.rp_registry_watcher_cache.invalidations";
    /// Highest block scanned by the `RpUpdated` invalidation poller.
    const METRICS_ID_NODE_RP_REGISTRY_WATCHER_LAST_POLLED_BLOCK: &str =
        "taceo.oprf.node.rp_registry_watcher_cache.last_polled_block";

    pub(super) fn describe_metrics() {
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

        metrics::describe_counter!(
            METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_INVALIDATIONS,
            metrics::Unit::Count,
            "Number of cache entries invalidated in response to on-chain RpUpdated events."
        );

        metrics::describe_gauge!(
            METRICS_ID_NODE_RP_REGISTRY_WATCHER_LAST_POLLED_BLOCK,
            metrics::Unit::Count,
            "Highest block scanned by the RpUpdated invalidation poller. Alert if this stops advancing."
        );
    }

    pub(crate) fn set(val: u64) {
        metrics::gauge!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE).set(val as f64);
    }

    pub(crate) fn hit() {
        metrics::counter!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_HITS).increment(1);
    }

    pub(crate) fn miss() {
        metrics::counter!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_MISSES).increment(1);
    }

    pub(crate) fn invalidation() {
        metrics::counter!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_INVALIDATIONS).increment(1);
    }

    pub(crate) fn set_last_polled_block(block: u64) {
        metrics::gauge!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_LAST_POLLED_BLOCK).set(block as f64);
    }
}

pub(crate) mod schema_issuer_cache {

    /// Number of stored schema issuers in the `schema_issuer_registry_watcher` cache.
    const METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_SIZE: &str =
        "taceo.oprf.node.schema_issuer_registry_watcher_cache.size";
    /// Number of misses in the `schema_issuer_registry_watcher` cache.
    const METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_MISSES: &str =
        "taceo.oprf.node.schema_issuer_registry_watcher_cache.misses";

    /// Number of hits in the `schema_issuer_registry_watcher` cache.
    const METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_HITS: &str =
        "taceo.oprf.node.schema_issuer_registry_watcher_cache.hits";

    pub(super) fn describe_metrics() {
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

    pub(crate) fn set(val: u64) {
        metrics::gauge!(METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_SIZE).set(val as f64);
    }

    pub(crate) fn hit() {
        metrics::counter!(METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_HITS).increment(1);
    }

    pub(crate) fn miss() {
        metrics::counter!(METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_MISSES).increment(1);
    }
}
