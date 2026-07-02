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
    request_tracking::describe_metrics();

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

    pub(crate) fn set(val: u64) {
        metrics::gauge!(METRICS_ID_NODE_NONCE_HISTORY_SIZE).set(val as f64);
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
}

pub(crate) mod request_tracking {

    /// Number of authenticated RP requests handed to the request tracker.
    const METRICS_ID_NODE_REQUEST_TRACKING_TRACKED: &str = "taceo.oprf.node.request_tracking.tracked";
    /// Number of request-tracking records dropped before being persisted.
    const METRICS_ID_NODE_REQUEST_TRACKING_DROPPED: &str = "taceo.oprf.node.request_tracking.dropped";
    const METRICS_ATTRID_MODULE: &str = "auth_module";
    const METRICS_ATTRID_DROP_REASON: &str = "reason";

    /// Drop reason: the in-memory queue to the database writer was full.
    pub(crate) const DROP_REASON_QUEUE_FULL: &str = "queue_full";
    /// Drop reason: the batch insert failed after exhausting all retries.
    pub(crate) const DROP_REASON_DB_ERROR: &str = "db_error";

    pub(super) fn describe_metrics() {
        metrics::describe_counter!(
            METRICS_ID_NODE_REQUEST_TRACKING_TRACKED,
            metrics::Unit::Count,
            "Number of authenticated RP requests handed to the request tracker."
        );

        metrics::describe_counter!(
            METRICS_ID_NODE_REQUEST_TRACKING_DROPPED,
            metrics::Unit::Count,
            "Number of request-tracking records dropped before being persisted (by reason)."
        );
    }

    pub(crate) fn inc_tracked(module: &'static str) {
        metrics::counter!(METRICS_ID_NODE_REQUEST_TRACKING_TRACKED, METRICS_ATTRID_MODULE => module)
            .increment(1);
    }

    pub(crate) fn inc_dropped(reason: &'static str, count: u64) {
        metrics::counter!(METRICS_ID_NODE_REQUEST_TRACKING_DROPPED, METRICS_ATTRID_DROP_REASON => reason)
            .increment(count);
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
