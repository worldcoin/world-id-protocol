//! Metric names and descriptions.

/// Verifications by `result` (`accepted`, `invalid`, `rejected`, `unavailable`, `internal`) and
/// `code`.
pub const METRICS_EMBEDDING_SIMILARITY_VERIFICATIONS: &str = "embedding_similarity.verifications";

/// Describes the sidecar's metrics to the installed recorder.
pub fn describe_metrics() {
    ::metrics::describe_counter!(
        METRICS_EMBEDDING_SIMILARITY_VERIFICATIONS,
        ::metrics::Unit::Count,
        "Proof of Embedding Similarity verifications, by result and code."
    );
    world_id_services_common::describe_http_request_metrics();
    world_id_services_common::describe_provider_transport_metrics();
}
