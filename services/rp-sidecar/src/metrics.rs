//! Metric names and descriptions.

/// Verifications by `result` (`accepted`, `invalid`, `rejected`, `unavailable`, `internal`,
/// `abandoned`) and `code`, which is `accepted` or `abandoned` for those two results.
pub const METRICS_EMBEDDING_SIMILARITY_VERIFICATIONS: &str = "embedding_similarity.verifications";

/// The duration of the zero-knowledge proof verification alone, which sizes the container.
pub const METRICS_EMBEDDING_SIMILARITY_PROOF_VERIFICATION_MS: &str =
    "embedding_similarity.proof_verification_ms";

/// Describes the sidecar's metrics to the installed recorder.
pub fn describe_metrics() {
    ::metrics::describe_counter!(
        METRICS_EMBEDDING_SIMILARITY_VERIFICATIONS,
        ::metrics::Unit::Count,
        "Proof of Embedding Similarity verifications, by result and code."
    );
    ::metrics::describe_histogram!(
        METRICS_EMBEDDING_SIMILARITY_PROOF_VERIFICATION_MS,
        ::metrics::Unit::Milliseconds,
        "Duration of the zero-knowledge proof verification of a Proof of Embedding Similarity."
    );
    world_id_services_common::describe_http_request_metrics();
    world_id_services_common::describe_provider_transport_metrics();
}
