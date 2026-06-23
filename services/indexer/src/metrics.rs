//! Metrics definitions and helpers for the world-id-indexer.

pub const METRICS_CHAIN_HEAD_BLOCK: &str = "chain.head_block";
pub const METRICS_CHAIN_PROCESSED_BLOCK: &str = "chain.processed_block";

pub const METRICS_EVENTS_COMMIT_BATCH_SIZE: &str = "events.commit_batch_size";
pub const METRICS_EVENTS_COMMIT_LATENCY_MS: &str = "events.commit_latency_ms";

pub const METRICS_TREE_SYNC_LATENCY_MS: &str = "tree.sync_latency_ms";
pub const METRICS_TREE_SYNC_EVENTS: &str = "tree.sync_events";
pub const METRICS_TREE_LAST_SYNCED_BLOCK: &str = "tree.last_synced_block";

pub use world_id_services_common::METRICS_HTTP_LATENCY_MS;

pub fn describe_metrics() {
    ::metrics::describe_gauge!(
        METRICS_CHAIN_HEAD_BLOCK,
        ::metrics::Unit::Count,
        "Latest observed chain head block number."
    );
    ::metrics::describe_gauge!(
        METRICS_CHAIN_PROCESSED_BLOCK,
        ::metrics::Unit::Count,
        "Latest processed block number by the indexer."
    );
    ::metrics::describe_histogram!(
        METRICS_EVENTS_COMMIT_BATCH_SIZE,
        ::metrics::Unit::Count,
        "Number of buffered events committed per DB transaction."
    );
    ::metrics::describe_histogram!(
        METRICS_EVENTS_COMMIT_LATENCY_MS,
        ::metrics::Unit::Milliseconds,
        "Latency of committing an event batch to DB."
    );

    ::metrics::describe_histogram!(
        METRICS_TREE_SYNC_LATENCY_MS,
        ::metrics::Unit::Milliseconds,
        "Latency of a single tree sync iteration from DB."
    );
    ::metrics::describe_histogram!(
        METRICS_TREE_SYNC_EVENTS,
        ::metrics::Unit::Count,
        "Number of events consumed in a tree sync iteration."
    );
    ::metrics::describe_gauge!(
        METRICS_TREE_LAST_SYNCED_BLOCK,
        ::metrics::Unit::Count,
        "Block number of the last DB event synced into the tree."
    );

    world_id_services_common::describe_http_request_metrics();

    world_id_services_common::describe_provider_transport_metrics();
}

pub fn set_chain_head_block(block_number: u64) {
    ::metrics::gauge!(METRICS_CHAIN_HEAD_BLOCK).set(block_number as f64);
}

pub fn set_chain_processed_block(block_number: u64) {
    ::metrics::gauge!(METRICS_CHAIN_PROCESSED_BLOCK).set(block_number as f64);
}

pub fn record_commit(batch_size: usize, latency_ms: f64) {
    ::metrics::histogram!(METRICS_EVENTS_COMMIT_BATCH_SIZE).record(batch_size as f64);
    ::metrics::histogram!(METRICS_EVENTS_COMMIT_LATENCY_MS).record(latency_ms);
}

pub fn record_tree_sync(events: usize, latency_ms: f64, last_synced_block: u64) {
    ::metrics::histogram!(METRICS_TREE_SYNC_EVENTS).record(events as f64);
    ::metrics::histogram!(METRICS_TREE_SYNC_LATENCY_MS).record(latency_ms);
    set_tree_last_synced_block(last_synced_block);
    set_chain_processed_block(last_synced_block);
}

pub fn set_tree_last_synced_block(block_number: u64) {
    ::metrics::gauge!(METRICS_TREE_LAST_SYNCED_BLOCK).set(block_number as f64);
}
