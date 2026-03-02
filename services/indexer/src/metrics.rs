//! Metrics definitions and helpers for the world-id-indexer.

pub const METRICS_CHAIN_HEAD_BLOCK: &str = "indexer.chain.head_block";
pub const METRICS_CHAIN_PROCESSED_BLOCK: &str = "indexer.chain.processed_block";

pub const METRICS_EVENTS_COMMIT_BATCH_SIZE: &str = "indexer.events.commit_batch_size";
pub const METRICS_EVENTS_COMMIT_LATENCY_MS: &str = "indexer.events.commit_latency_ms";

pub const METRICS_TREE_SYNC_LATENCY_MS: &str = "indexer.tree.sync_latency_ms";
pub const METRICS_TREE_SYNC_EVENTS: &str = "indexer.tree.sync_events";
pub const METRICS_TREE_LAST_SYNCED_BLOCK: &str = "indexer.tree.last_synced_block";

pub const METRICS_WS_RECONNECTS: &str = "indexer.ws.reconnects";

pub const METRICS_HTTP_LATENCY_MS: &str = "indexer.http.latency_ms";

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

    ::metrics::describe_counter!(
        METRICS_WS_RECONNECTS,
        ::metrics::Unit::Count,
        "Number of blockchain stream reconnect attempts."
    );

    ::metrics::describe_histogram!(
        METRICS_HTTP_LATENCY_MS,
        ::metrics::Unit::Milliseconds,
        "HTTP request latency in milliseconds."
    );
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

pub fn increment_ws_reconnects() {
    ::metrics::counter!(METRICS_WS_RECONNECTS).increment(1);
}

pub fn record_http_latency_ms(route: &str, status: u16, latency_ms: f64) {
    let status_class = match status / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    };

    ::metrics::histogram!(
        METRICS_HTTP_LATENCY_MS,
        "route" => route.to_string(),
        "status_class" => status_class
    )
    .record(latency_ms);
}
