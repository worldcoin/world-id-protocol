pub const METRICS_EVENTS_EMITTED: &str = "event_watcher.events_emitted";
pub const METRICS_LAST_EVENT_BLOCK: &str = "event_watcher.last_event_block";

pub fn describe_metrics() {
    ::metrics::describe_counter!(
        METRICS_EVENTS_EMITTED,
        ::metrics::Unit::Count,
        "Number of decoded on-chain events emitted by the watcher."
    );
    ::metrics::describe_gauge!(
        METRICS_LAST_EVENT_BLOCK,
        ::metrics::Unit::Count,
        "Latest block number for an emitted event."
    );
}

pub fn increment_events_emitted(name: &str, event_name: &str) {
    ::metrics::counter!(METRICS_EVENTS_EMITTED, "name" => name.to_owned(), "event_name" => event_name.to_owned())
        .increment(1);
}

pub fn set_last_event_block(name: &str, event_name: &str, block_number: u64) {
    ::metrics::gauge!(METRICS_LAST_EVENT_BLOCK, "name" => name.to_owned(), "event_name" => event_name.to_owned())
        .set(block_number as f64);
}

