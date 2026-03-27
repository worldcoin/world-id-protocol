pub const METRICS_EVENTS_EMITTED: &str = "event_watcher.events_emitted";
pub const METRICS_RPC_ERRORS: &str = "event_watcher.rpc_errors";
pub const METRICS_DECODE_ERRORS: &str = "event_watcher.decode_errors";
pub const METRICS_RECONNECTS: &str = "event_watcher.reconnects";
pub const METRICS_SUBSCRIPTION_UPTIME_SECS: &str = "event_watcher.subscription_uptime_secs";
pub const METRICS_LAST_EVENT_BLOCK: &str = "event_watcher.last_event_block";
pub const METRICS_CONNECTED: &str = "event_watcher.connected";
pub const METRICS_EVENTS_DROPPED_REMOVED: &str = "event_watcher.events_dropped_removed";
pub const METRICS_WATCHER_RESTARTS: &str = "event_watcher.watcher_restarts";

pub fn describe_metrics() {
    ::metrics::describe_counter!(
        METRICS_EVENTS_EMITTED,
        ::metrics::Unit::Count,
        "Number of decoded on-chain events emitted by the watcher."
    );
    ::metrics::describe_counter!(
        METRICS_RPC_ERRORS,
        ::metrics::Unit::Count,
        "Number of runtime RPC/subscription errors."
    );
    ::metrics::describe_counter!(
        METRICS_DECODE_ERRORS,
        ::metrics::Unit::Count,
        "Number of log decode errors."
    );
    ::metrics::describe_counter!(
        METRICS_RECONNECTS,
        ::metrics::Unit::Count,
        "Number of subscription reconnect attempts."
    );
    ::metrics::describe_gauge!(
        METRICS_SUBSCRIPTION_UPTIME_SECS,
        ::metrics::Unit::Seconds,
        "Uptime of the active websocket subscription in seconds."
    );
    ::metrics::describe_gauge!(
        METRICS_LAST_EVENT_BLOCK,
        ::metrics::Unit::Count,
        "Latest block number for an emitted event."
    );
    ::metrics::describe_gauge!(
        METRICS_CONNECTED,
        ::metrics::Unit::Count,
        "Whether the watcher is currently connected (1) or disconnected (0)."
    );
    ::metrics::describe_counter!(
        METRICS_EVENTS_DROPPED_REMOVED,
        ::metrics::Unit::Count,
        "Number of removed logs ignored by the watcher."
    );
    ::metrics::describe_counter!(
        METRICS_WATCHER_RESTARTS,
        ::metrics::Unit::Count,
        "Number of times a subscription task was restarted by the supervisor."
    );
}

pub fn increment_events_emitted(event_name: &str) {
    ::metrics::counter!(METRICS_EVENTS_EMITTED, "event_name" => event_name.to_owned()).increment(1);
}

pub fn increment_rpc_error(event_name: &str, method: &str) {
    ::metrics::counter!(METRICS_RPC_ERRORS, "event_name" => event_name.to_owned(), "method" => method.to_owned())
        .increment(1);
}

pub fn increment_decode_error(event_name: &str) {
    ::metrics::counter!(METRICS_DECODE_ERRORS, "event_name" => event_name.to_owned()).increment(1);
}

pub fn increment_reconnect(event_name: &str, reason: &str) {
    ::metrics::counter!(METRICS_RECONNECTS, "event_name" => event_name.to_owned(), "reason" => reason.to_owned())
        .increment(1);
}

pub fn set_subscription_uptime(event_name: &str, seconds: f64) {
    ::metrics::gauge!(METRICS_SUBSCRIPTION_UPTIME_SECS, "event_name" => event_name.to_owned())
        .set(seconds);
}

pub fn set_last_event_block(event_name: &str, block_number: u64) {
    ::metrics::gauge!(METRICS_LAST_EVENT_BLOCK, "event_name" => event_name.to_owned())
        .set(block_number as f64);
}

pub fn set_connected(event_name: &str, connected: bool) {
    ::metrics::gauge!(METRICS_CONNECTED, "event_name" => event_name.to_owned()).set(if connected {
        1.0
    } else {
        0.0
    });
}

pub fn increment_events_dropped_removed(event_name: &str) {
    ::metrics::counter!(METRICS_EVENTS_DROPPED_REMOVED, "event_name" => event_name.to_owned())
        .increment(1);
}

pub fn increment_watcher_restart(event_name: &str) {
    ::metrics::counter!(METRICS_WATCHER_RESTARTS, "event_name" => event_name.to_owned())
        .increment(1);
}
