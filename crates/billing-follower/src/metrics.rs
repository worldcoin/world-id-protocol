//! Metrics, through the `metrics` facade. They reach a backend once the consumer installs a
//! recorder.

pub const HEAD_BLOCK: &str = "billing_follower.head_block";
pub const SYNCED_BLOCK: &str = "billing_follower.synced_block";
pub const RPC_ERRORS: &str = "billing_follower.rpc_errors";
pub const REORGS: &str = "billing_follower.reorgs";
pub const REORG_DEPTH: &str = "billing_follower.reorg_depth";
pub const RESETS: &str = "billing_follower.resets";
pub const INVALID_EVENTS: &str = "billing_follower.invalid_events";
pub const REGISTRATIONS: &str = "billing_follower.registrations";
pub const BILLED_RPS: &str = "billing_follower.billed_rps";
pub const BACKFILL_SECONDS: &str = "billing_follower.backfill_seconds";

/// A gauge value; block numbers and counts stay far below `f64`'s exact integer range.
#[expect(clippy::cast_precision_loss, reason = "values stay below 2^53")]
pub const fn gauge_value(value: u64) -> f64 {
    value as f64
}
