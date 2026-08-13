use std::time::Duration;

use redis::{Script, aio::ConnectionManager};

use crate::{
    error::GatewayResult,
    storage::types::{RequestId, Timestamp},
};

/// Result of checking and conditionally recording one admission attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RateLimitOutcome {
    /// The request was recorded; `current_count` includes this request.
    Allowed { current_count: u64 },
    /// The window was already full, so the request was not recorded.
    Exceeded,
}

/// Per-account sliding-window admission limiter.
///
/// # Redis schema
///
/// - `gateway:ratelimit:leaf:<leaf-index>` is a sorted set whose members are
///   [`RequestId`] values and whose scores are admission timestamps.
///
/// Each key expires after one full window without an allowed request. The
/// limiter is independent from [`crate::storage::RequestRepository`]: admission
/// may consume rate-limit capacity even when later validation or durable request
/// acceptance fails.
#[derive(Clone)]
pub(crate) struct RateLimiter {
    manager: ConnectionManager,
}

impl RateLimiter {
    /// Creates a limiter backed by the supplied Redis connection manager.
    ///
    /// This does not read or modify any Redis key.
    pub(crate) fn new(manager: ConnectionManager) -> Self {
        Self { manager }
    }

    /// Atomically checks and conditionally records a request for one account.
    ///
    /// On `gateway:ratelimit:leaf:<leaf-index>`, removes entries with scores
    /// at or before `now - window`, then counts the remaining members. If the
    /// count is below `max_requests`, inserts `request_id` at score `now`,
    /// refreshes the key TTL to `window`, and returns
    /// [`RateLimitOutcome::Allowed`]. Otherwise returns
    /// [`RateLimitOutcome::Exceeded`] without recording the rejected request.
    ///
    /// Calls for the same account are serialized by one atomic Redis script, so
    /// concurrent gateway replicas cannot collectively exceed the limit.
    pub(crate) async fn check_and_record(
        &self,
        leaf_index: u64,
        request_id: RequestId,
        now: Timestamp,
        window: Duration,
        max_requests: u64,
    ) -> GatewayResult<RateLimitOutcome> {
        let window_secs = window.as_secs();
        let mut manager = self.manager.clone();
        let count: i64 = Script::new(
            r#"
            local now = tonumber(ARGV[1])
            local window = tonumber(ARGV[2])
            local limit = tonumber(ARGV[3])
            local oldest = now - window

            redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', oldest)
            local current = redis.call('ZCARD', KEYS[1])
            if current >= limit then
                return -1
            end

            redis.call('ZADD', KEYS[1], now, ARGV[4])
            redis.call('EXPIRE', KEYS[1], window)
            return current + 1
            "#,
        )
        .key(rate_limit_key(leaf_index))
        .arg(now)
        .arg(window_secs)
        .arg(max_requests)
        .arg(request_id.0.to_string())
        .invoke_async(&mut manager)
        .await?;

        if count < 0 {
            Ok(RateLimitOutcome::Exceeded)
        } else {
            Ok(RateLimitOutcome::Allowed {
                current_count: count as u64,
            })
        }
    }
}

fn rate_limit_key(leaf_index: u64) -> String {
    format!("gateway:ratelimit:leaf:{leaf_index}")
}
