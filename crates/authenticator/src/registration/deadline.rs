//! Deadlines and polling delays shared by both sides of a registration.

use std::{future::Future, time::Duration};

use backon::{ExponentialBuilder, Sleeper as _};
use futures_util::future::{Either, select};
use web_time::Instant;

/// The message-bridge session lifetime, from which each party estimates the session expiry
/// (WIP-109 §3.5).
pub(super) const SESSION_TTL: Duration = Duration::from_secs(15 * 60);

/// Runs `future` until `deadline`, returning `None` if the deadline passes first.
///
/// A future whose deadline has already passed is never polled.
pub(super) async fn before<F: Future>(deadline: Instant, future: F) -> Option<F::Output> {
    let now = Instant::now();
    if now >= deadline {
        return None;
    }
    let timeout = sleep(deadline.saturating_duration_since(now));
    match select(std::pin::pin!(future), std::pin::pin!(timeout)).await {
        Either::Left((output, _)) => Some(output),
        Either::Right(_) => None,
    }
}

/// Sleeps for `duration`, on native and browser targets alike.
pub(super) async fn sleep(duration: Duration) {
    backon::DefaultSleeper::default().sleep(duration).await;
}

/// The delays between polls of an outcome that takes a while: from one second, doubling up to
/// eight, with jitter.
///
/// The delays never run out; callers stop polling at their own deadline.
pub(super) fn polling_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_secs(1))
        .with_max_delay(Duration::from_secs(8))
        .without_max_times()
        .with_jitter()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_expired_deadline_never_polls_the_future() {
        let result = before(Instant::now() - Duration::from_secs(1), async {
            panic!("expired operation was polled");
        })
        .await;
        assert_eq!(result, None::<()>);
    }

    #[tokio::test]
    async fn a_future_that_outlives_the_deadline_is_dropped() {
        let deadline = Instant::now() + Duration::from_millis(10);
        assert_eq!(before(deadline, sleep(Duration::from_secs(60))).await, None);
    }
}
