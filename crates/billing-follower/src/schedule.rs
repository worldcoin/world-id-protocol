//! When the follower polls the chain, and how long it waits after a failed read.

use std::time::Duration;

use rand::Rng as _;
use tokio::time::Instant;

/// Polls on the chain's block schedule: quiet until just before the next block is due, then
/// every `poll_interval` until it arrives, then every `stalled_poll_interval` once the chain is
/// late by a whole block.
///
/// Timing follows when new heads were seen locally, not block timestamps, so the host's clock and
/// the provider's propagation delay do not matter.
#[derive(Debug, Clone)]
pub struct PollSchedule {
    block_time: Duration,
    poll_interval: Duration,
    stalled_poll_interval: Duration,
    last_new_head: Option<Instant>,
}

impl PollSchedule {
    pub const fn new(
        block_time: Duration,
        poll_interval: Duration,
        stalled_poll_interval: Duration,
    ) -> Self {
        Self {
            block_time,
            poll_interval,
            stalled_poll_interval,
            last_new_head: None,
        }
    }

    /// Records that a poll at `at` saw a new head.
    pub const fn new_head(&mut self, at: Instant) {
        self.last_new_head = Some(at);
    }

    /// When to poll next, given that the last poll ran at `now`.
    pub fn next_poll(&self, now: Instant) -> Instant {
        let Some(seen) = self.last_new_head else {
            return now + self.poll_interval;
        };
        // Wake two poll intervals before the next block is due, so it is caught within one.
        let due = seen + self.block_time.saturating_sub(self.poll_interval * 2);
        if now < due {
            due
        } else if now.duration_since(seen) < self.block_time * 2 {
            now + self.poll_interval
        } else {
            now + self.stalled_poll_interval
        }
    }
}

/// Exponential backoff with equal jitter: the `n`th wait is half of `min(max, base * 2^n)` plus a
/// random share of the other half.
#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    max: Duration,
    failures: u32,
}

impl Backoff {
    pub const fn new(base: Duration, max: Duration) -> Self {
        Self {
            base,
            max,
            failures: 0,
        }
    }

    /// The wait after one more failure.
    pub fn next_delay(&mut self) -> Duration {
        let ceiling = self
            .base
            .saturating_mul(1 << self.failures.min(16))
            .min(self.max);
        self.failures = self.failures.saturating_add(1);
        let half = ceiling / 2;
        half + half.mul_f64(rand::thread_rng().gen_range(0.0..=1.0))
    }

    /// Consecutive failures since the last success.
    pub const fn failures(&self) -> u32 {
        self.failures
    }

    pub const fn reset(&mut self) {
        self.failures = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    fn schedule() -> PollSchedule {
        PollSchedule::new(MS * 2000, MS * 100, MS * 1000)
    }

    #[tokio::test(start_paused = true)]
    async fn polls_wait_for_the_next_block_then_tighten_then_slow_down() {
        let mut schedule = schedule();
        let start = Instant::now();
        assert_eq!(schedule.next_poll(start), start + MS * 100);

        schedule.new_head(start);
        assert_eq!(schedule.next_poll(start), start + MS * 1800);
        let late = start + MS * 2500;
        assert_eq!(schedule.next_poll(late), late + MS * 100);
        let stalled = start + MS * 4000;
        assert_eq!(schedule.next_poll(stalled), stalled + MS * 1000);
    }

    #[test]
    fn backoff_grows_to_its_ceiling_with_jitter_and_resets() {
        let mut backoff = Backoff::new(MS * 200, MS * 10_000);
        let first = backoff.next_delay();
        assert!((MS * 100..=MS * 200).contains(&first), "{first:?}");
        for _ in 0..10 {
            backoff.next_delay();
        }
        let capped = backoff.next_delay();
        assert!((MS * 5000..=MS * 10_000).contains(&capped), "{capped:?}");
        assert_eq!(backoff.failures(), 12);
        backoff.reset();
        assert!(backoff.next_delay() <= MS * 200);
    }
}
