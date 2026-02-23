use std::{
    future::Future,
    num::NonZeroU32,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use alloy::{
    rpc::json_rpc::RequestPacket,
    transports::{TransportError, TransportErrorKind},
};
use backon::{BackoffBuilder, ExponentialBuilder};
use clap::Args;
use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
};
use serde::Deserialize;
use tower::{Layer, Service};

pub use alloy::transports::layers::RetryPolicy;

mod defaults {
    pub const BURST_SIZE: u32 = 10;
    pub const REQUESTS_PER_SECOND: u32 = 100;
    pub const MAX_RETRIES: u32 = 10;
    pub const INITIAL_BACKOFF_MS: u64 = 1000;
    pub const MAX_BACKOFF_MS: u64 = 60_000;
    pub const TIMEOUT_SECS: u64 = 10;

    pub const fn default_burst_size() -> u32 {
        BURST_SIZE
    }
    pub const fn default_requests_per_second() -> u32 {
        REQUESTS_PER_SECOND
    }
    pub const fn default_max_retries() -> u32 {
        MAX_RETRIES
    }
    pub const fn default_initial_backoff_ms() -> u64 {
        INITIAL_BACKOFF_MS
    }
    pub const fn default_max_backoff_ms() -> u64 {
        MAX_BACKOFF_MS
    }
    pub const fn default_timeout_secs() -> u64 {
        TIMEOUT_SECS
    }
}

#[derive(Args, Debug, Clone, Deserialize)]
pub struct ThrottleConfig {
    /// Requests per second rate limit.
    #[arg(long = "rps", default_value_t = 100, env = "RPC_REQUESTS_PER_SECOND")]
    #[serde(default = "defaults::default_requests_per_second")]
    pub requests_per_second: u32,

    /// Burst size for rate limiting.
    #[arg(long = "burst-size", default_value_t = 10, env = "RPC_BURST_SIZE")]
    #[serde(default = "defaults::default_burst_size")]
    pub burst_size: u32,
}

#[derive(Args, Debug, Clone, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts for failed RPC requests.
    /// Set to 0 to disable retries entirely.
    #[arg(long = "rpc-max-retries", default_value_t = defaults::MAX_RETRIES, env = "RPC_MAX_RETRIES")]
    #[serde(default = "defaults::default_max_retries")]
    pub max_retries: u32,

    /// Initial (minimum) backoff delay in milliseconds before the first retry.
    #[arg(long = "rpc-initial-backoff-ms", default_value_t = defaults::INITIAL_BACKOFF_MS, env = "RPC_INITIAL_BACKOFF_MS")]
    #[serde(default = "defaults::default_initial_backoff_ms")]
    pub initial_backoff_ms: u64,

    /// Maximum backoff delay in milliseconds. The exponential backoff will
    /// not exceed this value regardless of how many retries have occurred.
    #[arg(long = "rpc-max-backoff-ms", default_value_t = defaults::MAX_BACKOFF_MS, env = "RPC_MAX_BACKOFF_MS")]
    #[serde(default = "defaults::default_max_backoff_ms")]
    pub max_backoff_ms: u64,

    /// Per-RPC request timeout in seconds.
    #[arg(long = "rpc-timeout-secs", default_value_t = defaults::TIMEOUT_SECS, env = "RPC_TIMEOUT_SECS")]
    #[serde(default = "defaults::default_timeout_secs")]
    pub timeout_secs: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: defaults::MAX_RETRIES,
            initial_backoff_ms: defaults::INITIAL_BACKOFF_MS,
            max_backoff_ms: defaults::MAX_BACKOFF_MS,
            timeout_secs: defaults::TIMEOUT_SECS,
        }
    }
}

type Limiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// A Tower layer that rate-limits outgoing RPC requests using a
/// token-bucket algorithm (powered by [`governor`]).
///
/// Requests that exceed the configured rate are delayed (not rejected)
/// until a token becomes available, keeping the downstream provider
/// within its rate budget.
#[derive(Clone)]
pub(crate) struct ThrottleLayer {
    limiter: Arc<Limiter>,
}

impl ThrottleLayer {
    pub fn new_with_config(rps: u32, burst: u32) -> Self {
        let rps = NonZeroU32::new(rps).expect("RPS must be non-zero");
        let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
        Self {
            limiter: RateLimiter::direct(Quota::per_second(rps).allow_burst(burst)).into(),
        }
    }
}

impl<S> Layer<S> for ThrottleLayer {
    type Service = ThrottleService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ThrottleService {
            inner,
            limiter: self.limiter.clone(),
        }
    }
}

/// Tower service that awaits a rate-limit token before forwarding each request.
#[derive(Clone)]
pub(crate) struct ThrottleService<S> {
    inner: S,
    limiter: Arc<Limiter>,
}

impl<S> Service<RequestPacket> for ThrottleService<S>
where
    S: Service<RequestPacket> + Clone + Send + Sync + 'static,
    S::Response: Send + Sync + 'static,
    S::Error: Send + Sync + 'static,
    S::Future: Send,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        let limiter = self.limiter.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            limiter.until_ready().await;
            inner.call(req).await
        })
    }
}

/// A Tower layer that retries failed RPC requests with exponential backoff
/// (powered by [`backon::ExponentialBuilder`]).
///
/// The retry decision is delegated to an [`alloy::transports::layers::RetryPolicy`],
/// keeping this layer compatible with alloy's built-in
/// [`RateLimitRetryPolicy`](alloy::transports::layers::RateLimitRetryPolicy)
/// and its `.or()` combinator.
#[derive(Debug, Clone)]
pub struct RetryLayer<P> {
    policy: P,
    max_retries: u32,
    backoff: ExponentialBuilder,
}

impl<P> RetryLayer<P> {
    pub fn new(policy: P, config: &RetryConfig) -> Self {
        let backoff = ExponentialBuilder::default()
            .with_min_delay(Duration::from_millis(config.initial_backoff_ms))
            .with_max_delay(Duration::from_millis(config.max_backoff_ms))
            .with_jitter()
            .without_max_times();
        Self {
            policy,
            max_retries: config.max_retries,
            backoff,
        }
    }
}

impl<S, P: Clone> Layer<S> for RetryLayer<P> {
    type Service = RetryService<S, P>;

    fn layer(&self, inner: S) -> Self::Service {
        RetryService {
            inner,
            policy: self.policy.clone(),
            max_retries: self.max_retries,
            backoff: self.backoff,
        }
    }
}

/// Tower service that wraps each request in a retry loop with exponential backoff.
#[derive(Debug, Clone)]
pub struct RetryService<S, P> {
    inner: S,
    policy: P,
    max_retries: u32,
    backoff: ExponentialBuilder,
}

impl<S, P> Service<RequestPacket> for RetryService<S, P>
where
    S: Service<
            RequestPacket,
            Response = alloy::rpc::json_rpc::ResponsePacket,
            Error = TransportError,
        > + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send,
    P: RetryPolicy + Clone + 'static,
{
    type Response = alloy::rpc::json_rpc::ResponsePacket;
    type Error = TransportError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        let mut this = self.clone();

        Box::pin(async move {
            let mut backoff_iter = this.backoff.build();
            let mut attempt: u32 = 0;

            loop {
                let err;
                match this.inner.call(request.clone()).await {
                    Ok(resp) => {
                        if let Some(e) = resp.as_error() {
                            err = TransportError::ErrorResp(e.clone());
                        } else {
                            return Ok(resp);
                        }
                    }
                    Err(e) => {
                        err = e;
                    }
                }
                if !this.policy.should_retry(&err) {
                    return Err(err);
                }

                attempt += 1;
                if attempt > this.max_retries {
                    return Err(TransportErrorKind::custom_str(&format!(
                        "max retries exceeded: {err}"
                    )));
                }

                let exponential_delay = backoff_iter.next().unwrap_or(Duration::ZERO);
                let hint = this.policy.backoff_hint(&err);
                let delay = hint.unwrap_or(exponential_delay);

                tracing::debug!(
                    attempt,
                    max_retries = this.max_retries,
                    delay_ms = delay.as_millis() as u64,
                    backoff_ms = exponential_delay.as_millis() as u64,
                    hint_ms = hint.map(|h| h.as_millis() as u64),
                    %err,
                    "retrying RPC request"
                );

                tokio::time::sleep(delay).await;
            }
        })
    }
}
