//! This file creates an actor that batches [`BillableRpRequest`]s according to WIP-107 and sends them to the `OPRF-accountant` via the configured endpoint.
//!
//! All uniqueness proof requests are billable requests in the protocol. Therefore the `OPRF-node` collects all those requests and blindly `POSTs` them to the `OPRF-accountant`. This service is lightweight by choice. It does not perform any form of deduplication on requests (on replicas across the globe). This service expects the `OPRF-accountant` to provide an idempotent endpoint and even sending the same batch multiple times shall gracefully be handled by the `OPRF-accountant`.
//!
//! The worker has an internal buffer. If either the buffer reaches its capacity OR a pre-defined flush interval passes, the worker `POSTs` the currently buffered requests to the `OPRF-accountant`. The worker can be configured with a [`backon::ExponentialBackoff`](https://docs.rs/backon/latest/backon/struct.ExponentialBuilder.html). On error cases (after retry), the worker will drop the current batch. This batch won't be reported to the accountant then.
//!
//! To create a worker call the [`init`] method with the [`AccountantBatcherConfig`]. See the methods on the [`AccountantBatcherHandle`] for how to communicate with the worker.
//!
use std::{num::NonZeroUsize, time::Duration};

use backon::{ExponentialBuilder, Retryable};
use oprf_accountant::api::{BillableRpRequest, PostRequestQuery};
use reqwest::{StatusCode, Url};
use serde::Deserialize;
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio_util::sync::CancellationToken;
use tracing::instrument;
use uuid::Uuid;

use crate::metrics;

/// The configuration for the worker.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct AccountantBatcherConfig {
    /// The endpoint of the `OPRF-accountant`.
    ///
    /// The worker will send `POST` requests to this `URL`.
    pub endpoint: reqwest::Url,

    /// The channel size of the worker.
    ///
    /// Should be reasonably large to not drop requests in case the worker can't keep up.
    #[serde(default = "AccountantBatcherConfig::default_channel_size")]
    pub channel_size: NonZeroUsize,

    /// The max capacity of the internal buffer.
    ///
    /// If the buffer reaches this capacity, the worker will `POST` the buffer to the configured endpoint.
    #[serde(default = "AccountantBatcherConfig::default_buffer_capacity")]
    pub buffer_capacity: NonZeroUsize,

    /// The flush interval of the worker.
    ///
    /// In this interval, the worker will `POST` the buffer to the configured endpoint, irrelevant of the current buffer size.
    ///
    /// _Note_: this flush interval must be chosen with the `voting_window` of the contract in mind. If the `flush_interval` is too large we might miss requests at the accountant.
    #[serde(
        default = "AccountantBatcherConfig::default_flush_interval",
        with = "humantime_serde"
    )]
    pub flush_interval: Duration,

    /// Min delay between retries during flush.
    #[serde(
        default = "AccountantBatcherConfig::default_request_min_delay",
        with = "humantime_serde"
    )]
    pub request_min_delay: Duration,

    /// Max delay between retries during flush.
    #[serde(
        default = "AccountantBatcherConfig::default_request_max_delay",
        with = "humantime_serde"
    )]
    pub request_max_delay: Duration,

    /// The max total time for the retry logic.
    ///
    /// If after this time the requests still fail, the request is considered faulty.
    #[serde(
        default = "AccountantBatcherConfig::default_request_total_delay",
        with = "humantime_serde"
    )]
    pub request_total_delay: Duration,

    /// The maximal attempts the retry logic will try to flush the batch.
    ///
    /// If omitted, will not configure any maximal attempts. Can be set to 0 for tests to turn off the retry logic.
    #[serde(default)]
    pub request_max_attempts: Option<usize>,
}

impl AccountantBatcherConfig {
    // TODO finalize the size here. We are bound by the wip 101 aux data with is 1KB. So this channel is upper bound by ~10kb (which is nothing).
    //
    // With 5 req/s we would take 30 minutes to fill the buffer. We could increase by a factor of 10 even, which results in 100kb and would need 5h to fill the buffer with 5req/s.
    //
    // The voting window is somewhere between 1h and 1d. When we have the finalized numbers we can set the remaining parameters.
    const fn default_channel_size() -> NonZeroUsize {
        NonZeroUsize::new(10240).expect("10240 is non zero")
    }

    const fn default_buffer_capacity() -> NonZeroUsize {
        NonZeroUsize::new(1024).expect("1024 is non zero")
    }

    const fn default_flush_interval() -> Duration {
        Duration::from_mins(10)
    }

    const fn default_request_min_delay() -> Duration {
        Duration::from_millis(250)
    }

    const fn default_request_max_delay() -> Duration {
        Duration::from_mins(5)
    }

    const fn default_request_total_delay() -> Duration {
        Duration::from_mins(30)
    }

    /// Creates the [`AccountantBatcherConfig`] with the default values.
    #[must_use]
    pub fn with_default_values(endpoint: reqwest::Url) -> Self {
        Self {
            endpoint,
            channel_size: Self::default_channel_size(),
            buffer_capacity: Self::default_buffer_capacity(),
            flush_interval: Self::default_flush_interval(),
            request_min_delay: Self::default_request_min_delay(),
            request_max_delay: Self::default_request_max_delay(),
            request_total_delay: Self::default_request_total_delay(),
            request_max_attempts: None,
        }
    }
}

/// All jobs for the worker.
#[derive(Debug, Clone, PartialEq)]
enum AccountantBatcherJob {
    /// Add another request to the buffer.
    Put(BillableRpRequest),
    /// Send the current buffer to the configured endpoint.
    Flush,
    /// Stops the worker.
    ///
    /// All requests after the close will be ignored. All requests before the close will be handled.
    Close,
}

/// Internal worker struct.
struct AccountantBatcher {
    client: reqwest::Client,
    accountant_endpoint: Url,
    backoff: backon::ExponentialBuilder,
    buffer: Vec<BillableRpRequest>,
    buffer_size: usize,
    rx: mpsc::Receiver<AccountantBatcherJob>,
    flush_task: tokio::task::JoinHandle<()>,
}

/// Handle to worker.
///
/// To initially create a worker with an associated handle, see [`init`]. The handle can be cheaply cloned to get access to the underlying worker. Usually you only want to call `init` once per process.
#[derive(Debug, Clone)]
pub struct AccountantBatcherHandle(mpsc::Sender<AccountantBatcherJob>);

/// Creates a worker with an associated handle that is cheaply cloneable and can be used to communicate with the worker. Usually this only needs to be called only once within the process lifetime.
///
/// Internally uses an unbounded channel from `tokio`, therefore interactions with the handle will never block. The worker will use the provided `reqwest::Client`. Any configurations (e.g., timeouts) shall be set by call-site.
///
/// The worker will stop when calling [`AccountantBatcherHandle::close`].
///
/// # Panics
/// If `flush_interval` is zero.
#[must_use]
pub fn init(
    config: &AccountantBatcherConfig,
    client: reqwest::Client,
    cancellation_token: CancellationToken,
) -> (AccountantBatcherHandle, tokio::task::JoinHandle<()>) {
    tracing::info!("starting accountant batcher worker...");
    let (tx, rx) = mpsc::channel(config.channel_size.get());
    let batcher = AccountantBatcher::new(config, client, tx.clone(), rx);
    let batcher_task = tokio::task::spawn(async move {
        batcher.run().await;
        tracing::info!("successfully closed accountant batcher");
        cancellation_token.cancel();
    });
    (AccountantBatcherHandle(tx), batcher_task)
}

impl AccountantBatcherHandle {
    /// Records a [`BillableRpRequest`] and sends it to the worker.
    pub fn record_request(&self, request: BillableRpRequest) {
        let nonce = request.nonce;
        match self.0.try_send(AccountantBatcherJob::Put(request)) {
            Ok(()) => tracing::trace!("successfully send request with {nonce} to batcher"),
            Err(TrySendError::Full(_)) => {
                tracing::trace!("worker channel is full: dropping request with nonce {nonce}");
                metrics::accountant_batcher::inc_request_dropped_full();
            }
            Err(TrySendError::Closed(_)) => {
                // we log this as warning because this should no be possible
                tracing::warn!("trying to record request but batcher already gone");
            }
        }
    }

    /// Initiates a graceful shutdown of the worker.
    ///
    /// The worker will try to handle all requests sent before this request, but will ignore all jobs afterwards.
    pub async fn close(self) {
        if self.0.send(AccountantBatcherJob::Close).await.is_err() {
            tracing::warn!("trying to close batcher but already gone");
        }
    }
}

impl AccountantBatcher {
    /// Internal constructor for the worker.
    ///
    /// Spawns a `tokio::Task` that periodically sends a flush job to the worker. During teardown of the worker, the worker will abort the flush task and awaits its cancellation. This way the flush task will never talk to an already closed worker, and the worker can be sure that at least one handle will always exist until someone calls `AccountantBatcherHandle::close`.
    fn new(
        config: &AccountantBatcherConfig,
        client: reqwest::Client,
        tx: mpsc::Sender<AccountantBatcherJob>,
        rx: mpsc::Receiver<AccountantBatcherJob>,
    ) -> Self {
        // The worker during close will abort the flush task and wait until it is closed.
        let flush_task = tokio::task::spawn({
            let mut interval = tokio::time::interval(config.flush_interval);
            // set missed tick behavior to delay - in case we block during sending flush and we miss a tick, we want to send exactly one flush task and continue sleeping from that period again
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            async move {
                loop {
                    interval.tick().await;
                    tracing::trace!("sending account batch flush..");
                    if tx.send(AccountantBatcherJob::Flush).await.is_err() {
                        tracing::error!(
                            "could not send flush to accountant batcher - already closed (this should never happen)"
                        );
                    }
                }
            }
        });

        let backoff = ExponentialBuilder::new()
            .without_max_times()
            .with_min_delay(config.request_min_delay)
            .with_max_delay(config.request_max_delay)
            .with_total_delay(Some(config.request_total_delay));
        // we only set max times if explicitly provided. Mostly for tests to turn-off retry
        let backoff = if let Some(max_times) = config.request_max_attempts {
            backoff.with_max_times(max_times)
        } else {
            backoff
        };

        Self {
            accountant_endpoint: config.endpoint.clone(),
            client,
            rx,
            buffer: Vec::with_capacity(config.buffer_capacity.get()),
            buffer_size: config.buffer_capacity.get(),
            backoff,
            flush_task,
        }
    }

    /// Main event loop.
    ///
    /// This should only return when observing the `Close` job.
    async fn run(mut self) {
        while let Some(job) = self.rx.recv().await {
            match job {
                AccountantBatcherJob::Put(request) => self.put(request).await,
                AccountantBatcherJob::Flush => self.flush(Uuid::new_v4()).await,
                AccountantBatcherJob::Close => {
                    self.close().await;
                    return;
                }
            }
            let channel_size = self.rx.len();
            metrics::accountant_batcher::set_job_queue(channel_size);
            tracing::trace!("still have {channel_size} jobs in channel");
        }
        tracing::error!("all handles dropped but there should be the flush task?");
    }

    /// Puts a [`BillableRpRequest`] to the buffer.
    ///
    /// If buffer reaches max capacity, attempts to flush the buffer.
    #[instrument(level = "trace", skip_all, name = "accountant_batcher::put")]
    async fn put(&mut self, request: BillableRpRequest) {
        self.buffer.push(request);
        tracing::trace!(
            "adding request to buffer - buffer size now: {}",
            self.buffer.len()
        );
        if self.buffer.len() >= self.buffer_size {
            self.flush(Uuid::new_v4()).await;
        }
    }

    /// Flushes the buffer if buffer is not empty.
    ///
    /// Empties the buffer and attempts to send it to the endpoint.
    #[instrument(level = "info", skip_all, name = "accountant_batcher::flush", fields(%flush_id))]
    async fn flush(&mut self, flush_id: Uuid) {
        tracing::trace!("attempting to flush the buffer");
        let batch = std::mem::replace(&mut self.buffer, Vec::with_capacity(self.buffer_size));
        if batch.is_empty() {
            tracing::trace!("buffer empty - no flush");
        } else {
            tracing::trace!("attempting to flush buffer with size {}", batch.len());
            let query = PostRequestQuery { id: flush_id };
            let result = (|| async {
                self.client
                    .post(self.accountant_endpoint.clone())
                    .query(&query)
                    .json(&batch)
                    .send()
                    .await?
                    .error_for_status()?;
                Ok(())
            })
            .retry(self.backoff)
            .when(is_retryable)
            .notify(|err, duration| {
                tracing::warn!(?err, "Retrying flush after {duration:?}: {err}");
            })
            .await;
            match result {
                Ok(()) => tracing::trace!("Successfully sent batch to accountant"),
                Err(err) => {
                    tracing::error!(
                        ?err,
                        "Could not send batch of size {} to accountant: {err}",
                        batch.len()
                    );
                }
            }
        }
    }

    /// Closes the worker.
    ///
    /// Aborts the periodic flush task and flushes the remaining buffer so that requests recorded
    /// before the close are still reported to the accountant. The final flush uses the configured
    /// retry policy.
    #[instrument(level = "info", skip_all, name = "accountant_batcher::close")]
    async fn close(mut self) {
        tracing::info!("closing accountant batcher worker - flush the buffer one last time");
        self.flush_task.abort();
        if let Err(err) = (&mut self.flush_task).await
            && !err.is_cancelled()
        {
            tracing::warn!(?err, "Got error during close from flush task");
        }
        self.flush(Uuid::new_v4()).await;
    }
}

/// Returns `true` if the request should be retried.
///
/// Retryable errors:
/// - Timeout / connection errors
/// - Body read errors (transient connection drops)
/// - 5xx server errors
/// - 408 Request Timeout
#[inline]
fn is_retryable(e: &reqwest::Error) -> bool {
    if e.is_timeout() || e.is_connect() || e.is_body() {
        true
    } else if let Some(status) = e.status() {
        status.is_server_error() || status == StatusCode::REQUEST_TIMEOUT
    } else {
        false
    }
}

/// TODO this is just a place holder for now.
///
/// We will gate this behind cfg(test) but for now we need it for stubs tests. We will update the tests in a follow up PR.
///
/// Spawns a task that drains the channel so that recording requests does not log warnings.
#[must_use]
pub fn dev_null() -> AccountantBatcherHandle {
    let (tx, mut rx) = mpsc::channel(1024);
    tokio::task::spawn(async move { while rx.recv().await.is_some() {} });
    AccountantBatcherHandle(tx)
}
