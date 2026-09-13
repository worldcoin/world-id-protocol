//! The collector: issues nonces, admits payments, and settles the channel on chain.
//!
//! Stands in for a service like a Deep Face verifier host. It refuses rather than serves
//! whenever it cannot read current chain state, and it refuses at capacity with a proof the RP
//! can check against its own signatures.

use std::{
    collections::BTreeSet,
    str::FromStr as _,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use alloy::{
    primitives::{Address, B256, U256},
    providers::DynProvider,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use world_id_fee_escrow::{
    AdmitError, LaneNonce, Ledger, LedgerConfig, Payment, ReserveError,
    typed_data::{ChannelSettings, epoch_end},
};

use crate::{
    chain::{self, ChainSnapshot},
    rp::Admitted,
    unix_now,
};

/// Body of `POST /channels/{channel_id}/nonces`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReserveRequest {
    /// Epoch the payment will be billed to.
    pub epoch: u64,
    /// Fresh random idempotency key.
    pub request_id: String,
}

/// Body of `PUT /channels/{channel_id}/nonces/{lane}/{counter}`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RecordRequest {
    /// The idempotency key the reservation was issued under.
    pub request_id: String,
    /// The signed payment. Its channel and nonce must match the path.
    pub payment: Payment,
}

/// A refusal, carrying the proof of usage when the epoch ran out of capacity.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Refusal {
    /// Stable refusal class, for example `capacity_exhausted`.
    pub error: String,
    /// Human-readable detail.
    pub message: String,
    /// Highest payment per lane. Present only for `capacity_exhausted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_proof: Option<Vec<Payment>>,
}

/// Counters the demo and its test assert on.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
pub struct Stats {
    /// Units booked.
    pub admitted: u64,
    /// Requests refused because the epoch had no capacity left.
    pub refused_capacity: u64,
    /// Requests refused for any other reason.
    pub refused_other: u64,
    /// `settle` transactions sent.
    pub settlements: u64,
    /// Epochs closed by a settlement after they ended.
    pub epochs_closed: u64,
    /// Tokens received across every settlement.
    pub paid_total: U256,
}

/// What one settlement sweep did.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
pub struct SweepReport {
    /// `settle` transactions this sweep sent.
    pub settlements: u64,
    /// Epochs this sweep closed.
    pub closed: u64,
    /// Tokens this sweep moved to the collector.
    pub paid: U256,
}

/// Collector service state.
#[derive(Debug)]
pub struct Collector {
    provider: DynProvider,
    escrow: Address,
    snapshot: ChainSnapshot,
    settings: ChannelSettings,
    channel_id: B256,
    ledger: Mutex<Ledger<ChainSnapshot>>,
    stats: Mutex<Stats>,
    /// Epochs this collector has seen traffic for and may still owe a settlement on.
    open_epochs: Mutex<BTreeSet<u64>>,
    sequence: AtomicU64,
}

/// Shared handle to the collector.
pub type SharedCollector = Arc<Collector>;

impl Collector {
    /// Creates a collector serving one channel.
    #[must_use]
    pub fn new(
        provider: DynProvider,
        escrow: Address,
        chain_id: u64,
        snapshot: ChainSnapshot,
        settings: ChannelSettings,
        config: LedgerConfig,
    ) -> SharedCollector {
        let domain = world_id_fee_escrow::domain(chain_id, escrow);
        let mut ledger = Ledger::new(domain, snapshot.clone(), config);
        let channel_id = ledger.register_channel(settings.clone());
        snapshot.track(channel_id, settings.pricePerUnit);

        Arc::new(Self {
            provider,
            escrow,
            snapshot,
            settings,
            channel_id,
            ledger: Mutex::new(ledger),
            stats: Mutex::new(Stats::default()),
            open_epochs: Mutex::new(BTreeSet::new()),
            sequence: AtomicU64::new(0),
        })
    }

    /// The channel this collector serves.
    #[must_use]
    pub const fn channel_id(&self) -> B256 {
        self.channel_id
    }

    /// Current counters.
    pub async fn stats(&self) -> Stats {
        *self.stats.lock().await
    }

    /// Refreshes the capacity snapshot for an epoch before it is used to admit anything.
    ///
    /// A failure is logged and swallowed: the cached reading then either satisfies the
    /// staleness bound or does not, and [`ChainView`](world_id_fee_escrow::ChainView) refuses.
    async fn refresh(&self, epoch: u64) {
        if let Err(error) = self.snapshot.refresh(self.channel_id, epoch).await {
            tracing::warn!(
                channel = %self.channel_id,
                epoch,
                dependency = "escrow.epochState",
                %error,
                "capacity refresh failed, falling back to the cached reading"
            );
        }
        self.open_epochs.lock().await.insert(epoch);
    }

    /// Settles every epoch with new signed usage, then closes the ones that have ended.
    ///
    /// # Errors
    /// Returns an error if a `settle` transaction fails.
    pub async fn sweep(&self) -> eyre::Result<SweepReport> {
        let now = chain::block_timestamp(&self.provider).await?;
        let epochs: Vec<u64> = self.open_epochs.lock().await.iter().copied().collect();
        let mut report = SweepReport::default();

        for epoch in epochs {
            let batch = self
                .ledger
                .lock()
                .await
                .settlement_batch(self.channel_id, epoch);
            if !batch.is_empty() {
                let settled =
                    chain::settle(&self.provider, self.escrow, self.channel_id, epoch, &batch)
                        .await?;
                self.ledger
                    .lock()
                    .await
                    .mark_settled(self.channel_id, epoch, &batch);
                report.settlements += 1;
                report.paid += settled.paid;
                tracing::info!(
                    channel = %self.channel_id,
                    epoch,
                    authorisations = batch.len(),
                    settled_units = settled.settled_units,
                    "settled"
                );
            }

            // The closing settlement pays whatever signed usage did not. It needs no
            // signatures because it claims nothing about usage.
            let ended = epoch_end(&self.settings, epoch).is_some_and(|end| now >= end);
            if ended {
                let closed =
                    chain::settle(&self.provider, self.escrow, self.channel_id, epoch, &[]).await?;
                report.settlements += 1;
                report.paid += closed.paid;
                if closed.closed {
                    report.closed += 1;
                    self.ledger.lock().await.close_epoch(self.channel_id, epoch);
                    self.open_epochs.lock().await.remove(&epoch);
                    tracing::info!(channel = %self.channel_id, epoch, "epoch closed");
                }
            }
        }

        {
            let mut stats = self.stats.lock().await;
            stats.settlements += report.settlements;
            stats.epochs_closed += report.closed;
            stats.paid_total += report.paid;
        }
        Ok(report)
    }
}

/// Runs a settlement sweep every `interval` until the returned handle is aborted.
#[must_use]
pub fn settlement_task(state: SharedCollector, interval: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if let Err(error) = state.sweep().await {
                tracing::error!(channel = %state.channel_id, %error, "settlement sweep failed");
            }
        }
    })
}

/// Routes for the collector service.
pub fn router(state: SharedCollector) -> Router {
    Router::new()
        .route("/channels/{channel_id}/nonces", post(reserve))
        .route(
            "/channels/{channel_id}/nonces/{lane}/{counter}",
            put(record),
        )
        .route("/admit", post(admit))
        .route("/settle", post(sweep))
        .route("/stats", get(stats))
        .with_state(state)
}

/// Serves `router` on `listener` until the returned handle is aborted.
#[must_use]
pub fn serve(
    listener: tokio::net::TcpListener,
    state: SharedCollector,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, router(state)).await {
            tracing::error!(%error, "collector stopped");
        }
    })
}

/// Binds an ephemeral local port.
///
/// # Errors
/// Returns an error if the port cannot be bound.
pub async fn bind_ephemeral() -> eyre::Result<(std::net::SocketAddr, tokio::net::TcpListener)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    Ok((listener.local_addr()?, listener))
}

fn refuse(
    status: StatusCode,
    error: &str,
    message: String,
    refusal_proof: Option<Vec<Payment>>,
) -> Response {
    (
        status,
        Json(Refusal {
            error: error.to_string(),
            message,
            refusal_proof,
        }),
    )
        .into_response()
}

fn bad_channel(raw: &str) -> Response {
    refuse(
        StatusCode::BAD_REQUEST,
        "malformed_channel_id",
        format!("{raw:?} is not a 32-byte hex channel id"),
        None,
    )
}

async fn reserve(
    State(state): State<SharedCollector>,
    Path(channel_id): Path<String>,
    Json(body): Json<ReserveRequest>,
) -> Response {
    let Ok(channel_id) = B256::from_str(&channel_id) else {
        return bad_channel(&channel_id);
    };
    state.refresh(body.epoch).await;

    let issued =
        state
            .ledger
            .lock()
            .await
            .reserve(channel_id, body.epoch, &body.request_id, unix_now());
    match issued {
        Ok(issued) => Json(issued).into_response(),
        Err(error) => {
            let (status, class) = match error {
                ReserveError::UnknownChannel(_) => (StatusCode::NOT_FOUND, "unknown_channel"),
                ReserveError::EpochOutOfRange { .. } | ReserveError::NoCurrentEpoch(_) => {
                    (StatusCode::BAD_REQUEST, "epoch_out_of_range")
                }
                ReserveError::Chain(_) => (StatusCode::SERVICE_UNAVAILABLE, "chain_unavailable"),
                ReserveError::CapacityExhausted { .. } => {
                    (StatusCode::PAYMENT_REQUIRED, "capacity_exhausted")
                }
                ReserveError::TooManyPending { .. } => {
                    (StatusCode::TOO_MANY_REQUESTS, "too_many_pending")
                }
                ReserveError::Nonce(_) => (StatusCode::CONFLICT, "lane_exhausted"),
            };
            let proof = if class == "capacity_exhausted" {
                Some(
                    state
                        .ledger
                        .lock()
                        .await
                        .refusal_proof(channel_id, body.epoch),
                )
            } else {
                None
            };
            tracing::warn!(channel = %channel_id, epoch = body.epoch, class, %error, "nonce refused");
            refuse(status, class, error.to_string(), proof)
        }
    }
}

async fn record(
    State(state): State<SharedCollector>,
    Path((channel_id, lane, counter)): Path<(String, u32, u64)>,
    Json(body): Json<RecordRequest>,
) -> Response {
    let Ok(channel_id) = B256::from_str(&channel_id) else {
        return bad_channel(&channel_id);
    };
    // The path is the caller's claim; the payment itself is what gets banked, so they must agree.
    let claimed = body.payment.lane_nonce().ok();
    if body.payment.channel_id != channel_id || claimed != Some(LaneNonce::new(lane, counter)) {
        return refuse(
            StatusCode::BAD_REQUEST,
            "path_mismatch",
            "the payment does not match the channel, lane, and counter in the path".to_string(),
            None,
        );
    }

    let epoch = body.payment.epoch;
    let recorded = state
        .ledger
        .lock()
        .await
        .record(&body.payment, &body.request_id, unix_now());
    match recorded {
        Ok(_) => {
            state.stats.lock().await.admitted += 1;
            state.open_epochs.lock().await.insert(epoch);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => {
            state.stats.lock().await.refused_other += 1;
            tracing::warn!(
                channel = %channel_id,
                epoch,
                lane,
                counter,
                class = error.class(),
                %error,
                "early payment refused"
            );
            refuse(StatusCode::CONFLICT, error.class(), error.to_string(), None)
        }
    }
}

async fn admit(State(state): State<SharedCollector>, Json(payment): Json<Payment>) -> Response {
    let epoch = payment.epoch;
    state.refresh(epoch).await;

    let outcome = state.ledger.lock().await.admit(&payment, unix_now());
    match outcome {
        Ok(unit) => {
            state.stats.lock().await.admitted += 1;
            Json(Admitted {
                receipt: format!(
                    "verifier-mock-{}",
                    state.sequence.fetch_add(1, Ordering::SeqCst)
                ),
                epoch: unit.epoch,
                lane: unit.lane_nonce.lane,
                counter: unit.lane_nonce.counter,
            })
            .into_response()
        }
        Err(error) => {
            let class = error.class();
            let (status, proof) = match &error {
                AdmitError::CapacityExhausted { .. } => (
                    StatusCode::PAYMENT_REQUIRED,
                    Some(
                        state
                            .ledger
                            .lock()
                            .await
                            .refusal_proof(state.channel_id, epoch),
                    ),
                ),
                AdmitError::Chain(_) => (StatusCode::SERVICE_UNAVAILABLE, None),
                AdmitError::UnknownChannel(_) => (StatusCode::NOT_FOUND, None),
                _ => (StatusCode::CONFLICT, None),
            };
            {
                let mut counters = state.stats.lock().await;
                if matches!(error, AdmitError::CapacityExhausted { .. }) {
                    counters.refused_capacity += 1;
                } else {
                    counters.refused_other += 1;
                }
            }
            tracing::warn!(channel = %state.channel_id, epoch, class, %error, "admission refused");
            refuse(status, class, error.to_string(), proof)
        }
    }
}

async fn sweep(State(state): State<SharedCollector>) -> Response {
    match state.sweep().await {
        Ok(report) => Json(report).into_response(),
        Err(error) => {
            tracing::error!(channel = %state.channel_id, %error, "settlement failed");
            refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "settlement_failed",
                error.to_string(),
                None,
            )
        }
    }
}

async fn stats(State(state): State<SharedCollector>) -> Response {
    Json(state.stats().await).into_response()
}
