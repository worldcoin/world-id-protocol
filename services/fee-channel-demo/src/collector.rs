//! The mock service that gates work on a signed request and settles the channel on-chain.
//!
//! Stands in for something like a Deep Face TEE host: it admits a request only if the channel
//! it names can still pay for the work, then batches the highest authorisation per lane into
//! `IWorldIDFeeEscrow.settle`.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use alloy::{
    primitives::{Address, B256, U256},
    providers::DynProvider,
    sol_types::Eip712Domain,
};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use world_id_fee_escrow::{ProofRequestV2, collector::AdmitError};

use crate::chain::{self, WorldIDFeeEscrow};

/// Counters the test and the demo binary assert on.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
pub struct Stats {
    /// Requests admitted for work.
    pub admitted: usize,
    /// Requests refused because the channel could not cover the fee.
    pub rejected_insolvent: usize,
    /// Requests refused for any other reason.
    pub rejected_other: usize,
    /// Number of `settle` transactions sent.
    pub settlements: usize,
    /// Total WLD received across those settlements.
    pub paid_total: U256,
}

/// Collector service state.
#[derive(Debug)]
pub struct Collector {
    provider: DynProvider,
    escrow: Address,
    fee_schedule: Address,
    domain: Eip712Domain,
    ledger: Mutex<world_id_fee_escrow::Ledger>,
    stats: Mutex<Stats>,
    settle_every: usize,
    pending_since_settle: AtomicUsize,
    sequence: AtomicUsize,
}

/// Shared handle to the collector.
pub type SharedCollector = Arc<Collector>;

/// Successful admission response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WorkAccepted {
    /// Always true.
    pub admitted: bool,
    /// Stand-in for whatever the real service returns.
    pub receipt: String,
    /// Lane the request drew from.
    pub lane: u32,
    /// Counter the request carried.
    pub counter: u64,
}

/// Refusal response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WorkRejected {
    /// Always false.
    pub admitted: bool,
    /// Why the request was refused.
    pub reason: String,
}

/// Result of a settlement sweep.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct SettleReport {
    /// Settlements performed in this sweep.
    pub settlements: usize,
    /// WLD collected across the whole service lifetime.
    pub paid_total: U256,
}

impl Collector {
    /// Creates a collector that settles once `settle_every` requests have been admitted.
    #[must_use]
    pub fn new(
        provider: DynProvider,
        escrow: Address,
        fee_schedule: Address,
        domain: Eip712Domain,
        settle_every: usize,
    ) -> SharedCollector {
        Arc::new(Self {
            provider,
            escrow,
            fee_schedule,
            domain,
            ledger: Mutex::new(world_id_fee_escrow::Ledger::new()),
            stats: Mutex::new(Stats::default()),
            settle_every,
            pending_since_settle: AtomicUsize::new(0),
            sequence: AtomicUsize::new(0),
        })
    }

    /// Current counters.
    pub async fn stats(&self) -> Stats {
        *self.stats.lock().await
    }

    /// Settles every channel that has pending authorisations.
    ///
    /// Holds the ledger lock for the whole sweep. Releasing it between `settlement_batch` and
    /// `mark_settled` would let an admission land in between and have its authorisation
    /// cleared without ever being submitted.
    ///
    /// # Errors
    /// Returns an error if a `settle` transaction fails.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the ledger lock must span the whole sweep, see above"
    )]
    pub async fn settle_all(&self) -> eyre::Result<usize> {
        let mut performed = 0usize;
        {
            let mut ledger = self.ledger.lock().await;
            let escrow = WorldIDFeeEscrow::new(self.escrow, self.provider.clone());
            let channels: Vec<B256> = ledger.channels_with_pending();

            for channel_id in channels {
                let batch = ledger.settlement_batch(channel_id);
                if batch.is_empty() {
                    continue;
                }
                let auths = batch.iter().map(chain::to_sol_auth).collect();
                let receipt = escrow
                    .settle(channel_id, auths)
                    .send()
                    .await?
                    .get_receipt()
                    .await?;

                let paid_now: U256 = receipt
                    .inner
                    .logs()
                    .iter()
                    .filter_map(|log| log.log_decode::<WorldIDFeeEscrow::ChannelSettled>().ok())
                    .map(|log| log.inner.paidNow)
                    .sum();

                ledger.mark_settled(channel_id);
                performed += 1;
                {
                    let mut counters = self.stats.lock().await;
                    counters.settlements += 1;
                    counters.paid_total += paid_now;
                }
                tracing::info!(
                    channel = %channel_id,
                    authorisations = batch.len(),
                    paid_now = %paid_now,
                    "settled on-chain"
                );
            }
        }

        self.pending_since_settle.store(0, Ordering::SeqCst);
        Ok(performed)
    }
}

/// Routes for the collector service.
pub fn router(state: SharedCollector) -> Router {
    Router::new()
        .route("/work", post(work))
        .route("/settle", post(settle))
        .route("/stats", get(stats))
        .with_state(state)
}

/// Serves `router` on `listener` until the returned handle is aborted.
pub fn serve(
    listener: tokio::net::TcpListener,
    state: SharedCollector,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router(state)).await {
            tracing::error!(error = %e, "collector stopped");
        }
    })
}

fn reject(reason: String) -> Response {
    (
        StatusCode::PAYMENT_REQUIRED,
        Json(WorkRejected {
            admitted: false,
            reason,
        }),
    )
        .into_response()
}

async fn work(
    State(state): State<SharedCollector>,
    Json(request): Json<ProofRequestV2>,
) -> Response {
    let payment = match request.payment() {
        Ok(Some(payment)) => payment,
        Ok(None) => return reject("request carries no payment authorisation".to_string()),
        Err(e) => return reject(e.to_string()),
    };
    let (channel_id, nonce) = payment;

    // The whole admission runs under the ledger lock, including the two chain reads. The fee
    // is priced off the ledger's own projection, so anything that mutates the ledger in
    // between would invalidate the quote.
    let outcome = {
        let mut ledger = state.ledger.lock().await;

        let view = match chain::read_channel_view(&state.provider, state.escrow, channel_id).await {
            Ok(view) => view,
            Err(e) => return reject(format!("cannot read channel: {e}")),
        };
        let projected =
            ledger.projected_total(channel_id, nonce.lane, nonce.counter, view.settled_count);
        let quoted =
            match chain::cumulative_fee(&state.provider, state.fee_schedule, projected).await {
                Ok(fee) => fee,
                Err(e) => return reject(format!("cannot price the fee: {e}")),
            };

        let fee = |count: U256| {
            debug_assert_eq!(
                count, projected,
                "admit priced a different total than projected_total"
            );
            quoted
        };
        ledger.admit(&request, &view, &fee, &state.domain)
    };

    match outcome {
        Ok(()) => {
            let sequence = state.sequence.fetch_add(1, Ordering::SeqCst);
            {
                let mut counters = state.stats.lock().await;
                counters.admitted += 1;
            }
            tracing::info!(
                lane = nonce.lane,
                counter = nonce.counter,
                "admitted, doing the work"
            );

            let pending = state.pending_since_settle.fetch_add(1, Ordering::SeqCst) + 1;
            if pending >= state.settle_every
                && let Err(e) = state.settle_all().await
            {
                tracing::error!(error = %e, "settlement failed");
            }

            Json(WorkAccepted {
                admitted: true,
                receipt: format!("deepface-mock-{sequence}"),
                lane: nonce.lane,
                counter: nonce.counter,
            })
            .into_response()
        }
        Err(e) => {
            let insolvent = matches!(e, AdmitError::Insolvent { .. });
            {
                let mut counters = state.stats.lock().await;
                if insolvent {
                    counters.rejected_insolvent += 1;
                } else {
                    counters.rejected_other += 1;
                }
            }
            tracing::warn!(
                lane = nonce.lane,
                counter = nonce.counter,
                error = %e,
                "refused"
            );
            reject(e.to_string())
        }
    }
}

async fn settle(State(state): State<SharedCollector>) -> Response {
    match state.settle_all().await {
        Ok(settlements) => Json(SettleReport {
            settlements,
            paid_total: state.stats().await.paid_total,
        })
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(WorkRejected {
                admitted: false,
                reason: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn stats(State(state): State<SharedCollector>) -> Response {
    Json(state.stats().await).into_response()
}
