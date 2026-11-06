//! Relay of WIP-107 `WorldIDBilling.register` calls.
//!
//! Registrations skip the batch queue: each one is its own transaction, sent while its request
//! is being handled. Registrations of one RP share its period capacity and nonces, so in a shared
//! all-or-nothing batch one that reverts at inclusion would revert the others; and a queue drained
//! one transaction per policy tick would let a burst outlive the orphan sweeper's
//! queued-request deadline.
//!
//! A registration is tracked only once it holds the transaction lock, and is sent right after,
//! so a tracked registration is never left waiting where the sweeper could fail it. It waits for
//! the lock only until half the request timeout has passed since the request arrived, and is
//! dropped untracked if its request is gone by then, so a client that timed out never has its
//! registration sent behind its back. One that cannot get the lock in time is rejected with 503,
//! untracked.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use alloy::{
    primitives::{Bytes, TxKind},
    providers::Provider as _,
    rpc::types::TransactionRequest,
    transports::RpcError,
};
use axum::http::StatusCode;
use tokio::{
    sync::{Mutex, Semaphore},
    time::Instant,
};
use uuid::Uuid;
use world_id_primitives::api_types::{GatewayErrorCode, GatewayRequestKind, GatewayRequestState};

use crate::{
    error::{GatewayErrorResponse, parse_contract_error},
    metrics,
    request::Billing,
    request_tracker::RequestTracker,
};

/// Registrations a gateway handles at once, those waiting for the transaction lock included; more
/// are rejected with 503.
pub(crate) const MAX_IN_FLIGHT_SENDS: usize = 64;

const BATCH_TYPE: &str = "billing";

/// The Billing Contract and what sending to it needs.
#[derive(Clone)]
pub struct BillingRelay {
    /// The Billing Contract, with the gateway's provider and signer.
    pub contract: Arc<Billing>,
    tracker: RequestTracker,
    /// Shared with the batchers, which use the same signer.
    tx_send_lock: Arc<Mutex<()>>,
    /// How long after its request arrived a registration may still take `tx_send_lock`: half the
    /// request timeout, leaving the rest for tracking and sending it.
    lock_deadline: Duration,
    in_flight: Arc<Semaphore>,
}

impl BillingRelay {
    pub(crate) fn new(
        contract: Arc<Billing>,
        tracker: RequestTracker,
        tx_send_lock: Arc<Mutex<()>>,
        request_timeout: Duration,
    ) -> Self {
        Self {
            contract,
            tracker,
            tx_send_lock,
            lock_deadline: request_timeout / 2,
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT_SENDS)),
        }
    }

    /// Tracks request `id`, which arrived at `received_at`, and sends its `register` call,
    /// returning the transaction hash.
    ///
    /// Rejects the registration with 503, untracked, while [`MAX_IN_FLIGHT_SENDS`] are in flight
    /// or if the transaction lock stays busy until half the request timeout has passed.
    pub(crate) async fn submit(
        &self,
        received_at: Instant,
        id: Uuid,
        kind: GatewayRequestKind,
        inflight_keys: Vec<String>,
        calldata: Bytes,
    ) -> Result<String, GatewayErrorResponse> {
        let permit = self
            .in_flight
            .clone()
            .try_acquire_owned()
            .map_err(|_| busy("Too many billing registrations in flight."))?;
        let relay = self.clone();
        let caller = CallerGuard::new();
        let caller_waiting = caller.0.clone();
        // Spawned so that a request timeout cannot interrupt it between tracking the request and
        // recording the sent transaction.
        let task = tokio::spawn(async move {
            let _permit = permit;
            let deadline = received_at + relay.lock_deadline;
            let _send_guard = tokio::time::timeout_at(deadline, relay.tx_send_lock.lock())
                .await
                .map_err(|_| busy("The gateway is busy sending transactions."))?;
            // A caller that timed out has no request ID to follow the registration with, so it is
            // dropped untracked; nobody receives this error.
            if !caller_waiting.load(Ordering::Acquire) {
                tracing::warn!(request_id = %id, "billing registration dropped: its request is gone");
                return Err(busy("The request timed out."));
            }
            relay
                .tracker
                .new_request_with_id(id.to_string(), kind, inflight_keys)
                .await?;
            relay.send(id.to_string(), calldata).await
        });
        let result = task.await;
        drop(caller);
        result.map_err(|err| {
            tracing::error!(request_id = %id, error = %err, "billing send task failed");
            GatewayErrorResponse::internal_server_error()
        })?
    }

    /// Sends the tracked request `id`'s `register` call and tracks its receipt. The caller holds
    /// the transaction lock.
    async fn send(&self, id: String, calldata: Bytes) -> Result<String, GatewayErrorResponse> {
        metrics::record_batch_submitted(BATCH_TYPE, 1);
        let tx = TransactionRequest {
            to: Some(TxKind::Call(*self.contract.address())),
            input: calldata.into(),
            ..Default::default()
        };
        let start = Instant::now();
        // No explicit gas limit: the provider's gas filler estimates it.
        match self.contract.provider().send_transaction(tx).await {
            Ok(builder) => {
                let tx_hash = format!("0x{:x}", builder.tx_hash());
                metrics::record_batch_send_latency(BATCH_TYPE, start.elapsed().as_millis() as f64);
                self.tracker
                    .set_status(
                        &id,
                        GatewayRequestState::Submitted {
                            tx_hash: tx_hash.clone(),
                        },
                    )
                    .await;
                self.tracker.spawn_receipt_tracker(
                    vec![id],
                    builder,
                    tx_hash.clone(),
                    BATCH_TYPE,
                    start,
                );
                Ok(tx_hash)
            }
            Err(err) => {
                metrics::record_batch_send_failed(BATCH_TYPE, start.elapsed().as_millis() as f64);
                let error = err.to_string();
                tracing::error!(request_id = %id, %error, "billing registration failed to send");
                let code = parse_contract_error(&error);
                self.tracker
                    .set_status(&id, GatewayRequestState::failed(error.clone(), Some(code)))
                    .await;
                // A JSON-RPC error response is the node rejecting the transaction, e.g. a revert
                // during gas estimation since the simulation; anything else is the node being
                // unreachable.
                Err(match err {
                    RpcError::ErrorResp(_) => GatewayErrorResponse::from_simulation_error(error),
                    _ => GatewayErrorResponse::new(
                        GatewayErrorCode::BatcherUnavailable,
                        "Failed to reach the chain. Please try again.".to_string(),
                        StatusCode::SERVICE_UNAVAILABLE,
                    ),
                })
            }
        }
    }
}

/// Set while the request handler waits for the registration, cleared when it stops waiting, e.g.
/// on a request timeout.
struct CallerGuard(Arc<AtomicBool>);

impl CallerGuard {
    fn new() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }
}

impl Drop for CallerGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// A registration rejected, untracked, because the gateway cannot send it in time.
fn busy(reason: &str) -> GatewayErrorResponse {
    metrics::record_billing_rejected_busy();
    GatewayErrorResponse::new(
        GatewayErrorCode::BatcherUnavailable,
        format!("{reason} Please try again."),
        StatusCode::SERVICE_UNAVAILABLE,
    )
}
