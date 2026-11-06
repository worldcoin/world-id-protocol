//! Relay of WIP-107 `WorldIDBilling.register` calls.
//!
//! Registrations skip the batch queue: each one is its own transaction, sent while its request
//! is being handled. Registrations of one RP share its period capacity and nonces, so in a shared
//! all-or-nothing batch one that reverts at inclusion would revert the others; and a queue drained
//! one transaction per policy tick would let a burst outlive the orphan sweeper's
//! queued-request deadline. An accepted registration has therefore already been sent, and a
//! gateway with too many sends in flight rejects new ones instead of accepting them.

use std::sync::Arc;

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
use world_id_primitives::api_types::{GatewayErrorCode, GatewayRequestState};

use crate::{
    error::{GatewayErrorResponse, parse_contract_error},
    metrics,
    request::Billing,
    request_tracker::RequestTracker,
};

/// Registrations a gateway sends at once, waiting ones included; more are rejected with 503.
/// Sends are serialized by the shared transaction lock, so this bounds how long a request waits
/// for it.
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
    in_flight: Arc<Semaphore>,
}

impl BillingRelay {
    pub(crate) fn new(
        contract: Arc<Billing>,
        tracker: RequestTracker,
        tx_send_lock: Arc<Mutex<()>>,
    ) -> Self {
        Self {
            contract,
            tracker,
            tx_send_lock,
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT_SENDS)),
        }
    }

    /// Reserves a send slot, or rejects the registration while [`MAX_IN_FLIGHT_SENDS`] are in
    /// flight.
    pub(crate) fn reserve(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, GatewayErrorResponse> {
        self.in_flight.clone().try_acquire_owned().map_err(|_| {
            metrics::record_billing_rejected_busy();
            GatewayErrorResponse::new(
                GatewayErrorCode::BatcherUnavailable,
                "Too many billing registrations in flight. Please try again.".to_string(),
                StatusCode::SERVICE_UNAVAILABLE,
            )
        })
    }

    /// Sends the tracked request `id`'s `register` call and tracks its receipt, returning the
    /// transaction hash. Runs to completion even if the caller stops waiting, so the request's
    /// status is always settled.
    pub(crate) async fn send(
        &self,
        id: String,
        calldata: Bytes,
        _permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<String, GatewayErrorResponse> {
        metrics::record_batch_submitted(BATCH_TYPE, 1);
        self.tracker
            .set_status(&id, GatewayRequestState::Batching)
            .await;

        let tx = TransactionRequest {
            to: Some(TxKind::Call(*self.contract.address())),
            input: calldata.into(),
            ..Default::default()
        };
        let _send_guard = self.tx_send_lock.lock().await;
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
