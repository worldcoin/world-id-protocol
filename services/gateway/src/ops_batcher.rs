//! Operations batcher for insert/remove/recover/update operations.
//!
//! This batcher collects operations and submits them via Multicall3.

use std::{sync::Arc, time::Duration};

use crate::{
    RequestTracker,
    metrics::{
        METRICS_BATCH_FAILURE, METRICS_BATCH_LATENCY_MS, METRICS_BATCH_SIZE,
        METRICS_BATCH_SUBMITTED, METRICS_BATCH_SUCCESS,
    },
};
use alloy::{
    primitives::{Address, Bytes, address},
    providers::DynProvider,
};
use tokio::sync::mpsc;
use world_id_core::{
    types::{GatewayErrorCode, GatewayRequestState, parse_contract_error},
    world_id_registry::WorldIdRegistry::WorldIdRegistryInstance,
};

const MULTICALL3_ADDR: Address = address!("0xca11bde05977b3631167028862be2a173976ca11");

alloy::sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract Multicall3 {
        struct Call3 { address target; bool allowFailure; bytes callData; }
        struct Result { bool success; bytes returnData; }
        function aggregate3(Call3[] calldata calls) payable returns (Result[] memory returnData);
    }
}

#[derive(Clone)]
pub struct OpsBatcherHandle {
    pub tx: mpsc::Sender<OpsEnvelope>,
}

/// Envelope for ops batcher containing pre-computed calldata.
#[derive(Debug)]
pub struct OpsEnvelope {
    pub id: String,
    pub calldata: Bytes,
}

pub struct OpsBatcherRunner {
    rx: mpsc::Receiver<OpsEnvelope>,
    registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
    window: Duration,
    max_batch_size: usize,
    tracker: RequestTracker,
}

impl OpsBatcherRunner {
    pub fn new(
        registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
        window: Duration,
        max_batch_size: usize,
        rx: mpsc::Receiver<OpsEnvelope>,
        tracker: RequestTracker,
    ) -> Self {
        Self {
            rx,
            registry,
            window,
            max_batch_size,
            tracker,
        }
    }

    pub async fn run(mut self) {
        let provider = self.registry.provider();
        let mc = Multicall3::new(MULTICALL3_ADDR, provider);

        loop {
            let Some(first) = self.rx.recv().await else {
                tracing::info!("ops batcher channel closed");
                return;
            };

            let mut batch = vec![first];
            let deadline = tokio::time::Instant::now() + self.window;

            loop {
                if batch.len() >= self.max_batch_size {
                    break;
                }
                match tokio::time::timeout_at(deadline, self.rx.recv()).await {
                    Ok(Some(req)) => batch.push(req),
                    Ok(None) => {
                        tracing::info!("ops batcher channel closed while batching");
                        break;
                    }
                    Err(_) => break, // Timeout expired
                }
            }

            let batch_size = batch.len();
            let ids: Vec<String> = batch.iter().map(|env| env.id.clone()).collect();

            ::metrics::counter!(METRICS_BATCH_SUBMITTED, "type" => "ops").increment(1);
            ::metrics::histogram!(METRICS_BATCH_SIZE, "type" => "ops").record(batch_size as f64);

            self.tracker
                .set_status_batch(&ids, GatewayRequestState::Batching)
                .await;

            let calls: Vec<Multicall3::Call3> = batch
                .into_iter()
                .map(|env| Multicall3::Call3 {
                    target: *self.registry.address(),
                    allowFailure: false,
                    callData: env.calldata,
                })
                .collect();

            let start = std::time::Instant::now();
            let res = mc.aggregate3(calls).send().await;
            match res {
                Ok(builder) => {
                    let latency_ms = start.elapsed().as_millis() as f64;
                    ::metrics::histogram!(METRICS_BATCH_LATENCY_MS, "type" => "ops")
                        .record(latency_ms);
                    ::metrics::counter!(METRICS_BATCH_SUCCESS, "type" => "ops").increment(1);

                    let hash = format!("0x{:x}", builder.tx_hash());
                    self.tracker
                        .set_status_batch(
                            &ids,
                            GatewayRequestState::Submitted {
                                tx_hash: hash.clone(),
                            },
                        )
                        .await;

                    let tracker = self.tracker.clone();
                    let ids_for_receipt = ids;
                    tokio::spawn(async move {
                        match builder.get_receipt().await {
                            Ok(receipt) => {
                                if receipt.status() {
                                    tracker
                                        .set_status_batch(
                                            &ids_for_receipt,
                                            GatewayRequestState::Finalized {
                                                tx_hash: hash.clone(),
                                            },
                                        )
                                        .await;
                                } else {
                                    tracker
                                        .set_status_batch(
                                            &ids_for_receipt,
                                            GatewayRequestState::failed(
                                                format!(
                                                    "transaction reverted on-chain (tx: {hash})"
                                                ),
                                                Some(GatewayErrorCode::TransactionReverted),
                                            ),
                                        )
                                        .await;
                                }
                            }
                            Err(err) => {
                                tracker
                                    .set_status_batch(
                                        &ids_for_receipt,
                                        GatewayRequestState::failed(
                                            format!("transaction confirmation error: {err}"),
                                            Some(GatewayErrorCode::ConfirmationError),
                                        ),
                                    )
                                    .await;
                            }
                        }
                    });
                }
                Err(e) => {
                    let latency_ms = start.elapsed().as_millis() as f64;
                    ::metrics::histogram!(METRICS_BATCH_LATENCY_MS, "type" => "ops")
                        .record(latency_ms);
                    ::metrics::counter!(METRICS_BATCH_FAILURE, "type" => "ops").increment(1);

                    tracing::warn!(error = %e, "multicall3 send failed");
                    let error_str = e.to_string();
                    let code = parse_contract_error(&error_str);
                    self.tracker
                        .set_status_batch(&ids, GatewayRequestState::failed(error_str, Some(code)))
                        .await;
                }
            }
        }
    }
}
