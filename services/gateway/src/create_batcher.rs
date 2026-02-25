use std::{sync::Arc, time::Duration};

use crate::{
    RequestTracker,
    error::parse_contract_error,
    metrics::{
        METRICS_BATCH_FAILURE, METRICS_BATCH_LATENCY_MS, METRICS_BATCH_SIZE,
        METRICS_BATCH_SUBMITTED, METRICS_BATCH_SUCCESS,
    },
};
use alloy::{
    primitives::{Address, U256},
    providers::DynProvider,
};
use tokio::sync::mpsc;
use world_id_core::{
    api_types::{CreateAccountRequest, GatewayErrorCode, GatewayRequestState},
    world_id_registry::WorldIdRegistry::WorldIdRegistryInstance,
};

#[derive(Clone)]
pub struct CreateBatcherHandle {
    pub tx: mpsc::Sender<CreateReqEnvelope>,
}

#[derive(Debug)]
pub struct CreateReqEnvelope {
    pub id: String,
    pub req: CreateAccountRequest,
}

pub struct CreateBatcherRunner {
    rx: mpsc::Receiver<CreateReqEnvelope>,
    registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
    window: Duration,
    max_batch_size: usize,
    tracker: RequestTracker,
}

impl CreateBatcherRunner {
    pub fn new(
        registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
        window: Duration,
        max_batch_size: usize,
        rx: mpsc::Receiver<CreateReqEnvelope>,
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
        loop {
            let Some(first) = self.rx.recv().await else {
                tracing::info!("create batcher channel closed");
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
                        tracing::info!("create batcher channel closed while batching");
                        break;
                    }
                    Err(_) => break, // Timeout expired
                }
            }

            let batch_size = batch.len();
            let ids: Vec<String> = batch.iter().map(|env| env.id.clone()).collect();

            ::metrics::counter!(METRICS_BATCH_SUBMITTED, "type" => "create").increment(1);
            ::metrics::histogram!(METRICS_BATCH_SIZE, "type" => "create").record(batch_size as f64);

            self.tracker
                .set_status_batch(&ids, GatewayRequestState::Batching)
                .await;

            let mut recovery_addresses: Vec<Address> = Vec::new();
            let mut auths: Vec<Vec<Address>> = Vec::new();
            let mut pubkeys: Vec<Vec<U256>> = Vec::new();
            let mut commits: Vec<U256> = Vec::new();

            // Collect all authenticator addresses from this batch for cache cleanup
            let mut all_addresses: Vec<Address> = Vec::new();
            for env in batch {
                all_addresses.extend(env.req.authenticator_addresses.iter());
                recovery_addresses.push(env.req.recovery_address.unwrap_or(Address::ZERO));
                auths.push(env.req.authenticator_addresses);
                pubkeys.push(env.req.authenticator_pubkeys);
                commits.push(env.req.offchain_signer_commitment);
            }

            let call =
                self.registry
                    .createManyAccounts(recovery_addresses, auths, pubkeys, commits);

            let start = std::time::Instant::now();
            match call.send().await {
                Ok(builder) => {
                    let latency_ms = start.elapsed().as_millis() as f64;
                    ::metrics::histogram!(METRICS_BATCH_LATENCY_MS, "type" => "create")
                        .record(latency_ms);
                    ::metrics::counter!(METRICS_BATCH_SUCCESS, "type" => "create").increment(1);

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
                    let addresses_for_cleanup = all_addresses;
                    tokio::spawn(async move {
                        match builder.get_receipt().await {
                            Ok(receipt) => {
                                tracker
                                    .finalize_from_receipt(
                                        &ids_for_receipt,
                                        receipt.status(),
                                        &hash,
                                    )
                                    .await;
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
                        // Remove all addresses from the in-flight tracker after finalization
                        tracker.remove_inflight(&addresses_for_cleanup).await;
                    });
                }
                Err(err) => {
                    let latency_ms = start.elapsed().as_millis() as f64;
                    ::metrics::histogram!(METRICS_BATCH_LATENCY_MS, "type" => "create")
                        .record(latency_ms);
                    ::metrics::counter!(METRICS_BATCH_FAILURE, "type" => "create").increment(1);

                    tracing::error!(error = %err, "create batch send failed");
                    let error_str = err.to_string();
                    let code = parse_contract_error(&error_str);
                    self.tracker
                        .set_status_batch(&ids, GatewayRequestState::failed(error_str, Some(code)))
                        .await;
                    // Remove all addresses from the in-flight tracker on send failure
                    self.tracker.remove_inflight(&all_addresses).await;
                }
            }
        }
    }
}
