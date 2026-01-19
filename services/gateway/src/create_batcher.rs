use std::sync::Arc;
use std::time::Duration;

use crate::request_tracker::RequestTracker;
use alloy::primitives::{Address, U256};
use alloy::providers::DynProvider;
use tokio::sync::mpsc;
use world_id_core::types::{
    parse_contract_error, CreateAccountRequest, GatewayErrorCode, GatewayRequestState,
};
use world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance;

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
                tracing::info!(target: "world_id_gateway::create_batcher", "create batcher channel closed");
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
                        tracing::info!(target: "world_id_gateway::create_batcher", "create batcher channel closed while batching");
                        break;
                    }
                    Err(_) => break, // Timeout expired
                }
            }

            let ids: Vec<String> = batch.iter().map(|env| env.id.clone()).collect();
            self.tracker
                .set_status_batch(&ids, GatewayRequestState::Batching)
                .await;

            let mut recovery_addresses: Vec<Address> = Vec::new();
            let mut auths: Vec<Vec<Address>> = Vec::new();
            let mut pubkeys: Vec<Vec<U256>> = Vec::new();
            let mut commits: Vec<U256> = Vec::new();

            for env in &batch {
                recovery_addresses.push(env.req.recovery_address.unwrap_or(Address::ZERO));
                auths.push(env.req.authenticator_addresses.clone());
                pubkeys.push(env.req.authenticator_pubkeys.clone());
                commits.push(env.req.offchain_signer_commitment);
            }

            let call =
                self.registry
                    .createManyAccounts(recovery_addresses, auths, pubkeys, commits);
            match call.send().await {
                Ok(builder) => {
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
                    let ids_for_receipt = ids.clone();
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
                Err(err) => {
                    tracing::error!(target: "world_id_gateway::create_batcher", error = %err, "create batch send failed");
                    let error_str = err.to_string();
                    let code = parse_contract_error(&error_str);
                    self.tracker
                        .set_status_batch(&ids, GatewayRequestState::failed(error_str, Some(code)))
                        .await;
                }
            }
        }
    }
}
