use std::time::Duration;

use alloy::primitives::{Address, U256};
use alloy::providers::DynProvider;
use tokio::sync::mpsc;
use world_id_core::account_registry::AccountRegistry;
use world_id_core::types::CreateAccountRequest;

use crate::{RequestState, RequestTracker};

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
    provider: DynProvider,
    registry: Address,
    window: Duration,
    max_batch_size: usize,
    tracker: RequestTracker,
}

impl CreateBatcherRunner {
    pub fn new(
        provider: DynProvider,
        registry: Address,
        window: Duration,
        max_batch_size: usize,
        rx: mpsc::Receiver<CreateReqEnvelope>,
        tracker: RequestTracker,
    ) -> Self {
        Self {
            rx,
            provider,
            registry,
            window,
            max_batch_size,
            tracker,
        }
    }

    pub async fn run(mut self) {
        let provider = self.provider.clone();
        let contract = AccountRegistry::new(self.registry, provider);

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

            let ids: Vec<String> = batch.iter().map(|env| env.id.clone()).collect();
            self.tracker
                .set_status_batch(&ids, RequestState::Batching)
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

            let call = contract.createManyAccounts(recovery_addresses, auths, pubkeys, commits);
            match call.send().await {
                Ok(builder) => {
                    let hash = format!("0x{:x}", builder.tx_hash());
                    self.tracker
                        .set_status_batch(
                            &ids,
                            RequestState::Submitted {
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
                                            RequestState::Finalized {
                                                tx_hash: hash.clone(),
                                            },
                                        )
                                        .await;
                                } else {
                                    tracker
                                        .set_status_batch(
                                            &ids_for_receipt,
                                            RequestState::Failed {
                                                error: format!(
                                                    "transaction reverted on-chain (tx: {hash})"
                                                ),
                                            },
                                        )
                                        .await;
                                }
                            }
                            Err(err) => {
                                tracker
                                    .set_status_batch(
                                        &ids_for_receipt,
                                        RequestState::Failed {
                                            error: format!("transaction confirmation error: {err}"),
                                        },
                                    )
                                    .await;
                            }
                        }
                    });
                }
                Err(err) => {
                    tracing::error!(error = %err, "create batch send failed");
                    self.tracker
                        .set_status_batch(
                            &ids,
                            RequestState::Failed {
                                error: err.to_string(),
                            },
                        )
                        .await;
                }
            }
        }
    }
}
