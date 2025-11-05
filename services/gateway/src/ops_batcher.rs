use std::time::Duration;

use alloy::primitives::{address, Address, Bytes, U256};
use alloy::providers::DynProvider;
use tokio::sync::mpsc;
use world_id_core::account_registry::AccountRegistry;

use crate::{GatewayError, RequestState, RequestTracker};

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
    pub tx: mpsc::Sender<OpEnvelope>,
}

#[derive(Debug)]
pub enum OpKind {
    Update {
        account_index: U256,
        old_authenticator_address: Address,
        new_authenticator_address: Address,
        old_commit: U256,
        new_commit: U256,
        signature: Bytes,
        sibling_nodes: Vec<U256>,
        nonce: U256,
        pubkey_id: U256,
        new_pubkey: U256,
    },
    Insert {
        account_index: U256,
        new_authenticator_address: Address,
        old_commit: U256,
        new_commit: U256,
        signature: Bytes,
        sibling_nodes: Vec<U256>,
        nonce: U256,
        pubkey_id: U256,
        new_pubkey: U256,
    },
    Remove {
        account_index: U256,
        authenticator_address: Address,
        old_commit: U256,
        new_commit: U256,
        signature: Bytes,
        sibling_nodes: Vec<U256>,
        nonce: U256,
        pubkey_id: U256,
        authenticator_pubkey: U256,
    },
    Recover {
        account_index: U256,
        new_authenticator_address: Address,
        old_commit: U256,
        new_commit: U256,
        signature: Bytes,
        sibling_nodes: Vec<U256>,
        nonce: U256,
        new_pubkey: U256,
    },
}

#[derive(Debug)]
pub struct OpEnvelope {
    pub id: String,
    pub kind: OpKind,
}

pub struct OpsBatcherRunner {
    rx: mpsc::Receiver<OpEnvelope>,
    provider: DynProvider,
    registry: Address,
    window: Duration,
    max_batch_size: usize,
    tracker: RequestTracker,
}

impl OpsBatcherRunner {
    pub fn new(
        provider: DynProvider,
        registry: Address,
        window: Duration,
        max_batch_size: usize,
        rx: mpsc::Receiver<OpEnvelope>,
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

    /// Simulate an operation to check if it would revert without spending gas
    async fn simulate_operation(
        contract: &AccountRegistry::AccountRegistryInstance<DynProvider>,
        kind: &OpKind,
    ) -> Result<(), String> {
        match kind {
            OpKind::Update {
                account_index,
                old_authenticator_address,
                new_authenticator_address,
                old_commit,
                new_commit,
                signature,
                sibling_nodes,
                nonce,
                pubkey_id,
                new_pubkey,
            } => {
                contract
                    .updateAuthenticator(
                        *account_index,
                        *old_authenticator_address,
                        *new_authenticator_address,
                        *pubkey_id,
                        *new_pubkey,
                        *old_commit,
                        *new_commit,
                        signature.clone(),
                        sibling_nodes.clone(),
                        *nonce,
                    )
                    .call()
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
            OpKind::Insert {
                account_index,
                new_authenticator_address,
                old_commit,
                new_commit,
                signature,
                sibling_nodes,
                nonce,
                pubkey_id,
                new_pubkey,
            } => {
                contract
                    .insertAuthenticator(
                        *account_index,
                        *new_authenticator_address,
                        *pubkey_id,
                        *new_pubkey,
                        *old_commit,
                        *new_commit,
                        signature.clone(),
                        sibling_nodes.clone(),
                        *nonce,
                    )
                    .call()
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
            OpKind::Remove {
                account_index,
                authenticator_address,
                old_commit,
                new_commit,
                signature,
                sibling_nodes,
                nonce,
                pubkey_id,
                authenticator_pubkey,
            } => {
                contract
                    .removeAuthenticator(
                        *account_index,
                        *authenticator_address,
                        *pubkey_id,
                        *authenticator_pubkey,
                        *old_commit,
                        *new_commit,
                        signature.clone(),
                        sibling_nodes.clone(),
                        *nonce,
                    )
                    .call()
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
            OpKind::Recover {
                account_index,
                new_authenticator_address,
                old_commit,
                new_commit,
                signature,
                sibling_nodes,
                nonce,
                new_pubkey,
            } => {
                contract
                    .recoverAccount(
                        *account_index,
                        *new_authenticator_address,
                        *new_pubkey,
                        *old_commit,
                        *new_commit,
                        signature.clone(),
                        sibling_nodes.clone(),
                        *nonce,
                    )
                    .call()
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
        }
    }

    pub async fn run(mut self) {
        let provider = self.provider.clone();
        let contract = AccountRegistry::new(self.registry, provider.clone());
        let mc = Multicall3::new(MULTICALL3_ADDR, provider);

        loop {
            let Some(first) = self.rx.recv().await else {
                tracing::info!("ops batcher channel closed");
                return;
            };

            // Simulate the first operation before starting a batch
            if let Err(sim_error) = Self::simulate_operation(&contract, &first.kind).await {
                tracing::warn!(id = %first.id, error = %sim_error, "operation pre-flight simulation failed");
                // Parse the error to get a specific error code if possible
                let err = GatewayError::from_contract_error(&sim_error);
                let err = match err {
                    GatewayError::Unknown(msg) => GatewayError::PreFlightFailed(msg),
                    specific => specific,
                };
                self.tracker
                    .set_status(&first.id, RequestState::failed_from_error(err))
                    .await;
                continue; // Skip this operation and wait for the next one
            }

            let mut batch = vec![first];
            let deadline = tokio::time::Instant::now() + self.window;

            loop {
                if batch.len() >= self.max_batch_size {
                    break;
                }
                match tokio::time::timeout_at(deadline, self.rx.recv()).await {
                    Ok(Some(req)) => {
                        // Simulate each additional operation before adding to batch
                        if let Err(sim_error) = Self::simulate_operation(&contract, &req.kind).await {
                            tracing::warn!(id = %req.id, error = %sim_error, "operation pre-flight simulation failed");
                            // Parse the error to get a specific error code if possible
                            let err = GatewayError::from_contract_error(&sim_error);
                            let err = match err {
                                GatewayError::Unknown(msg) => GatewayError::PreFlightFailed(msg),
                                specific => specific,
                            };
                            self.tracker
                                .set_status(&req.id, RequestState::failed_from_error(err))
                                .await;
                            // Skip this operation but continue batching
                        } else {
                            batch.push(req);
                        }
                    }
                    Ok(None) => {
                        tracing::info!("ops batcher channel closed while batching");
                        break;
                    }
                    Err(_) => break, // Timeout expired
                }
            }

            let ids: Vec<String> = batch.iter().map(|env| env.id.clone()).collect();
            self.tracker
                .set_status_batch(&ids, RequestState::Batching)
                .await;

            let mut calls: Vec<Multicall3::Call3> = Vec::with_capacity(batch.len());
            for env in &batch {
                let data: alloy::primitives::Bytes = match &env.kind {
                    OpKind::Update {
                        account_index,
                        old_authenticator_address,
                        new_authenticator_address,
                        old_commit,
                        new_commit,
                        signature,
                        sibling_nodes,
                        nonce,
                        pubkey_id,
                        new_pubkey,
                    } => contract
                        .updateAuthenticator(
                            *account_index,
                            *old_authenticator_address,
                            *new_authenticator_address,
                            *pubkey_id,
                            *new_pubkey,
                            *old_commit,
                            *new_commit,
                            signature.clone(),
                            sibling_nodes.clone(),
                            *nonce,
                        )
                        .calldata()
                        .clone(),
                    OpKind::Insert {
                        account_index,
                        new_authenticator_address,
                        old_commit,
                        new_commit,
                        signature,
                        sibling_nodes,
                        nonce,
                        pubkey_id,
                        new_pubkey,
                    } => contract
                        .insertAuthenticator(
                            *account_index,
                            *new_authenticator_address,
                            *pubkey_id,
                            *new_pubkey,
                            *old_commit,
                            *new_commit,
                            signature.clone(),
                            sibling_nodes.clone(),
                            *nonce,
                        )
                        .calldata()
                        .clone(),
                    OpKind::Remove {
                        account_index,
                        authenticator_address,
                        old_commit,
                        new_commit,
                        signature,
                        sibling_nodes,
                        nonce,
                        pubkey_id,
                        authenticator_pubkey,
                    } => contract
                        .removeAuthenticator(
                            *account_index,
                            *authenticator_address,
                            *pubkey_id,
                            *authenticator_pubkey,
                            *old_commit,
                            *new_commit,
                            signature.clone(),
                            sibling_nodes.clone(),
                            *nonce,
                        )
                        .calldata()
                        .clone(),
                    OpKind::Recover {
                        account_index,
                        new_authenticator_address,
                        old_commit,
                        new_commit,
                        signature,
                        sibling_nodes,
                        nonce,
                        new_pubkey,
                    } => contract
                        .recoverAccount(
                            *account_index,
                            *new_authenticator_address,
                            *new_pubkey,
                            *old_commit,
                            *new_commit,
                            signature.clone(),
                            sibling_nodes.clone(),
                            *nonce,
                        )
                        .calldata()
                        .clone(),
                };
                calls.push(Multicall3::Call3 {
                    target: self.registry,
                    allowFailure: false,
                    callData: data,
                });
            }

            let res = mc.aggregate3(calls).send().await;
            match res {
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
                                    let err = GatewayError::TransactionReverted(hash.clone());
                                    tracker
                                        .set_status_batch(
                                            &ids_for_receipt,
                                            RequestState::failed_from_error(err),
                                        )
                                        .await;
                                }
                            }
                            Err(err) => {
                                let err = GatewayError::ConfirmationError(err.to_string());
                                tracker
                                    .set_status_batch(
                                        &ids_for_receipt,
                                        RequestState::failed_from_error(err),
                                    )
                                    .await;
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "multicall3 send failed");
                    let err = GatewayError::Unknown(e.to_string());
                    self.tracker
                        .set_status_batch(&ids, RequestState::failed_from_error(err))
                        .await;
                }
            }
        }
    }
}
