use std::time::Duration;

use alloy::primitives::{address, Address, Bytes, U256};
use alloy::providers::{DynProvider, Provider};
use tokio::sync::mpsc;
use world_id_core::account_registry::AccountRegistry;

use crate::error::{parse_contract_error, ErrorCode};
use crate::{RequestState, RequestTracker};

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
        leaf_index: U256,
        old_authenticator_address: Address,
        new_authenticator_address: Address,
        old_commit: U256,
        new_commit: U256,
        signature: Bytes,
        sibling_nodes: Vec<U256>,
        nonce: U256,
        pubkey_id: u32,
        new_pubkey: U256,
    },
    Insert {
        leaf_index: U256,
        new_authenticator_address: Address,
        old_commit: U256,
        new_commit: U256,
        signature: Bytes,
        sibling_nodes: Vec<U256>,
        nonce: U256,
        pubkey_id: u32,
        new_pubkey: U256,
    },
    Remove {
        leaf_index: U256,
        authenticator_address: Address,
        old_commit: U256,
        new_commit: U256,
        signature: Bytes,
        sibling_nodes: Vec<U256>,
        nonce: U256,
        pubkey_id: u32,
        authenticator_pubkey: U256,
    },
    Recover {
        leaf_index: U256,
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

    pub async fn run(mut self) {
        let provider = self.provider.clone();
        let contract = AccountRegistry::new(self.registry, provider.clone());
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

            let ids: Vec<String> = batch.iter().map(|env| env.id.clone()).collect();
            self.tracker
                .set_status_batch(&ids, RequestState::Batching)
                .await;

            let mut calls: Vec<Multicall3::Call3> = Vec::with_capacity(batch.len());
            for env in &batch {
                let data: alloy::primitives::Bytes = match &env.kind {
                    OpKind::Update {
                        leaf_index,
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
                            *leaf_index,
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
                        leaf_index,
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
                            *leaf_index,
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
                        leaf_index,
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
                            *leaf_index,
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
                        leaf_index,
                        new_authenticator_address,
                        old_commit,
                        new_commit,
                        signature,
                        sibling_nodes,
                        nonce,
                        new_pubkey,
                    } => contract
                        .recoverAccount(
                            *leaf_index,
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
                    allowFailure: true,
                    callData: data,
                });
            }

            // When using allowFailure: true, gas estimation can be inaccurate because
            // Multicall3 doesn't revert on failed subcalls, so we estimate using
            // allowFailure: false to get the gas needed for successful execution.
            let estimation_calls: Vec<Multicall3::Call3> = calls
                .iter()
                .map(|c| Multicall3::Call3 {
                    target: c.target,
                    allowFailure: false,
                    callData: c.callData.clone(),
                })
                .collect();
            let estimated_gas = match mc.aggregate3(estimation_calls).estimate_gas().await {
                Ok(gas) => gas,
                Err(_e) => {
                    // If estimation fails (e.g. one of the calls would revert), use a generous default.
                    // This is expected when a subcall will fail.
                    500_000u64 * batch.len() as u64
                }
            };
            // Add 20% buffer to the estimated gas for safety
            let gas_limit = estimated_gas.saturating_mul(6).saturating_div(5);
            let res = mc.aggregate3(calls).gas(gas_limit).send().await;
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
                    let provider = self.provider.clone();
                    let registry = self.registry;
                    tokio::spawn(async move {
                        match builder.get_receipt().await {
                            Ok(receipt) => {
                                if receipt.status() {
                                    // Transaction succeeded. Since we set allowFailure=true in Multicall3,
                                    // we need to inspect which subcalls (to the registry) failed.
                                    // Try to debug_trace the transaction; if this fails (e.g. provider
                                    // does not support debug), fall back to marking all as finalized.
                                    let traced = provider
                                        .client()
                                        .request::<_, serde_json::Value>(
                                            "debug_traceTransaction",
                                            vec![
                                                serde_json::json!(hash.as_str()),
                                                serde_json::json!({ "tracer": "callTracer" }),
                                            ],
                                        )
                                        .await;

                                    match traced {
                                        Ok(trace) => {
                                            // Collect internal calls to the registry in execution order.
                                            fn collect_calls<'a>(
                                                v: &'a serde_json::Value,
                                                target_hex: &str,
                                                out: &mut Vec<&'a serde_json::Value>,
                                            ) {
                                                if let Some(obj) = v.as_object() {
                                                    if let Some(to) =
                                                        obj.get("to").and_then(|t| t.as_str())
                                                    {
                                                        if to.eq_ignore_ascii_case(target_hex) {
                                                            out.push(v);
                                                        }
                                                    }
                                                    if let Some(calls) =
                                                        obj.get("calls").and_then(|c| c.as_array())
                                                    {
                                                        for c in calls {
                                                            collect_calls(c, target_hex, out);
                                                        }
                                                    }
                                                }
                                            }

                                            let target_hex = format!("0x{:x}", registry);
                                            let mut subcalls: Vec<&serde_json::Value> = Vec::new();
                                            let root = trace.get("result").unwrap_or(&trace);
                                            collect_calls(root, &target_hex, &mut subcalls);

                                            // If counts mismatch, fall back to finalize-all to avoid mislabeling.
                                            if subcalls.len() != ids_for_receipt.len() {
                                                tracker
                                                    .set_status_batch(
                                                        &ids_for_receipt,
                                                        RequestState::Finalized {
                                                            tx_hash: hash.clone(),
                                                        },
                                                    )
                                                    .await;
                                            } else {
                                                // Map each subcall to success/failure and update corresponding request id.
                                                for (i, id) in ids_for_receipt.iter().enumerate() {
                                                    let sc = subcalls[i];
                                                    let error_str = sc
                                                        .get("error")
                                                        .and_then(|e| e.as_str())
                                                        .map(|s| s.to_string());
                                                    let failed_flag = sc
                                                        .get("reverted")
                                                        .and_then(|b| b.as_bool())
                                                        .unwrap_or(false)
                                                        || sc
                                                            .get("failed")
                                                            .and_then(|b| b.as_bool())
                                                            .unwrap_or(false);
                                                    // Try to extract revert data for better error code parsing.
                                                    let revert_data = sc
                                                        .get("output")
                                                        .and_then(|o| o.as_str())
                                                        .or_else(|| {
                                                            sc.get("revertReason")
                                                                .and_then(|o| o.as_str())
                                                        })
                                                        .or_else(|| {
                                                            sc.get("returnData")
                                                                .and_then(|o| o.as_str())
                                                        })
                                                        .map(|s| s.to_string());

                                                    if error_str.is_none() && !failed_flag {
                                                        // Success
                                                        tracker
                                                            .set_status(
                                                                id,
                                                                RequestState::Finalized {
                                                                    tx_hash: hash.clone(),
                                                                },
                                                            )
                                                            .await;
                                                    } else {
                                                        // Failure for this subcall: build message + code.
                                                        let code = revert_data
                                                            .as_ref()
                                                            .map(|data| parse_contract_error(data))
                                                            .or_else(|| {
                                                                error_str.as_ref().map(|err| {
                                                                    parse_contract_error(err)
                                                                })
                                                            });
                                                        let msg = if let Some(err) = error_str {
                                                            format!(
                                                                "multicall subcall failed: {err} (tx: {})",
                                                                hash
                                                            )
                                                        } else if let Some(data) = revert_data {
                                                            format!(
                                                                "multicall subcall reverted with data {data} (tx: {})",
                                                                hash
                                                            )
                                                        } else {
                                                            format!(
                                                                "multicall subcall failed (tx: {})",
                                                                hash
                                                            )
                                                        };
                                                        tracker
                                                            .set_status(
                                                                id,
                                                                RequestState::failed(msg, code),
                                                            )
                                                            .await;
                                                    }
                                                }
                                            }
                                        }
                                        Err(_e) => {
                                            // Provider doesn't support debug - finalize all.
                                            tracker
                                                .set_status_batch(
                                                    &ids_for_receipt,
                                                    RequestState::Finalized {
                                                        tx_hash: hash.clone(),
                                                    },
                                                )
                                                .await;
                                        }
                                    }
                                } else {
                                    tracker
                                        .set_status_batch(
                                            &ids_for_receipt,
                                            RequestState::failed(
                                                format!(
                                                    "transaction reverted on-chain (tx: {hash})"
                                                ),
                                                Some(ErrorCode::TransactionReverted),
                                            ),
                                        )
                                        .await;
                                }
                            }
                            Err(err) => {
                                tracker
                                    .set_status_batch(
                                        &ids_for_receipt,
                                        RequestState::failed(
                                            format!("transaction confirmation error: {err}"),
                                            Some(ErrorCode::ConfirmationError),
                                        ),
                                    )
                                    .await;
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "multicall3 send failed");
                    let error_str = e.to_string();
                    let code = parse_contract_error(&error_str);
                    self.tracker
                        .set_status_batch(&ids, RequestState::failed(error_str, Some(code)))
                        .await;
                }
            }
        }
    }
}
