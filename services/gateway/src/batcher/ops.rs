//! Operations batcher for insert/remove/recover/update operations.
//!
//! This batcher collects operations and submits them via Multicall3.
//! Gas estimation is handled automatically by the `GasEstimateWithFallbackFiller`
//! in the shared provider stack.

use std::sync::Arc;

use alloy::{
    primitives::{Address, Bytes, address},
    providers::{DynProvider, Provider},
    rpc::json_rpc::RpcError,
};
use tokio::sync::mpsc;
use world_id_registries::world_id::WorldIdRegistry::WorldIdRegistryInstance;

use crate::request_tracker::BacklogScope;

use super::{BatchSubmitStrategy, BatcherEnvelope, GenericBatcherRunner, PendingBatchTx};

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

/// Envelope for ops batcher containing pre-computed calldata for a single
/// registry operation.
#[derive(Debug)]
pub struct OpsEnvelope {
    pub id: String,
    pub calldata: Bytes,
}

impl BatcherEnvelope for OpsEnvelope {
    fn request_id(&self) -> &str {
        &self.id
    }
}

#[derive(Default)]
pub(crate) struct OpsStrategy;

impl BatchSubmitStrategy<OpsEnvelope> for OpsStrategy {
    fn batch_type(&self) -> &'static str {
        "ops"
    }

    fn backlog_scope(&self) -> BacklogScope {
        BacklogScope::Ops
    }

    async fn send_batch(
        &self,
        registry: &WorldIdRegistryInstance<Arc<DynProvider>>,
        batch: Vec<OpsEnvelope>,
    ) -> Result<PendingBatchTx, alloy::contract::Error> {
        let mc = Multicall3::new(MULTICALL3_ADDR, registry.provider().clone());

        let calls: Vec<Multicall3::Call3> = batch
            .into_iter()
            .map(|envelope| Multicall3::Call3 {
                target: *registry.address(),
                allowFailure: false,
                callData: envelope.calldata,
            })
            .collect();

        // Pre-flight: check whether the assembled Multicall3 call would
        // revert before committing to the submit path.  If `estimate_gas`
        // returns a JSON-RPC execution error we still proceed — the
        // GasEstimateWithFallbackFiller will use the fallback gas limit so
        // that the transaction can be sent to avoid a nonce gap — but we
        // flag the result so the receipt handler can log/metric it
        // separately from unexpected reverts.
        let expected_revert = match registry
            .provider()
            .clone()
            .estimate_gas(
                mc.aggregate3(calls.clone()).into_transaction_request(),
            )
            .await
        {
            Ok(_) => false,
            Err(RpcError::ErrorResp(ref error)) => {
                tracing::warn!(
                    %error,
                    "pre-flight eth_estimateGas indicates batch will revert; \
                     submitting anyway to avoid nonce gap"
                );
                true
            }
            // Transport / infrastructure errors: don't block submission, but
            // don't mark as expected either — we don't know what will happen.
            Err(_) => false,
        };

        let builder = mc.aggregate3(calls).send().await?;

        if expected_revert {
            Ok(PendingBatchTx::new_expected_revert(builder))
        } else {
            Ok(PendingBatchTx::new(builder))
        }
    }
}

pub type OpsBatcherRunner = GenericBatcherRunner<OpsEnvelope, OpsStrategy>;
