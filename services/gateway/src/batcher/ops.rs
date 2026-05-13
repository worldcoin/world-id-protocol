//! Operations batcher for insert/remove/recover/update operations.
//!
//! This batcher collects operations and submits them via Multicall3.

use std::sync::Arc;

use alloy::{
    primitives::{Address, Bytes, address},
    providers::{DynProvider, Provider},
    rpc::json_rpc::RpcError,
};
use tokio::sync::mpsc;
use world_id_registries::world_id::WorldIdRegistry::WorldIdRegistryInstance;

use crate::request_tracker::BacklogScope;

use super::{
    BatchSubmitStrategy, BatcherEnvelope, GenericBatcherRunner, PendingBatchTx,
    GAS_ESTIMATION_FALLBACK, apply_gas_margin,
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

        // Build the transaction request for gas estimation.
        let tx_request = mc.aggregate3(calls.clone()).into_transaction_request();

        // Estimate gas explicitly so the result is visible here.
        // - Success: apply +20% margin and mark as not expected to revert.
        // - Execution revert error: use the fallback limit (enough to record
        //   the on-chain revert) and flag the transaction as expected to revert
        //   so the receipt handler can log/metric it separately.
        // - Transport / infrastructure error: propagate to the caller.
        let (gas_limit, expected_revert) =
            match registry.provider().clone().estimate_gas(tx_request).await {
                Ok(estimate) => (apply_gas_margin(estimate), false),
                Err(RpcError::ErrorResp(error)) => {
                    tracing::warn!(
                        %error,
                        gas_limit = GAS_ESTIMATION_FALLBACK,
                        "eth_estimateGas returned an execution error — \
                         transaction will likely revert; submitting with \
                         fallback gas limit to avoid nonce gap"
                    );
                    (GAS_ESTIMATION_FALLBACK, true)
                }
                Err(e) => return Err(alloy::contract::Error::TransportError(e)),
            };

        // Gas is set explicitly; any gas filler in the provider stack will
        // skip estimation because gas_limit is already present.
        let builder = mc.aggregate3(calls).gas(gas_limit).send().await?;

        if expected_revert {
            Ok(PendingBatchTx::new_expected_revert(builder))
        } else {
            Ok(PendingBatchTx::new(builder))
        }
    }
}

pub type OpsBatcherRunner = GenericBatcherRunner<OpsEnvelope, OpsStrategy>;
