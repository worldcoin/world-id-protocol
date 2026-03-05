//! Operations batcher for insert/remove/recover/update operations.
//!
//! This batcher collects operations and submits them via Multicall3.

use std::sync::Arc;

use alloy::{
    primitives::{Address, Bytes, address},
    providers::DynProvider,
};
use tokio::sync::mpsc;
use world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance;

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

/// Envelope for ops batcher containing pre-computed calldata.
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
            .map(|env| Multicall3::Call3 {
                target: *registry.address(),
                allowFailure: false,
                callData: env.calldata,
            })
            .collect();

        let builder = mc
            .aggregate3(calls)
            .send()
            .await?;

        Ok(PendingBatchTx::new(builder))
    }
}

pub type OpsBatcherRunner = GenericBatcherRunner<OpsEnvelope, OpsStrategy>;
