//! Batcher for WIP-107 `WorldIDBilling.register` calls.
//!
//! Registrations are batched apart from registry operations: Multicall3 calls do not allow failure,
//! so a registration that reverts at inclusion (a consumed nonce, exhausted capacity, a period
//! that ended) fails only its own batch, never an account operation.

use std::sync::Arc;

use alloy::{primitives::Address, providers::DynProvider};
use tokio::sync::mpsc;
use world_id_registries::world_id::WorldIdRegistry::WorldIdRegistryInstance;

use crate::request_tracker::BacklogScope;

use super::{
    BatchSubmitStrategy, GenericBatcherRunner, OpsEnvelope, PendingBatchTx,
    ops::{MULTICALL3_ADDR, Multicall3},
};

#[derive(Clone)]
pub struct BillingBatcherHandle {
    pub tx: mpsc::Sender<OpsEnvelope>,
}

/// Submits each batch through Multicall3 to the Billing Contract.
pub(crate) struct BillingStrategy {
    billing_contract: Address,
}

impl BillingStrategy {
    pub(crate) const fn new(billing_contract: Address) -> Self {
        Self { billing_contract }
    }
}

impl BatchSubmitStrategy<OpsEnvelope> for BillingStrategy {
    fn batch_type(&self) -> &'static str {
        "billing"
    }

    fn backlog_scope(&self) -> BacklogScope {
        BacklogScope::Billing
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
                target: self.billing_contract,
                allowFailure: false,
                callData: envelope.calldata,
            })
            .collect();
        let builder = mc.aggregate3(calls).send().await?;
        Ok(PendingBatchTx::new(builder))
    }
}

pub type BillingBatcherRunner = GenericBatcherRunner<OpsEnvelope, BillingStrategy>;
