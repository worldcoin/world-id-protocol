//! Batcher for WIP-107 `WorldIDBilling.register` calls.
//!
//! Registrations are batched apart from registry operations, so a registration that reverts at
//! inclusion fails only a billing batch, never an account operation. Within a batch, Multicall3
//! calls do not allow failure. Validation simulates each registration and rejects those whose
//! authorization could expire before the orphan sweeper would fail them as stale, so the remaining way for a batch to revert is a race
//! on shared state, mainly an RP's last capacity: when more registrations for an RP share a batch
//! than it has slots left, the whole batch reverts. Their retries then fit or fail simulation, so
//! this resolves within one retry.

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
