//! Batcher for WIP-107 `WorldIDBilling.register` calls.
//!
//! Each registration is its own transaction, sent straight to the Billing Contract. Registrations
//! of one RP share its period capacity and nonces, so in a shared all-or-nothing batch one
//! registration that reverts at inclusion (exhausted capacity, a consumed nonce, an ended period)
//! would revert every other one, even those that passed simulation.

use std::sync::Arc;

use alloy::{
    primitives::{Address, TxKind},
    providers::{DynProvider, Provider as _},
    rpc::types::TransactionRequest,
    transports::TransportErrorKind,
};
use tokio::sync::mpsc;
use world_id_registries::world_id::WorldIdRegistry::WorldIdRegistryInstance;

use crate::request_tracker::BacklogScope;

use super::{BatchSubmitStrategy, GenericBatcherRunner, OpsEnvelope, PendingBatchTx};

/// Registrations per transaction; see the module documentation.
pub(crate) const BILLING_BATCH_SIZE: usize = 1;

#[derive(Clone)]
pub struct BillingBatcherHandle {
    pub tx: mpsc::Sender<OpsEnvelope>,
}

/// Sends each registration as one transaction to the Billing Contract.
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
        let [envelope] = <[OpsEnvelope; BILLING_BATCH_SIZE]>::try_from(batch).map_err(|batch| {
            alloy::contract::Error::TransportError(TransportErrorKind::custom_str(&format!(
                "a billing batch holds exactly one registration, got {}",
                batch.len()
            )))
        })?;
        // No explicit gas limit: the provider's gas filler estimates it.
        let tx = TransactionRequest {
            to: Some(TxKind::Call(self.billing_contract)),
            input: envelope.calldata.into(),
            ..Default::default()
        };
        let builder = registry.provider().send_transaction(tx).await?;
        Ok(PendingBatchTx::new(builder))
    }
}

pub type BillingBatcherRunner = GenericBatcherRunner<OpsEnvelope, BillingStrategy>;
