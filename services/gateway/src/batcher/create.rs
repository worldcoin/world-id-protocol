use std::sync::Arc;

use alloy::{
    primitives::{Address, U256},
    providers::DynProvider,
};
use tokio::sync::mpsc;
use tracing::error;
use world_id_core::{
    api_types::CreateAccountRequest, world_id_registry::WorldIdRegistry::WorldIdRegistryInstance,
};

use crate::request_tracker::BacklogScope;

use super::{BatchSubmitStrategy, BatcherEnvelope, GenericBatcherRunner, PendingBatchTx};

#[derive(Clone)]
pub struct CreateBatcherHandle {
    pub tx: mpsc::Sender<CreateReqEnvelope>,
}

#[derive(Debug)]
pub struct CreateReqEnvelope {
    pub id: String,
    pub req: CreateAccountRequest,
}

impl BatcherEnvelope for CreateReqEnvelope {
    fn request_id(&self) -> &str {
        &self.id
    }
}

#[derive(Default)]
pub(crate) struct CreateStrategy;

impl BatchSubmitStrategy<CreateReqEnvelope> for CreateStrategy {
    fn batch_type(&self) -> &'static str {
        "create"
    }

    fn backlog_scope(&self) -> BacklogScope {
        BacklogScope::Create
    }

    async fn send_batch(
        &self,
        registry: &WorldIdRegistryInstance<Arc<DynProvider>>,
        batch: Vec<CreateReqEnvelope>,
        nonce: u64,
    ) -> Result<PendingBatchTx, alloy::contract::Error> {
        let mut recovery_addresses: Vec<Address> = Vec::new();
        let mut auths: Vec<Vec<Address>> = Vec::new();
        let mut pubkeys: Vec<Vec<U256>> = Vec::new();
        let mut commits: Vec<U256> = Vec::new();

        for env in batch {
            recovery_addresses.push(env.req.recovery_address.unwrap_or(Address::ZERO));
            auths.push(env.req.authenticator_addresses);
            pubkeys.push(env.req.authenticator_pubkeys);
            commits.push(env.req.offchain_signer_commitment);
        }

        let builder = registry
            .createManyAccounts(recovery_addresses, auths, pubkeys, commits)
            .nonce(nonce)
            .send()
            .await
            .inspect_err(|e| error!(error = ?e, "failed to send create batch transaction"))?;

        Ok(PendingBatchTx::new(builder))
    }
}

pub type CreateBatcherRunner = GenericBatcherRunner<CreateReqEnvelope, CreateStrategy>;
