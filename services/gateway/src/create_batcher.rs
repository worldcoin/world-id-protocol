use std::sync::Arc;

use alloy::{
    primitives::{Address, U256},
    providers::DynProvider,
};
use tokio::sync::mpsc;
use world_id_core::{
    api_types::CreateAccountRequest, world_id_registry::WorldIdRegistry::WorldIdRegistryInstance,
};

use crate::{
    RequestTracker,
    batch_policy::BaseFeeCache,
    config::BatchPolicyConfig,
    generic_batcher::{BatchSubmitStrategy, BatcherEnvelope, GenericBatcherRunner, PendingBatchTx},
    request_tracker::BacklogScope,
};

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
    ) -> Result<PendingBatchTx, String> {
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
            .send()
            .await
            .map_err(|e| e.to_string())?;

        Ok(PendingBatchTx {
            tx_hash: format!("0x{:x}", builder.tx_hash()),
            builder,
        })
    }
}

pub type CreateBatcherRunner = GenericBatcherRunner<CreateReqEnvelope, CreateStrategy>;

impl CreateBatcherRunner {
    pub fn new_create(
        registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
        max_batch_size: usize,
        local_queue_limit: usize,
        rx: mpsc::Receiver<CreateReqEnvelope>,
        tracker: RequestTracker,
        batch_policy: BatchPolicyConfig,
        base_fee_cache: BaseFeeCache,
    ) -> Self {
        Self::new(
            registry,
            max_batch_size,
            local_queue_limit,
            rx,
            tracker,
            batch_policy,
            base_fee_cache,
            CreateStrategy,
        )
    }
}
