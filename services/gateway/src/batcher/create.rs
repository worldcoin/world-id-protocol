use std::sync::Arc;

use alloy::{
    primitives::{Address, U256},
    providers::DynProvider,
    rpc::types::TransactionRequest,
};
use tokio::sync::mpsc;
use world_id_primitives::api_types::CreateAccountRequest;
use world_id_registries::world_id::WorldIdRegistry::WorldIdRegistryInstance;

use crate::{batch_type::BatchType, request_tracker::BacklogScope};

use super::{BatchSubmitStrategy, BatcherEnvelope, GenericBatcherRunner};

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
    fn batch_type(&self) -> BatchType {
        BatchType::Create
    }

    fn backlog_scope(&self) -> BacklogScope {
        BacklogScope::Create
    }

    fn build_tx(
        &self,
        registry: &WorldIdRegistryInstance<Arc<DynProvider>>,
        batch: &[CreateReqEnvelope],
    ) -> TransactionRequest {
        let mut recovery_addresses: Vec<Address> = Vec::with_capacity(batch.len());
        let mut auths: Vec<Vec<Address>> = Vec::with_capacity(batch.len());
        let mut pubkeys: Vec<Vec<U256>> = Vec::with_capacity(batch.len());
        let mut commits: Vec<U256> = Vec::with_capacity(batch.len());

        for envelope in batch {
            recovery_addresses.push(envelope.req.recovery_address.unwrap_or(Address::ZERO));
            auths.push(envelope.req.authenticator_addresses.clone());
            pubkeys.push(envelope.req.authenticator_pubkeys.clone());
            commits.push(envelope.req.offchain_signer_commitment);
        }

        registry
            .createManyAccounts(recovery_addresses, auths, pubkeys, commits)
            .into_transaction_request()
    }
}

pub type CreateBatcherRunner = GenericBatcherRunner<CreateReqEnvelope, CreateStrategy>;
