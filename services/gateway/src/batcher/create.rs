use std::sync::Arc;

use alloy::{
    primitives::{Address, U256},
    providers::DynProvider,
    rpc::types::TransactionRequest,
};
use world_id_primitives::api_types::CreateAccountRequest;
use world_id_registries::world_id::WorldIdRegistry::WorldIdRegistryInstance;

use crate::batch_type::BatchType;

use super::{BatchSubmitStrategy, BatcherEnvelope, GenericBatcher};

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

    fn build_tx(
        &self,
        registry: &WorldIdRegistryInstance<Arc<DynProvider>>,
        batch: Vec<CreateReqEnvelope>,
    ) -> TransactionRequest {
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

        registry
            .createManyAccounts(recovery_addresses, auths, pubkeys, commits)
            .into_transaction_request()
    }
}

pub type CreateBatcher = GenericBatcher<CreateReqEnvelope, CreateStrategy>;
