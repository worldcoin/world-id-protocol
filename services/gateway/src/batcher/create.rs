use std::sync::Arc;

use alloy::{
    primitives::{Address, U256},
    providers::DynProvider,
};
use tokio::sync::mpsc;
use world_id_primitives::api_types::CreateAccountRequest;
use world_id_registries::world_id::WorldIdRegistry::WorldIdRegistryInstance;

use crate::request_tracker::BacklogScope;

use super::{BatchSubmitStrategy, BatcherEnvelope, GenericBatcherRunner, PendingBatchTx};

/// Fixed gas overhead for `createManyAccounts` (proxy dispatch, tree root
/// path recomputation, calldata decoding). Derived from empirical
/// `eth_estimateGas` measurements at N=1..16 against WorldChain Mainnet.
const CREATE_BATCH_FIXED_GAS: u64 = 500_000;

/// Marginal gas per account in a `createManyAccounts` batch
/// (`_registerAccount` + leaf-level Poseidon hash + SSTORE). From the same
/// empirical measurement, rounded up for ~10% headroom.
const CREATE_BATCH_PER_ACCOUNT_GAS: u64 = 120_000;

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
    ) -> Result<PendingBatchTx, alloy::contract::Error> {
        let mut recovery_addresses: Vec<Address> = Vec::new();
        let mut auths: Vec<Vec<Address>> = Vec::new();
        let mut pubkeys: Vec<Vec<U256>> = Vec::new();
        let mut commits: Vec<U256> = Vec::new();

        let batch_len = batch.len() as u64;
        for env in batch {
            recovery_addresses.push(env.req.recovery_address.unwrap_or(Address::ZERO));
            auths.push(env.req.authenticator_addresses);
            pubkeys.push(env.req.authenticator_pubkeys);
            commits.push(env.req.offchain_signer_commitment);
        }

        let gas_limit = CREATE_BATCH_FIXED_GAS + CREATE_BATCH_PER_ACCOUNT_GAS * batch_len;

        let builder = registry
            .createManyAccounts(recovery_addresses, auths, pubkeys, commits)
            .gas(gas_limit)
            .send()
            .await?;

        Ok(PendingBatchTx::new(builder))
    }
}

pub type CreateBatcherRunner = GenericBatcherRunner<CreateReqEnvelope, CreateStrategy>;
