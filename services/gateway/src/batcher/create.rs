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

/// Flat gas ceiling used when `eth_estimateGas` fails for any reason.
const GAS_ESTIMATION_FALLBACK: u64 = 3_000_000;

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

        for env in batch {
            recovery_addresses.push(env.req.recovery_address.unwrap_or(Address::ZERO));
            auths.push(env.req.authenticator_addresses);
            pubkeys.push(env.req.authenticator_pubkeys);
            commits.push(env.req.offchain_signer_commitment);
        }

        let call = registry.createManyAccounts(recovery_addresses, auths, pubkeys, commits);
        let gas_limit = match call.estimate_gas().await {
            Ok(estimate) => {
                let gas_limit = estimate.saturating_mul(120) / 100;
                tracing::info!(
                    estimate,
                    gas_limit,
                    "estimated gas for createManyAccounts batch"
                );
                gas_limit
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    gas_limit = GAS_ESTIMATION_FALLBACK,
                    "eth_estimateGas failed for createManyAccounts batch; using fallback gas limit"
                );
                GAS_ESTIMATION_FALLBACK
            }
        };

        let builder = call.gas(gas_limit).send().await?;

        Ok(PendingBatchTx::new(builder))
    }
}

pub type CreateBatcherRunner = GenericBatcherRunner<CreateReqEnvelope, CreateStrategy>;
