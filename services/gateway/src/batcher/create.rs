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
        gas_fallback_used: &Arc<std::sync::atomic::AtomicBool>,
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

        // Reset the filler flag before the send so any stale value from a
        // previous transaction doesn't leak.  The GasEstimateWithFallbackFiller
        // will set it to `true` during the fill phase if eth_estimateGas
        // returns an execution-revert error.
        gas_fallback_used.store(false, std::sync::atomic::Ordering::Relaxed);

        let builder = registry
            .createManyAccounts(recovery_addresses, auths, pubkeys, commits)
            .send()
            .await?;

        // Read the flag immediately after .send() completes.  The filler
        // ran synchronously as part of the fill pipeline before the
        // transaction was broadcast.
        let expected_revert = gas_fallback_used.load(std::sync::atomic::Ordering::Relaxed);

        if expected_revert {
            Ok(PendingBatchTx::new_expected_revert(builder))
        } else {
            Ok(PendingBatchTx::new(builder))
        }
    }
}

pub type CreateBatcherRunner = GenericBatcherRunner<CreateReqEnvelope, CreateStrategy>;
