use std::sync::Arc;

use alloy::{
    primitives::{Address, U256},
    providers::{DynProvider, Provider},
    rpc::json_rpc::RpcError,
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

        // Pre-flight: detect whether the batch will revert on-chain before
        // committing.  On an execution error we still submit (to avoid a
        // nonce gap) but flag the transaction as an expected revert so the
        // receipt handler can log/metric it separately.
        let call =
            registry.createManyAccounts(recovery_addresses.clone(), auths.clone(), pubkeys.clone(), commits.clone());
        let expected_revert = match registry
            .provider()
            .clone()
            .estimate_gas(call.into_transaction_request())
            .await
        {
            Ok(_) => false,
            Err(RpcError::ErrorResp(ref error)) => {
                tracing::warn!(
                    %error,
                    "pre-flight eth_estimateGas indicates createManyAccounts will revert; \
                     submitting anyway to avoid nonce gap"
                );
                true
            }
            Err(_) => false,
        };

        let builder = registry
            .createManyAccounts(recovery_addresses, auths, pubkeys, commits)
            .send()
            .await?;

        if expected_revert {
            Ok(PendingBatchTx::new_expected_revert(builder))
        } else {
            Ok(PendingBatchTx::new(builder))
        }
    }
}

pub type CreateBatcherRunner = GenericBatcherRunner<CreateReqEnvelope, CreateStrategy>;
