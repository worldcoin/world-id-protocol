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

use super::{
    BatchSubmitStrategy, BatcherEnvelope, GenericBatcherRunner, PendingBatchTx,
    GAS_ESTIMATION_FALLBACK, apply_gas_margin,
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

        // Build the transaction request for gas estimation.
        let tx_request = registry
            .createManyAccounts(
                recovery_addresses.clone(),
                auths.clone(),
                pubkeys.clone(),
                commits.clone(),
            )
            .into_transaction_request();

        // Estimate gas explicitly so the result is visible here.
        // - Success: apply +20% margin and mark as not expected to revert.
        // - Execution revert error: use the fallback limit and flag the
        //   transaction as expected to revert so the receipt handler can
        //   log/metric it separately from genuine unexpected failures.
        // - Transport / infrastructure error: propagate to the caller.
        let (gas_limit, expected_revert) =
            match registry.provider().clone().estimate_gas(tx_request).await {
                Ok(estimate) => (apply_gas_margin(estimate), false),
                Err(RpcError::ErrorResp(error)) => {
                    tracing::warn!(
                        %error,
                        gas_limit = GAS_ESTIMATION_FALLBACK,
                        "eth_estimateGas returned an execution error — \
                         transaction will likely revert; submitting with \
                         fallback gas limit to avoid nonce gap"
                    );
                    (GAS_ESTIMATION_FALLBACK, true)
                }
                Err(e) => return Err(alloy::contract::Error::TransportError(e)),
            };

        // Gas is set explicitly; any gas filler in the provider stack will
        // skip estimation because gas_limit is already present.
        let builder = registry
            .createManyAccounts(recovery_addresses, auths, pubkeys, commits)
            .gas(gas_limit)
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
