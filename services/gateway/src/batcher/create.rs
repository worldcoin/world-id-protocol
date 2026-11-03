use std::sync::Arc;

use alloy::{
    primitives::{Address, U256},
    providers::DynProvider,
};
use tokio::sync::mpsc;
use world_id_primitives::{TREE_DEPTH, api_types::CreateAccountRequest};
use world_id_registries::world_id::WorldIdRegistry::WorldIdRegistryInstance;

use crate::request_tracker::BacklogScope;

use super::{BatchSubmitStrategy, BatcherEnvelope, GenericBatcherRunner, PendingBatchTx};

/// Upper bound on the extra gas `insertMany` can need per tree level when the
/// batch lands at a later leaf index than the one it was estimated at.
///
/// Another signer can insert leaves between our `eth_estimateGas` and our
/// inclusion. Per level, shifting the batch start can add one parent node
/// (a Poseidon2 hash, ~7.1k, plus a zero-to-nonzero SSTORE, 22.1k), turn the
/// level's one overwritten node into a fresh write (22.1k instead of 5k), and
/// add two cold sibling reads (2 x 2.1k). That is ~50.5k; round up to 55k.
const TREE_INSERT_HEADROOM_PER_LEVEL: u64 = 55_000;

/// Gas added on top of the `createManyAccounts` estimate. The extra work is
/// bounded by the tree depth, not by the batch size, so a fixed headroom is
/// both safe for small batches and cheap for large ones (unused gas is not
/// charged).
const TREE_INSERT_HEADROOM: u64 = TREE_DEPTH as u64 * TREE_INSERT_HEADROOM_PER_LEVEL;

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
        // On estimation failure, send without a gas limit so the provider's
        // `GasEstimateWithFallbackFiller` handles it as for any other tx: it
        // re-estimates and either falls back for reverts or propagates the error.
        let call = match call.estimate_gas().await {
            Ok(estimate) => call.gas(estimate.saturating_add(TREE_INSERT_HEADROOM)),
            Err(_) => call,
        };
        let builder = call.send().await?;

        Ok(PendingBatchTx::new(builder))
    }
}

pub type CreateBatcherRunner = GenericBatcherRunner<CreateReqEnvelope, CreateStrategy>;

#[cfg(test)]
mod tests {
    use alloy::{
        network::EthereumWallet,
        primitives::{Address, U256},
        providers::{Provider, ProviderBuilder},
    };
    use world_id_test_utils::anvil::TestAnvil;

    use super::*;

    fn account(seed: u64) -> CreateAccountRequest {
        CreateAccountRequest {
            recovery_address: None,
            authenticator_addresses: vec![Address::left_padding_from(&seed.to_be_bytes())],
            authenticator_pubkeys: vec![U256::from(seed)],
            offchain_signer_commitment: U256::from(seed),
        }
    }

    fn envelope(seed: u64) -> CreateReqEnvelope {
        CreateReqEnvelope {
            id: seed.to_string(),
            req: account(seed),
        }
    }

    async fn registry_for(
        anvil: &TestAnvil,
        signer: usize,
        address: Address,
    ) -> WorldIdRegistryInstance<Arc<DynProvider>> {
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(anvil.signer(signer).unwrap()))
            .connect(anvil.endpoint())
            .await
            .unwrap()
            .erased();
        WorldIdRegistryInstance::new(address, Arc::new(provider))
    }

    /// Reproduces a stage incident where two gateway replicas inserted into
    /// the tree in the same block. The batch was estimated with leaves 510
    /// and 511 (siblings) but landed at 511 and 512, which sit in different
    /// 512-leaf subtrees, so `insertMany` did far more work than estimated.
    #[tokio::test]
    async fn create_batch_survives_concurrent_insert_across_subtree_boundary() {
        let anvil = TestAnvil::spawn_auto_mine().unwrap();
        let address = anvil
            .deploy_world_id_registry_v2(anvil.signer(0).unwrap())
            .await
            .unwrap();
        let gateway = registry_for(&anvil, 0, address).await;
        let other_replica = registry_for(&anvil, 1, address).await;

        // Leaf indices start at 1, so this fills leaves 1..=509.
        for chunk in (1..=509u64).collect::<Vec<_>>().chunks(102) {
            CreateStrategy
                .send_batch(&gateway, chunk.iter().copied().map(envelope).collect())
                .await
                .unwrap()
                .builder
                .get_receipt()
                .await
                .unwrap();
        }

        let provider = gateway.provider();
        let () = provider
            .raw_request("evm_setAutomine".into(), (false,))
            .await
            .unwrap();

        let ours = CreateStrategy
            .send_batch(&gateway, vec![envelope(510), envelope(511)])
            .await
            .unwrap();

        let other = account(512);
        let theirs = other_replica
            .createManyAccounts(
                vec![Address::ZERO],
                vec![other.authenticator_addresses],
                vec![other.authenticator_pubkeys],
                vec![other.offchain_signer_commitment],
            )
            .gas(5_000_000)
            .max_priority_fee_per_gas(100_000_000_000)
            .max_fee_per_gas(200_000_000_000)
            .send()
            .await
            .unwrap();

        let _: String = provider.raw_request("evm_mine".into(), ()).await.unwrap();

        let theirs = theirs.get_receipt().await.unwrap();
        let ours = ours.builder.get_receipt().await.unwrap();
        assert!(theirs.status());
        assert_eq!(theirs.block_number, ours.block_number);
        assert!(theirs.transaction_index < ours.transaction_index);
        assert!(
            ours.status(),
            "batch reverted after using {} gas",
            ours.gas_used
        );
    }
}
