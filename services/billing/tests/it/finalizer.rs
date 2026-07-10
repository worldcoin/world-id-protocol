//! Finalizer worker integration tests against a local anvil chain with a real
//! `BillingContract` deployment (built from the workspace's forge artifacts).

use alloy::{
    eips::BlockNumberOrTag,
    network::EthereumWallet,
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::{SignerSync as _, local::PrivateKeySigner},
    sol_types::{SolCall as _, SolStruct as _, eip712_domain},
};
use alloy_primitives::{Address, U256};
use eyre::{ContextCompat as _, Result};
use world_id_billing::{
    bindings::IBillingContract as KeeperBindings,
    finalizer::{Finalizer, FinalizerArgs},
};
use world_id_test_utils::anvil::TestAnvil;

use crate::finalizer::artifacts::{
    BillingContract, ERC1967Proxy, IBillingContract as ContractTypes, OprfKeyRegistryMock,
};

/// Bindings generated from the workspace's forge artifacts (`forge build` must
/// have run). Kept in a module of their own because the artifact ABI also
/// spawns an `IBillingContract` namespace for the contract's struct types,
/// which would clash with the service's own bindings at file scope.
mod artifacts {
    use alloy::sol;

    sol!(
        #[allow(clippy::too_many_arguments)]
        #[sol(rpc)]
        BillingContract,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/out/BillingContract.sol/BillingContract.json"
        )
    );

    sol!(
        #[sol(rpc)]
        OprfKeyRegistryMock,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/out/BillingContract.t.sol/OprfKeyRegistryMock.json"
        )
    );

    sol!(
        #[sol(rpc)]
        ERC1967Proxy,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/out/ERC1967Proxy.sol/ERC1967Proxy.json"
        )
    );
}

// EIP-712 mirror of the contract's vote structs; the struct names must match
// the Solidity ones exactly for the typehashes to line up.
mod eip712 {
    alloy::sol! {
        struct RpCount {
            uint64 rpId;
            uint64 count;
        }

        struct BillingVoteChunk {
            uint32 epoch;
            uint32 chunkIndex;
            bool isFinal;
            RpCount[] counts;
        }
    }
}

const EPOCH_LEN: u64 = 1_000;
const VOTING: u64 = 1_000;
const PAYMENT: u64 = 2_000;
const REBATE: u32 = 10;
const RATE: u64 = 10;

struct TestSetup {
    anvil: TestAnvil,
    provider: DynProvider,
    billing: Address,
    genesis: u64,
    /// The OPRF node keys registered in the mock registry.
    nodes: Vec<PrivateKeySigner>,
}

impl TestSetup {
    /// Deploys the `BillingContract` behind an ERC1967 proxy with a 3-node
    /// mock OPRF registry, with `genesis` set to the chain's current time.
    async fn new() -> Result<Self> {
        let anvil = TestAnvil::spawn()?;
        let deployer = anvil.signer(0)?;
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(deployer))
            .connect_http(anvil.endpoint().parse()?)
            .erased();

        let nodes = vec![anvil.signer(1)?, anvil.signer(2)?, anvil.signer(3)?];

        let oprf = OprfKeyRegistryMock::deploy(provider.clone()).await?;
        oprf.setPeers(nodes.iter().map(|s| s.address()).collect())
            .send()
            .await?
            .get_receipt()
            .await?;

        let genesis = latest_timestamp(&provider).await?;

        let implementation = BillingContract::deploy(provider.clone()).await?;
        let init = BillingContract::initializeCall {
            feeRecipient: Address::repeat_byte(0xFE),
            // The fee token is never touched by finalization; any non-zero
            // address satisfies the initializer.
            feeToken: Address::repeat_byte(0xF0),
            oprfKeyRegistry: *oprf.address(),
            genesis,
            epochLength: EPOCH_LEN,
            votingWindow: VOTING,
            paymentWindow: PAYMENT,
            tiers: vec![ContractTypes::Tier {
                upTo: U256::MAX,
                rate: U256::from(RATE),
            }],
            rebatePeriodEpochs: REBATE,
        };
        let proxy = ERC1967Proxy::deploy(
            provider.clone(),
            *implementation.address(),
            init.abi_encode().into(),
        )
        .await?;

        Ok(Self {
            anvil,
            provider,
            billing: *proxy.address(),
            genesis,
            nodes,
        })
    }

    fn finalizer(&self, max_steps_per_tx: u64) -> Finalizer {
        Finalizer::new(
            self.provider.clone(),
            self.billing,
            &FinalizerArgs {
                max_steps_per_tx,
                receipt_timeout_secs: 30,
                close_lag_secs: 0,
                confirm_retry_interval_secs: 1,
                confirm_max_attempts: 5,
            },
        )
    }

    fn contract(&self) -> BillingContract::BillingContractInstance<DynProvider> {
        BillingContract::new(self.billing, self.provider.clone())
    }

    /// Warps chain time to `timestamp` and mines a block so view calls see it.
    async fn warp_to(&self, timestamp: u64) -> Result<()> {
        self.provider
            .raw_request::<_, serde_json::Value>("evm_setNextBlockTimestamp".into(), (timestamp,))
            .await?;
        self.provider
            .raw_request::<_, serde_json::Value>("evm_mine".into(), ())
            .await?;
        Ok(())
    }

    /// Submits a complete single-chunk vote for `epoch` from every registered
    /// node, reporting `count` requests for `rp_id`. Warps into the epoch's
    /// voting window first.
    async fn vote_all_nodes(&self, epoch: u32, rp_id: u64, count: u64) -> Result<()> {
        self.warp_to(self.genesis + (u64::from(epoch) + 1) * EPOCH_LEN)
            .await?;

        let chain_id = self.provider.get_chain_id().await?;
        let domain = eip712_domain!(
            name: "BillingContract",
            version: "1.0",
            chain_id: chain_id,
            verifying_contract: self.billing,
        );

        let chunks = self
            .nodes
            .iter()
            .map(|node| {
                let chunk = eip712::BillingVoteChunk {
                    epoch,
                    chunkIndex: 0,
                    isFinal: true,
                    counts: vec![eip712::RpCount { rpId: rp_id, count }],
                };
                let signature = node.sign_hash_sync(&chunk.eip712_signing_hash(&domain))?;
                Ok(ContractTypes::SignedVoteChunk {
                    chunkIndex: 0,
                    isFinal: true,
                    counts: vec![ContractTypes::RpCount { rpId: rp_id, count }],
                    signature: signature.as_bytes().to_vec().into(),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let receipt = self
            .contract()
            .submitBillingVotes(epoch, chunks)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status(), "submitBillingVotes reverted");
        Ok(())
    }

    async fn sender_nonce(&self) -> Result<u64> {
        Ok(self
            .provider
            .get_transaction_count(self.anvil.signer(0)?.address())
            .await?)
    }
}

async fn latest_timestamp(provider: &DynProvider) -> Result<u64> {
    Ok(provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .context("no latest block")?
        .header
        .timestamp)
}

#[tokio::test]
async fn tick_is_noop_before_first_voting_window_closes() -> Result<()> {
    let setup = TestSetup::new().await?;
    let billing = KeeperBindings::new(setup.billing, setup.provider.clone());

    let nonce_before = setup.sender_nonce().await?;
    setup.finalizer(500).tick().await?;

    assert_eq!(
        setup.sender_nonce().await?,
        nonce_before,
        "no transaction should be sent while nothing is finalizable"
    );
    assert!(
        !billing.epochWatermarks().call().await?.finalizedExists,
        "nothing should be finalized yet"
    );
    Ok(())
}

#[tokio::test]
async fn tick_advances_cursor_over_voteless_epochs() -> Result<()> {
    let setup = TestSetup::new().await?;
    let billing = KeeperBindings::new(setup.billing, setup.provider.clone());

    // Close epochs 0..=2 without a single vote.
    setup
        .warp_to(setup.genesis + 3 * EPOCH_LEN + VOTING)
        .await?;
    let closed = billing.epochWatermarks().call().await?;
    assert!(closed.closedExists);
    assert_eq!(closed.closedEpoch, 2);

    setup.finalizer(500).tick().await?;

    let finalized = billing.epochWatermarks().call().await?;
    assert!(finalized.finalizedExists);
    assert_eq!(
        finalized.finalizedEpoch, 2,
        "cursor should advance past all closed vote-less epochs (latest finalized = 2)"
    );
    Ok(())
}

#[tokio::test]
async fn tick_finalizes_voted_epoch_and_accrues_debt() -> Result<()> {
    let setup = TestSetup::new().await?;
    let contract = setup.contract();

    let (rp_id, count) = (7u64, 50u64);
    setup.vote_all_nodes(0, rp_id, count).await?;
    // Close epoch 0's voting window.
    setup.warp_to(setup.genesis + EPOCH_LEN + VOTING).await?;

    setup.finalizer(500).tick().await?;

    assert_eq!(
        contract.outstandingDebt(rp_id).call().await?,
        U256::from(count * RATE),
        "the RP's lower-median count should be priced and accrued as debt"
    );
    let billing = KeeperBindings::new(setup.billing, setup.provider.clone());
    let finalized = billing.epochWatermarks().call().await?;
    assert!(finalized.finalizedExists);
    assert_eq!(finalized.finalizedEpoch, 0);
    Ok(())
}

#[tokio::test]
async fn tick_drains_full_backlog_in_one_call() -> Result<()> {
    let setup = TestSetup::new().await?;
    let billing = KeeperBindings::new(setup.billing, setup.provider.clone());

    // Close epochs 0..=3 without a single vote; with 1 step per tx (one
    // epoch-close each), a single tick() call must still fully drain all 4 —
    // there's no longer a per-tick transaction budget to bound the burst.
    setup
        .warp_to(setup.genesis + 4 * EPOCH_LEN + VOTING)
        .await?;

    setup.finalizer(1).tick().await?;

    let finalized = billing.epochWatermarks().call().await?;
    assert!(finalized.finalizedExists);
    assert_eq!(
        finalized.finalizedEpoch, 3,
        "a single tick() call should fully drain the backlog (latest finalized = 3)"
    );
    Ok(())
}

#[tokio::test]
async fn next_deadline_matches_voting_window_end() -> Result<()> {
    let setup = TestSetup::new().await?;
    let finalizer = setup.finalizer(500);

    // next_deadline reads the contract's votingWindowEnd; for epoch 0 that is its
    // epoch-end plus the voting window.
    let expected = setup.genesis + EPOCH_LEN + VOTING;
    assert_eq!(finalizer.next_deadline(0).await?, expected);
    Ok(())
}

#[tokio::test]
async fn wait_for_close_confirmed_errors_after_exhausting_retries() -> Result<()> {
    let setup = TestSetup::new().await?;
    // Epoch 0 never closes (no time warp); a tiny bound keeps the test fast.
    let finalizer = Finalizer::new(
        setup.provider.clone(),
        setup.billing,
        &FinalizerArgs {
            max_steps_per_tx: 500,
            receipt_timeout_secs: 30,
            close_lag_secs: 0,
            confirm_retry_interval_secs: 1,
            confirm_max_attempts: 2,
        },
    );

    assert!(
        finalizer.wait_for_close_confirmed(0).await.is_err(),
        "should give up once confirm_max_attempts is exhausted, not hang"
    );
    Ok(())
}
