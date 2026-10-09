//! Failure-path scenarios for the submitter and resolver against a real Anvil
//! chain and a real Redis.
//!
//! A crash is modelled by stopping a sequence part-way and resolving with a
//! fresh [`TransactionSubmitter`], which shares nothing with the first one but
//! Redis and the chain, exactly as a restarted process would.

use std::{sync::Arc, time::Duration};

use alloy::{
    network::TransactionBuilder as _,
    primitives::{Address, U256, address},
    providers::{DynProvider, Provider as _},
    rpc::types::TransactionRequest,
};
use testcontainers_modules::{
    redis::{REDIS_PORT, Redis},
    testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _},
};
use uuid::Uuid;
use world_id_primitives::api_types::{GatewayErrorCode, GatewayRequestKind, GatewayRequestState};
use world_id_services_common::{ProviderArgs, ProviderWallet, SignerArgs};
use world_id_test_utils::anvil::TestAnvil;

use super::{SubmitOutcome, TransactionSubmitter};
use crate::{
    batch_type::BatchType,
    config::WalletConfig,
    request_tracker::{RequestTracker, now_unix_secs},
    storage::wallet_store::{Submission, WalletState, WalletStore},
};

/// An address nobody listens on, standing in for an RPC endpoint that is down.
const DEAD_RPC: &str = "http://127.0.0.1:1";
const RECIPIENT: Address = address!("00000000000000000000000000000000000000aa");

struct Harness {
    anvil: TestAnvil,
    redis_url: String,
    wallet: ProviderWallet,
    tracker: RequestTracker,
    wallet_store: WalletStore,
    _redis: ContainerAsync<Redis>,
}

impl Harness {
    async fn start() -> Self {
        let anvil = TestAnvil::spawn_auto_mine().expect("failed to spawn anvil");
        let redis = Redis::default()
            .with_tag("latest")
            .start()
            .await
            .expect("failed to start Redis container");
        let host = redis.get_host().await.expect("Redis host");
        let port = redis
            .get_host_port_ipv4(REDIS_PORT)
            .await
            .expect("Redis port");
        let redis_url = format!("redis://{host}:{port}");

        let wallet = wallet_for(&anvil, anvil.endpoint()).await;
        let tracker = RequestTracker::new(redis_url.clone(), None, Duration::from_secs(600)).await;
        let wallet_store = WalletStore::connect(&redis_url)
            .await
            .expect("failed to connect wallet store");

        Self {
            anvil,
            redis_url,
            wallet,
            tracker,
            wallet_store,
            _redis: redis,
        }
    }

    /// A submitter for the harness wallet, as a freshly started process would
    /// build it. `resolver_rpc` is the endpoint its resolver reads from.
    async fn submitter(
        &self,
        resolver_rpc: &str,
        config: WalletConfig,
    ) -> Arc<TransactionSubmitter> {
        self.submitter_with_wallet(self.wallet.clone(), resolver_rpc, config)
            .await
    }

    async fn submitter_with_wallet(
        &self,
        wallet: ProviderWallet,
        resolver_rpc: &str,
        config: WalletConfig,
    ) -> Arc<TransactionSubmitter> {
        TransactionSubmitter::connect(
            vec![wallet],
            vec![read_provider(resolver_rpc).await],
            self.tracker.clone(),
            &self.redis_url,
            config,
        )
        .await
        .expect("failed to build submitter")
    }

    /// Creates `count` tracked requests and returns their ids.
    async fn requests(&self, count: usize) -> Vec<String> {
        let mut ids = Vec::with_capacity(count);
        for _ in 0..count {
            let id = Uuid::new_v4().to_string();
            self.tracker
                .new_request_with_id(id.clone(), GatewayRequestKind::CreateAccount, Vec::new())
                .await
                .expect("failed to create request");
            ids.push(id);
        }
        ids
    }

    async fn status(&self, id: &str) -> GatewayRequestState {
        self.tracker
            .snapshot(id)
            .await
            .expect("request record exists")
            .status
    }

    async fn wallet_state(&self) -> Option<WalletState> {
        self.wallet_store
            .get(self.wallet.address)
            .await
            .expect("failed to read wallet record")
            .map(|record| record.state)
    }

    /// Signs a transfer and commits it as in flight, the way `submit` does,
    /// then stops: the process "crashes" before the statuses are written and
    /// before anything is broadcast.
    async fn commit_without_broadcast(
        &self,
        submitter: &TransactionSubmitter,
        ids: &[String],
    ) -> alloy::consensus::TxEnvelope {
        submitter.mark_batching(ids).await;
        let (entry, lease_id) = submitter.acquire().await.expect("a wallet is free");
        let signed = entry
            .sign_transaction(transfer())
            .await
            .expect("failed to sign");

        let submission = Submission {
            nonce: alloy::consensus::Transaction::nonce(&signed),
            tx_hash: *signed.tx_hash(),
            request_ids: ids.to_vec(),
            batch_type: BatchType::Create,
            submitted_at: now_unix_secs(),
        };
        self.wallet_store
            .mark_in_flight(
                entry.address,
                lease_id,
                submission,
                Duration::from_secs(600),
            )
            .await
            .expect("failed to commit");
        signed
    }
}

async fn wallet_for(anvil: &TestAnvil, rpc: &str) -> ProviderWallet {
    wallet_at(anvil, rpc, 0).await
}

/// A provider wallet for the anvil account at `index`.
async fn wallet_at(anvil: &TestAnvil, rpc: &str, index: usize) -> ProviderWallet {
    let key = anvil
        .signer(index)
        .expect("anvil signer")
        .to_bytes()
        .to_string();
    ProviderArgs::new()
        .with_http_urls([rpc])
        .with_signer(SignerArgs::from_wallet(key))
        .with_max_rpc_retries(0)
        .http_wallet()
        .await
        .expect("failed to build provider wallet")
}

async fn read_provider(rpc: &str) -> DynProvider {
    ProviderArgs::new()
        .with_http_urls([rpc])
        .with_max_rpc_retries(0)
        .http()
        .await
        .expect("failed to build read provider")
}

fn transfer() -> TransactionRequest {
    TransactionRequest::default()
        .with_to(RECIPIENT)
        .with_value(U256::from(1))
}

/// Treats every submitter as finished (no broadcast grace) and gives up on a
/// busy pool at once, so each scenario is decided by the chain alone.
fn config() -> WalletConfig {
    WalletConfig {
        absent_grace_secs: 0,
        acquire_timeout_secs: 0,
        ..WalletConfig::default()
    }
}

/// Runs resolver passes until the wallet record is released.
///
/// A receipt can trail the broadcast by a moment on a loaded machine, and a
/// pass skips a wallet another submitter resolved within the last interval, so
/// one pass is not always enough.
async fn resolve(harness: &Harness, submitter: &TransactionSubmitter) {
    for _ in 0..50 {
        submitter.resolve_all().await;
        if harness.wallet_state().await.is_none() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the wallet record was not released after 50 resolver passes");
}

fn assert_failed_with(status: &GatewayRequestState, code: GatewayErrorCode) {
    match status {
        GatewayRequestState::Failed { error_code, .. } => {
            // `GatewayErrorCode` has no `PartialEq`; its `Debug` form is its identity.
            assert_eq!(
                format!("{error_code:?}"),
                format!("{:?}", Some(code)),
                "unexpected failure: {status:?}"
            );
        }
        other => panic!("expected a failed request, got {other:?}"),
    }
}

#[tokio::test]
async fn a_submitted_batch_is_committed_before_broadcast_and_finalized() {
    let harness = Harness::start().await;
    let submitter = harness.submitter(harness.anvil.endpoint(), config()).await;
    let ids = harness.requests(2).await;

    submitter.mark_batching(&ids).await;
    let outcome = submitter
        .submit(transfer(), ids.clone(), BatchType::Create)
        .await
        .expect("submit");
    assert_eq!(outcome, SubmitOutcome::Submitted);
    assert_eq!(harness.wallet_state().await, Some(WalletState::InFlight));
    assert!(matches!(
        harness.status(&ids[0]).await,
        GatewayRequestState::Submitted { .. }
    ));

    resolve(&harness, &submitter).await;

    for id in &ids {
        assert!(matches!(
            harness.status(id).await,
            GatewayRequestState::Finalized { .. }
        ));
    }
    assert_eq!(harness.wallet_state().await, None, "the wallet is released");
}

#[tokio::test]
async fn a_crash_after_broadcast_is_finalized_by_the_restarted_process() {
    let harness = Harness::start().await;
    let crashed = harness.submitter(harness.anvil.endpoint(), config()).await;
    let ids = harness.requests(1).await;

    let signed = harness.commit_without_broadcast(&crashed, &ids).await;
    let _pending = harness
        .wallet
        .provider
        .send_tx_envelope(signed)
        .await
        .expect("broadcast")
        .get_receipt()
        .await
        .expect("mined");
    drop(crashed);

    let restarted = harness.submitter(harness.anvil.endpoint(), config()).await;
    resolve(&harness, &restarted).await;

    assert!(matches!(
        harness.status(&ids[0]).await,
        GatewayRequestState::Finalized { .. }
    ));
    assert_eq!(harness.wallet_state().await, None);
}

#[tokio::test]
async fn a_crash_between_commit_and_broadcast_fails_the_batch_and_frees_the_nonce() {
    let harness = Harness::start().await;
    let crashed = harness.submitter(harness.anvil.endpoint(), config()).await;
    let ids = harness.requests(2).await;

    harness.commit_without_broadcast(&crashed, &ids).await;
    drop(crashed);

    let restarted = harness.submitter(harness.anvil.endpoint(), config()).await;
    resolve(&harness, &restarted).await;

    for id in &ids {
        assert_failed_with(
            &harness.status(id).await,
            GatewayErrorCode::ConfirmationError,
        );
    }
    assert_eq!(harness.wallet_state().await, None);

    // The nonce was never consumed, so the next batch can use the wallet.
    let next = harness.requests(1).await;
    restarted.mark_batching(&next).await;
    let outcome = restarted
        .submit(transfer(), next.clone(), BatchType::Create)
        .await
        .expect("submit");
    assert_eq!(outcome, SubmitOutcome::Submitted);
    resolve(&harness, &restarted).await;
    assert!(matches!(
        harness.status(&next[0]).await,
        GatewayRequestState::Finalized { .. }
    ));
}

#[tokio::test]
async fn an_unknown_transaction_is_left_alone_while_it_may_still_be_broadcasting() {
    let harness = Harness::start().await;
    let submitter = harness
        .submitter(
            harness.anvil.endpoint(),
            WalletConfig {
                absent_grace_secs: 60,
                ..config()
            },
        )
        .await;
    let ids = harness.requests(1).await;

    // Committed a moment ago and not yet visible to the chain, as if the
    // submitter were still inside its (possibly retried) broadcast.
    harness.commit_without_broadcast(&submitter, &ids).await;
    submitter.resolve_all().await;

    assert_eq!(harness.wallet_state().await, Some(WalletState::InFlight));
    assert!(
        matches!(harness.status(&ids[0]).await, GatewayRequestState::Batching),
        "requests are neither adopted nor failed within the grace"
    );
}

#[tokio::test]
async fn a_replaced_transaction_fails_its_batch_and_releases_the_wallet() {
    let harness = Harness::start().await;
    let submitter = harness.submitter(harness.anvil.endpoint(), config()).await;
    let ids = harness.requests(1).await;

    harness.commit_without_broadcast(&submitter, &ids).await;

    // Something else spends the same nonce first.
    harness
        .wallet
        .provider
        .send_transaction(transfer().with_value(U256::from(2)))
        .await
        .expect("send replacement")
        .get_receipt()
        .await
        .expect("replacement receipt");

    resolve(&harness, &submitter).await;

    assert_failed_with(
        &harness.status(&ids[0]).await,
        GatewayErrorCode::ConfirmationError,
    );
    assert_eq!(harness.wallet_state().await, None);
}

#[tokio::test]
async fn an_rpc_outage_before_signing_commits_nothing_and_frees_the_wallet() {
    let harness = Harness::start().await;
    let dead_wallet = wallet_for(&harness.anvil, DEAD_RPC).await;
    let submitter = harness
        .submitter_with_wallet(dead_wallet, harness.anvil.endpoint(), config())
        .await;
    let ids = harness.requests(1).await;

    submitter.mark_batching(&ids).await;
    let result = submitter
        .submit(transfer(), ids.clone(), BatchType::Create)
        .await;

    assert!(result.is_err(), "signing needs the RPC, so submit fails");
    assert_eq!(
        harness.wallet_state().await,
        None,
        "nothing was committed and the lease is released"
    );
    assert!(matches!(
        harness.status(&ids[0]).await,
        GatewayRequestState::Batching
    ));
}

#[tokio::test]
async fn an_unreachable_resolver_rpc_parks_the_wallet_until_the_chain_answers() {
    let harness = Harness::start().await;
    let blind = harness
        .submitter(
            DEAD_RPC,
            WalletConfig {
                resolution_timeout_secs: 0,
                ..config()
            },
        )
        .await;
    let ids = harness.requests(1).await;

    blind.mark_batching(&ids).await;
    blind
        .submit(transfer(), ids.clone(), BatchType::Create)
        .await
        .expect("submit");

    // Every probe fails, so the fate is undecided past the timeout.
    blind.resolve_all().await;

    assert_failed_with(
        &harness.status(&ids[0]).await,
        GatewayErrorCode::ConfirmationError,
    );
    assert_eq!(harness.wallet_state().await, Some(WalletState::Parked));
    assert!(
        blind.acquire().await.is_none(),
        "a parked wallet is not handed out"
    );

    // Once the chain is readable again the transaction is found and the wallet
    // returns to the pool. The requests keep the answer they were given.
    let healthy = harness.submitter(harness.anvil.endpoint(), config()).await;
    resolve(&harness, &healthy).await;

    assert_eq!(harness.wallet_state().await, None);
    assert_failed_with(
        &harness.status(&ids[0]).await,
        GatewayErrorCode::ConfirmationError,
    );
}

#[tokio::test]
async fn a_batch_resolved_elsewhere_before_broadcast_is_abandoned() {
    let harness = Harness::start().await;
    let submitter = harness.submitter(harness.anvil.endpoint(), config()).await;
    let ids = harness.requests(2).await;

    submitter.mark_batching(&ids).await;
    // The sweeper fails one request while the batch is waiting.
    harness
        .tracker
        .set_status(
            &ids[1],
            GatewayRequestState::failed("swept", Some(GatewayErrorCode::InternalServerError)),
        )
        .await;

    let outcome = submitter
        .submit(transfer(), ids.clone(), BatchType::Create)
        .await
        .expect("submit");

    assert_eq!(outcome, SubmitOutcome::Abandoned);
    assert_eq!(
        harness.wallet_state().await,
        None,
        "the signature was discarded"
    );
    assert_failed_with(
        &harness.status(&ids[0]).await,
        GatewayErrorCode::InternalServerError,
    );
    assert_eq!(
        harness
            .wallet
            .provider
            .get_transaction_count(harness.wallet.address)
            .await
            .expect("nonce"),
        0,
        "nothing was broadcast"
    );
}

#[tokio::test]
async fn a_partly_resolved_batch_is_still_resolved_and_released() {
    let harness = Harness::start().await;
    let submitter = harness.submitter(harness.anvil.endpoint(), config()).await;
    let ids = harness.requests(2).await;

    submitter.mark_batching(&ids).await;
    submitter
        .submit(transfer(), ids.clone(), BatchType::Create)
        .await
        .expect("submit");

    // One request is resolved by someone else after broadcast, so the batch
    // write for the receipt is refused as a whole.
    harness
        .tracker
        .set_status(
            &ids[1],
            GatewayRequestState::failed("operator", Some(GatewayErrorCode::InternalServerError)),
        )
        .await;

    resolve(&harness, &submitter).await;

    assert!(matches!(
        harness.status(&ids[0]).await,
        GatewayRequestState::Finalized { .. }
    ));
    assert_failed_with(
        &harness.status(&ids[1]).await,
        GatewayErrorCode::InternalServerError,
    );
    assert_eq!(harness.wallet_state().await, None, "the wallet is released");
}

#[tokio::test]
async fn a_record_of_an_unconfigured_wallet_is_still_resolved() {
    let harness = Harness::start().await;
    let removed = harness.submitter(harness.anvil.endpoint(), config()).await;
    let ids = harness.requests(1).await;

    removed.mark_batching(&ids).await;
    removed
        .submit(transfer(), ids.clone(), BatchType::Create)
        .await
        .expect("submit");
    drop(removed);

    // The wallet that signed is dropped from configuration without draining;
    // a replica that knows only another wallet must still decide its record.
    let other_wallet = wallet_at(&harness.anvil, harness.anvil.endpoint(), 1).await;
    let other = harness
        .submitter_with_wallet(other_wallet, harness.anvil.endpoint(), config())
        .await;
    resolve(&harness, &other).await;

    assert!(matches!(
        harness.status(&ids[0]).await,
        GatewayRequestState::Finalized { .. }
    ));
    assert_eq!(harness.wallet_state().await, None, "the record is released");
}
