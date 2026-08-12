//! Nonce-gap recovery tests for [`TxSubmitter`].
//!
//! These drive the submitter directly rather than through the HTTP API: the
//! behaviour under test is nonce mechanics, so the transactions are plain
//! self-transfers and no registry is involved.
//!
//! Anvil runs with auto-mining disabled so that transactions can be held in the
//! mempool, dropped with `anvil_dropTransaction`, and mined on demand — which is
//! what makes the production failure reproducible.

#![cfg(feature = "integration-tests")]

use std::{sync::Arc, time::Duration};

use alloy::{
    primitives::{Address, TxHash, U256},
    providers::{Provider, ext::AnvilApi},
    rpc::types::TransactionRequest,
};
use world_id_gateway::{RequestTracker, TxSubmitter, TxSubmitterConfig};
use world_id_primitives::api_types::{GatewayRequestKind, GatewayRequestState};
use world_id_services_common::{ProviderArgs, SignerArgs};
use world_id_test_utils::anvil::TestAnvil;

mod common;
use crate::common::{GW_PRIVATE_KEY, start_redis};

/// Escalation interval used by the tests. Short so a pass becomes due without
/// making the suite slow; production defaults to 30s.
const TEST_ESCALATION_INTERVAL_SECS: u64 = 1;

struct Harness {
    submitter: Arc<TxSubmitter>,
    provider: Arc<alloy::providers::DynProvider>,
    tracker: RequestTracker,
    signer: Address,
    _anvil: TestAnvil,
    _redis: testcontainers_modules::testcontainers::ContainerAsync<
        testcontainers_modules::redis::Redis,
    >,
}

impl Harness {
    /// Spawns anvil with auto-mining off, plus Redis, and builds a submitter.
    async fn new(config: TxSubmitterConfig) -> Self {
        let anvil = TestAnvil::spawn_auto_mine().expect("failed to spawn anvil");
        let (redis_url, redis) = start_redis().await;

        let args = ProviderArgs {
            http: Some(vec![anvil.endpoint().parse().expect("invalid anvil url")]),
            signer: Some(SignerArgs::from_wallet(GW_PRIVATE_KEY.to_string())),
            ..Default::default()
        };
        let (provider, signer) = args
            .http_with_signer_address()
            .await
            .expect("failed to build provider");
        let signer = signer.expect("signer address should be resolved");
        let provider = Arc::new(provider);

        // Hold transactions in the mempool so a gap can be created on purpose.
        provider
            .anvil_set_auto_mine(false)
            .await
            .expect("failed to disable automine");

        let tracker = RequestTracker::new(redis_url, None, 600).await;
        let submitter = Arc::new(TxSubmitter::new(
            provider.clone(),
            signer,
            config,
            tracker.clone(),
        ));

        Self {
            submitter,
            provider,
            tracker,
            signer,
            _anvil: anvil,
            _redis: redis,
        }
    }

    /// Registers a request in the tracker and submits a self-transfer carrying
    /// it, returning the request id.
    async fn submit_one(&self) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        self.tracker
            .new_request_with_id(id.clone(), GatewayRequestKind::CreateAccount, vec![])
            .await
            .expect("failed to register request");

        let request = TransactionRequest::default()
            .to(self.signer)
            .value(U256::ZERO);

        self.submitter
            .submit(
                request,
                vec![id.clone()],
                "create",
                tokio::time::Instant::now(),
            )
            .await;
        id
    }

    async fn latest_nonce(&self) -> u64 {
        self.provider
            .get_transaction_count(self.signer)
            .await
            .expect("failed to read transaction count")
    }

    async fn mine(&self) {
        self.provider
            .anvil_mine(Some(1), None)
            .await
            .expect("failed to mine");
    }

    async fn drop_tx(&self, hash: &str) {
        let hash: TxHash = hash.parse().expect("invalid tx hash");
        self.provider
            .anvil_drop_transaction(hash)
            .await
            .expect("failed to drop transaction");
    }
}

fn base_config() -> TxSubmitterConfig {
    TxSubmitterConfig {
        escalation_interval_secs: TEST_ESCALATION_INTERVAL_SECS,
        escalation_factor_percent: 200,
        max_escalations: 3,
        // Disabled by default so the gap tests can queue several transactions.
        max_inflight_txs: 0,
        // Anvil accounts are funded; a floor of 0 keeps the tests deterministic.
        min_balance_wei: 0,
    }
}

/// The production failure: the transaction holding nonce `N` is dropped from the
/// mempool while `N+1` is already queued behind it. Nothing can be mined until
/// `N` is filled again.
///
/// Asserts that escalation re-broadcasts the dropped transaction at its original
/// nonce and both transactions then land.
#[tokio::test]
async fn dropped_transaction_is_rebroadcast_at_the_same_nonce() {
    let harness = Harness::new(base_config()).await;
    let start_nonce = harness.latest_nonce().await;

    harness.submit_one().await;
    harness.submit_one().await;

    let inflight = harness.submitter.inflight().await;
    assert_eq!(inflight.len(), 2, "both transactions should be in flight");
    assert_eq!(inflight[0].0, start_nonce);
    assert_eq!(inflight[1].0, start_nonce + 1);

    // Drop the transaction holding the lower nonce, leaving a gap.
    harness.drop_tx(&inflight[0].1).await;
    harness.mine().await;
    assert_eq!(
        harness.latest_nonce().await,
        start_nonce,
        "nothing can be mined while the gap exists"
    );

    // Let the escalation interval elapse, then run one pass.
    tokio::time::sleep(Duration::from_millis(
        TEST_ESCALATION_INTERVAL_SECS * 1000 + 200,
    ))
    .await;
    harness.submitter.escalate_once().await;

    harness.mine().await;
    assert_eq!(
        harness.latest_nonce().await,
        start_nonce + 2,
        "re-broadcast should fill the gap and unblock the queued transaction"
    );
}

/// With the escalation budget exhausted, the batch is abandoned: its requests
/// are failed and the nonce is released so later transactions can be mined.
#[tokio::test]
async fn exhausted_escalations_release_the_nonce() {
    let config = TxSubmitterConfig {
        // The first escalation pass goes straight to terminal.
        max_escalations: 0,
        ..base_config()
    };
    let harness = Harness::new(config).await;
    let start_nonce = harness.latest_nonce().await;

    let abandoned_id = harness.submit_one().await;
    harness.submit_one().await;

    let inflight = harness.submitter.inflight().await;
    harness.drop_tx(&inflight[0].1).await;
    harness.mine().await;
    assert_eq!(harness.latest_nonce().await, start_nonce);

    tokio::time::sleep(Duration::from_millis(
        TEST_ESCALATION_INTERVAL_SECS * 1000 + 200,
    ))
    .await;
    harness.submitter.escalate_once().await;

    harness.mine().await;
    assert_eq!(
        harness.latest_nonce().await,
        start_nonce + 2,
        "the release transaction should fill the nonce and unblock the queue"
    );

    let record = harness
        .tracker
        .snapshot(&abandoned_id)
        .await
        .expect("abandoned request should still have a record");
    assert!(
        matches!(record.status, GatewayRequestState::Failed { .. }),
        "abandoned batch requests must be failed, got {:?}",
        record.status
    );

    assert!(
        harness.submitter.inflight().await.is_empty(),
        "the abandoned entry must be dropped from the in-flight set"
    );
}

/// The in-flight cap refuses further submissions rather than piling batches up
/// behind a nonce that is not progressing.
#[tokio::test]
async fn inflight_cap_refuses_further_submissions() {
    let config = TxSubmitterConfig {
        max_inflight_txs: 1,
        ..base_config()
    };
    let harness = Harness::new(config).await;

    assert!(
        harness.submitter.can_submit().await,
        "an idle submitter should accept a batch"
    );

    harness.submit_one().await;

    assert!(
        !harness.submitter.can_submit().await,
        "the cap should refuse a second batch while one is unconfirmed"
    );

    harness.mine().await;
    // Give the receipt watcher a moment to clear the entry.
    for _ in 0..50 {
        if harness.submitter.inflight().await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        harness.submitter.can_submit().await,
        "capacity should return once the transaction is confirmed"
    );
}

/// A balance floor above the signer's balance stops submission.
#[tokio::test]
async fn balance_floor_stops_submission() {
    let config = TxSubmitterConfig {
        min_balance_wei: u128::MAX,
        ..base_config()
    };
    let harness = Harness::new(config).await;

    assert!(
        !harness.submitter.can_submit().await,
        "submission must stop when the balance is below the floor"
    );
}
