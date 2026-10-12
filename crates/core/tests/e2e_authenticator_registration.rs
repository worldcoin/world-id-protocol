#![cfg(feature = "authenticator")]

//! End-to-end WIP-109 registrations through the gateway, a V2 registry and a bridge stub.
//!
//! The scenarios run in order against one account and share its state. Each scenario is boxed,
//! so that the test's own future stays small on the test thread's stack.

use std::{sync::Arc, time::Duration};

use alloy::primitives::{Address, U256};
use reqwest::Url;
use world_id_core::{
    Authenticator, Signer,
    artifacts::{ZkArtifactSource, dummy::DummyZkArtifactSource},
    registration::{
        Approval, ApprovalOutcome, ApproverError, AuthenticatorName, BridgeClient,
        CheckedRegistration, DeliveryOutcome, IncomingRegistration, KnownAuthenticator,
        MAX_VAULT_SIZE, PendingRegistration, RegistrationDigest, RegistrationErrorReason,
        RegistrationPlan, RegistrationRequester, RequestedClass, RequesterStatus, UserVerification,
        Vault, VaultFormat,
    },
};
use world_id_gateway::{
    BatchPolicyConfig, GatewayConfig, GatewayHandle, RegistryVersion, SignerArgs, defaults,
    spawn_gateway_for_tests,
};
use world_id_primitives::{Config, ServiceEndpoint};
use world_id_test_utils::{
    anvil::TestAnvil,
    bridge::BridgeStub,
    redis_testcontainer,
    stubs::{AccountIndexerStub, StubAccount, StubAuthenticator},
};

/// The account's first authenticator, an Admin Authenticator that approves the registrations.
const APPROVER_SEED: [u8; 32] = [42; 32];
/// Registered as a Proving Authenticator, with the vault.
const PROVING_SEED: [u8; 32] = [43; 32];
/// Refused and declined, then registered as an Admin Authenticator.
const ADMIN_SEED: [u8; 32] = [44; 32];
/// Pairs through a link whose digest was replaced.
const TAMPERED_LINK_SEED: [u8; 32] = [45; 32];
/// Approved too close to the response deadline.
const LATE_APPROVAL_SEED: [u8; 32] = [46; 32];
/// Registered without its oversized vault.
const OVERSIZED_VAULT_SEED: [u8; 32] = [47; 32];
/// Ends with a failed user verification on the approving device.
const FAILED_VERIFICATION_SEED: [u8; 32] = [48; 32];
/// Approved with more than a response can carry.
const OVERSIZED_RESPONSE_SEED: [u8; 32] = [49; 32];

/// The services a registration runs against, and the account it registers on.
struct Harness {
    config: Config,
    approver: Authenticator,
    /// The account state the indexer stub serves, updated after each insertion lands.
    indexed: StubAccount,
    indexer: AccountIndexerStub,
    bridge: BridgeStub,
    _gateway: GatewayHandle,
    _anvil: TestAnvil,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_authenticator_registration() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let (_redis, redis_url) = redis_testcontainer()
        .await
        .expect("failed to start Redis testcontainer");
    let mut harness = Box::pin(Harness::start(redis_url)).await;

    let proving = Box::pin(a_proving_authenticator_is_registered_with_the_vault(
        &mut harness,
    ))
    .await;
    Box::pin(a_retry_finds_the_existing_registration(&harness)).await;
    Box::pin(another_class_for_a_registered_key_is_a_conflict(&harness)).await;
    Box::pin(a_proving_authenticator_cannot_approve(&harness, &proving)).await;
    Box::pin(the_user_declines(&harness)).await;
    Box::pin(an_admin_authenticator_is_registered_and_finds_its_account(
        &mut harness,
    ))
    .await;
    Box::pin(approving_close_to_the_deadline_submits_nothing(&harness)).await;
    Box::pin(failed_user_verification_submits_nothing(&harness)).await;
    Box::pin(an_oversized_vault_is_left_out(&mut harness)).await;
    Box::pin(an_oversized_response_is_refused_before_submitting(&harness)).await;
    Box::pin(a_request_that_does_not_match_its_link_is_answered_invalid_params(&harness)).await;
}

/// A Proving Authenticator is registered and receives the vault, and its pairing link cannot be
/// used twice.
async fn a_proving_authenticator_is_registered_with_the_vault(h: &mut Harness) -> Authenticator {
    let mut session = h.requester(&PROVING_SEED, RequestedClass::Proving);
    session.publish().await.unwrap();
    assert_eq!(session.poll().await.unwrap(), RequesterStatus::Waiting);
    let link = session.pairing_uri().unwrap();

    let incoming = h.receive(&mut session).await.unwrap();
    assert_eq!(
        incoming.request().name.as_ref().unwrap().as_str(),
        "Chrome on MacBook"
    );
    let checked = incoming.check(&h.approver).await.unwrap();
    assert_eq!(checked.plan(), RegistrationPlan::Insert { pubkey_id: 1 });
    let vault = Vault {
        format: VaultFormat::WalletkitPlaintextV1,
        data: b"SQLite format 3".to_vec().into(),
    };
    let approval = Approval {
        vault: Some(vault.clone()),
        authenticators: vec![KnownAuthenticator {
            pubkey_id: 0,
            name: "iPhone".to_string(),
        }],
    };
    let outcome = h
        .approve_and_index(checked, approval, &PROVING_SEED, RequestedClass::Proving)
        .await;
    assert_eq!(outcome.delivery.unwrap(), DeliveryOutcome::Delivered);
    assert_eq!(outcome.result.unwrap().pubkey_id, 1);

    let RequesterStatus::Completed(Ok(result)) = completed(&mut session).await else {
        panic!("registration failed");
    };
    assert_eq!(result.leaf_index, h.approver.leaf_index());
    assert_eq!(result.vault, Some(vault));
    assert_eq!(result.authenticators[0].name.as_str(), "iPhone");
    let proving = session
        .verify(&PROVING_SEED, &result, h.config.clone(), dummy_zk_source())
        .await
        .unwrap();
    assert_eq!(proving.leaf_index(), h.approver.leaf_index());
    assert_eq!(proving.pubkey_id(), U256::from(1));
    assert_eq!(session.poll().await.unwrap(), RequesterStatus::Expired);

    let reused = PendingRegistration::receive(&link, &[h.bridge_client()]).await;
    assert!(matches!(reused, Err(ApproverError::Expired)));
    proving
}

/// A new session with the same keys finds the existing registration and inserts nothing.
async fn a_retry_finds_the_existing_registration(h: &Harness) {
    let nonce = h.approver.signing_nonce().await.unwrap();
    let mut session = h.requester(&PROVING_SEED, RequestedClass::Proving);
    session.publish().await.unwrap();
    let checked = h
        .receive(&mut session)
        .await
        .unwrap()
        .check(&h.approver)
        .await
        .unwrap();
    assert_eq!(
        checked.plan(),
        RegistrationPlan::AlreadyRegistered { pubkey_id: 1 }
    );
    let outcome = checked
        .approve(&h.approver, Approval::default(), verified())
        .await;
    assert_eq!(outcome.delivery.unwrap(), DeliveryOutcome::Delivered);

    let RequesterStatus::Completed(Ok(result)) = completed(&mut session).await else {
        panic!("retry failed");
    };
    assert_eq!((result.pubkey_id, result.vault), (1, None));
    assert_eq!(h.approver.signing_nonce().await.unwrap(), nonce);
}

/// Asking for another class with a registered key is refused as a conflict.
async fn another_class_for_a_registered_key_is_a_conflict(h: &Harness) {
    let mut session = h.requester(&PROVING_SEED, RequestedClass::Admin);
    session.publish().await.unwrap();
    let refused = h
        .receive(&mut session)
        .await
        .unwrap()
        .check(&h.approver)
        .await;
    assert!(matches!(
        refused,
        Err(ApproverError::Refused {
            reason: RegistrationErrorReason::AuthenticatorConflict,
            ..
        })
    ));
    assert_error(&mut session, RegistrationErrorReason::AuthenticatorConflict).await;
}

/// A Proving Authenticator cannot approve registrations.
async fn a_proving_authenticator_cannot_approve(h: &Harness, proving: &Authenticator) {
    let mut session = h.requester(&ADMIN_SEED, RequestedClass::Admin);
    session.publish().await.unwrap();
    let refused = h.receive(&mut session).await.unwrap().check(proving).await;
    assert!(matches!(
        refused,
        Err(ApproverError::Refused {
            reason: RegistrationErrorReason::NotAuthorized,
            ..
        })
    ));
    assert_error(&mut session, RegistrationErrorReason::NotAuthorized).await;
}

/// The user declines on the consent screen.
async fn the_user_declines(h: &Harness) {
    let mut session = h.requester(&ADMIN_SEED, RequestedClass::Admin);
    session.publish().await.unwrap();
    let checked = h
        .receive(&mut session)
        .await
        .unwrap()
        .check(&h.approver)
        .await
        .unwrap();
    assert_eq!(checked.reject().await.unwrap(), DeliveryOutcome::Delivered);
    assert_error(&mut session, RegistrationErrorReason::UserRejected).await;
}

/// An Admin Authenticator is registered and can find its account by its address.
async fn an_admin_authenticator_is_registered_and_finds_its_account(h: &mut Harness) {
    let mut session = h.requester(&ADMIN_SEED, RequestedClass::Admin);
    session.publish().await.unwrap();
    let checked = h
        .receive(&mut session)
        .await
        .unwrap()
        .check(&h.approver)
        .await
        .unwrap();
    assert_eq!(checked.plan(), RegistrationPlan::Insert { pubkey_id: 2 });
    let outcome = h
        .approve_and_index(
            checked,
            Approval::default(),
            &ADMIN_SEED,
            RequestedClass::Admin,
        )
        .await;
    assert_eq!(outcome.delivery.unwrap(), DeliveryOutcome::Delivered);

    let RequesterStatus::Completed(Ok(result)) = completed(&mut session).await else {
        panic!("admin registration failed");
    };
    session
        .verify(&ADMIN_SEED, &result, h.config.clone(), dummy_zk_source())
        .await
        .unwrap();
    let admin = Authenticator::init(&ADMIN_SEED, h.config.clone(), dummy_zk_source())
        .await
        .unwrap();
    assert_eq!(admin.leaf_index(), h.approver.leaf_index());
    assert_eq!(admin.pubkey_id(), U256::from(2));
}

/// Approving with too little time left to track an insertion submits nothing.
async fn approving_close_to_the_deadline_submits_nothing(h: &Harness) {
    let nonce = h.approver.signing_nonce().await.unwrap();
    let mut session = h.requester(&LATE_APPROVAL_SEED, RequestedClass::Proving);
    session.publish().await.unwrap();
    let checked = h
        .receive(&mut session)
        .await
        .unwrap()
        .with_response_deadline(Duration::from_secs(30))
        .check(&h.approver)
        .await
        .unwrap();
    let outcome = checked
        .approve(&h.approver, Approval::default(), verified())
        .await;
    assert_eq!(outcome.result, Err(RegistrationErrorReason::InternalError));
    assert_eq!(h.approver.signing_nonce().await.unwrap(), nonce);
    assert_error(&mut session, RegistrationErrorReason::InternalError).await;
}

/// A failed user verification ends the session with `internal_error` and submits nothing.
async fn failed_user_verification_submits_nothing(h: &Harness) {
    let nonce = h.approver.signing_nonce().await.unwrap();
    let mut session = h.requester(&FAILED_VERIFICATION_SEED, RequestedClass::Proving);
    session.publish().await.unwrap();
    let checked = h
        .receive(&mut session)
        .await
        .unwrap()
        .check(&h.approver)
        .await
        .unwrap();
    assert_eq!(
        checked.user_verification_failed().await.unwrap(),
        DeliveryOutcome::Delivered
    );
    assert_eq!(h.approver.signing_nonce().await.unwrap(), nonce);
    assert_error(&mut session, RegistrationErrorReason::InternalError).await;
}

/// A vault over 3.5 MiB is left out, and the registration proceeds without it.
async fn an_oversized_vault_is_left_out(h: &mut Harness) {
    let mut session = h.requester(&OVERSIZED_VAULT_SEED, RequestedClass::Proving);
    session.publish().await.unwrap();
    let checked = h
        .receive(&mut session)
        .await
        .unwrap()
        .check(&h.approver)
        .await
        .unwrap();
    assert_eq!(checked.plan(), RegistrationPlan::Insert { pubkey_id: 3 });
    let approval = Approval {
        vault: Some(Vault {
            format: VaultFormat::WalletkitPlaintextV1,
            data: vec![0; MAX_VAULT_SIZE + 1].into(),
        }),
        ..Approval::default()
    };
    let outcome = h
        .approve_and_index(
            checked,
            approval,
            &OVERSIZED_VAULT_SEED,
            RequestedClass::Proving,
        )
        .await;
    assert!(outcome.vault_omitted);
    assert_eq!(outcome.delivery.unwrap(), DeliveryOutcome::Delivered);

    let RequesterStatus::Completed(Ok(result)) = completed(&mut session).await else {
        panic!("registration without the vault failed");
    };
    assert_eq!((result.pubkey_id, result.vault), (3, None));
}

/// An approval too large for the requester to accept is refused before anything is submitted.
async fn an_oversized_response_is_refused_before_submitting(h: &Harness) {
    let nonce = h.approver.signing_nonce().await.unwrap();
    let mut session = h.requester(&OVERSIZED_RESPONSE_SEED, RequestedClass::Proving);
    session.publish().await.unwrap();
    let checked = h
        .receive(&mut session)
        .await
        .unwrap()
        .check(&h.approver)
        .await
        .unwrap();
    let oversized = Approval {
        authenticators: vec![KnownAuthenticator {
            pubkey_id: 0,
            name: "x".repeat(4 * 1024 * 1024),
        }],
        ..Approval::default()
    };
    let outcome = checked.approve(&h.approver, oversized, verified()).await;
    assert_eq!(outcome.result, Err(RegistrationErrorReason::InternalError));
    assert_eq!(h.approver.signing_nonce().await.unwrap(), nonce);
    assert_error(&mut session, RegistrationErrorReason::InternalError).await;
}

/// A request that does not match the digest in its link is answered with `invalid_params`.
async fn a_request_that_does_not_match_its_link_is_answered_invalid_params(h: &Harness) {
    let mut session = h.requester(&TAMPERED_LINK_SEED, RequestedClass::Proving);
    session.publish().await.unwrap();
    let mut tampered = session.pairing_uri().unwrap();
    tampered.digest = RegistrationDigest::from_bytes([0; 32]);
    let mut pending = PendingRegistration::receive(&tampered, &[h.bridge_client()])
        .await
        .unwrap();
    assert_eq!(session.poll().await.unwrap(), RequesterStatus::Retrieved);

    let refused = pending.authenticate(session.pairing_code().unwrap()).await;
    assert!(matches!(
        refused,
        Err(ApproverError::InvalidRequest {
            delivery: Some(Ok(DeliveryOutcome::Delivered)),
            ..
        })
    ));
    assert_error(&mut session, RegistrationErrorReason::InvalidParams).await;
}

impl Harness {
    /// Starts anvil with a V2 registry, the gateway and the stubs, and registers the account's
    /// first authenticator from [`APPROVER_SEED`].
    async fn start(redis_url: String) -> Self {
        let anvil = TestAnvil::spawn_with_multicall3()
            .await
            .expect("failed to spawn anvil with multicall3");
        let deployer = anvil.signer(0).unwrap();
        let registry_address = anvil
            .deploy_world_id_registry_v2(deployer.clone())
            .await
            .unwrap();
        let gateway = spawn_gateway_for_tests(GatewayConfig {
            registry_addr: registry_address,
            registry_version: RegistryVersion::V2,
            provider: world_id_gateway::ProviderArgs {
                http: vec![anvil.endpoint().parse().unwrap()],
                signer: SignerArgs::from_wallet(hex::encode(deployer.to_bytes())),
                ..Default::default()
            },
            listen_addr: (std::net::Ipv4Addr::LOCALHOST, 0).into(),
            max_create_batch_size: 10,
            max_ops_batch_size: 10,
            redis_url,
            request_timeout_secs: 10,
            rate_limit_max_requests: None,
            rate_limit_window_secs: None,
            sweeper_interval_secs: defaults::SWEEPER_INTERVAL_SECS,
            stale_queued_threshold_secs: defaults::STALE_QUEUED_THRESHOLD_SECS,
            stale_submitted_threshold_secs: defaults::STALE_SUBMITTED_THRESHOLD_SECS,
            batch_policy: BatchPolicyConfig::default(),
        })
        .await
        .expect("failed to spawn gateway");
        let indexer = AccountIndexerStub::spawn().await.unwrap();
        let bridge = BridgeStub::spawn().await.unwrap();
        let config = Config::new(
            Some(anvil.endpoint().to_string()),
            anvil.instance.chain_id(),
            registry_address,
            ServiceEndpoint::direct(indexer.url.clone()),
            ServiceEndpoint::direct(format!("http://{}", gateway.listen_addr)),
            Vec::new(),
            2,
        )
        .unwrap();

        let approver = Authenticator::init_or_register(
            &APPROVER_SEED,
            config.clone(),
            Some(anvil.signer(1).unwrap().address()),
            dummy_zk_source(),
        )
        .await
        .unwrap();
        let indexed = StubAccount {
            authenticators: vec![Some(StubAuthenticator {
                pubkey: approver.offchain_pubkey(),
                address: approver.onchain_address(),
            })],
            recovery_counter: 0,
        };
        indexer.set_account(approver.leaf_index(), indexed.clone());
        Self {
            config,
            approver,
            indexed,
            indexer,
            bridge,
            _gateway: gateway,
            _anvil: anvil,
        }
    }

    fn bridge_client(&self) -> BridgeClient {
        BridgeClient::with_base_url(
            "bridge.example.org".parse().unwrap(),
            Url::parse(&self.bridge.url).unwrap(),
        )
        .unwrap()
    }

    fn requester(&self, seed: &[u8; 32], class: RequestedClass) -> RegistrationRequester {
        let name = AuthenticatorName::try_from("Chrome on MacBook".to_string()).unwrap();
        RegistrationRequester::new(seed, class, Some(name), self.bridge_client()).unwrap()
    }

    /// Opens the session's link on the approver, then enters the code the requester shows once
    /// the request was retrieved.
    async fn receive(
        &self,
        session: &mut RegistrationRequester,
    ) -> Result<IncomingRegistration, ApproverError> {
        assert!(session.pairing_code().is_none());
        let mut pending =
            PendingRegistration::receive(&session.pairing_uri().unwrap(), &[self.bridge_client()])
                .await?;
        assert_eq!(session.poll().await.unwrap(), RequesterStatus::Retrieved);
        assert!(session.pairing_uri().is_none());
        pending.authenticate(session.pairing_code().unwrap()).await
    }

    /// Approves `checked`, and indexes the authenticator from `seed` once its insertion reaches
    /// the registry, as an indexer would.
    async fn approve_and_index(
        &mut self,
        checked: CheckedRegistration,
        approval: Approval,
        seed: &[u8; 32],
        class: RequestedClass,
    ) -> ApprovalOutcome {
        let signer = Signer::from_seed_bytes(seed).unwrap();
        let mut indexed = self.indexed.clone();
        indexed.authenticators.push(Some(StubAuthenticator {
            pubkey: signer.offchain_signer_pubkey(),
            address: match class {
                RequestedClass::Admin => signer.onchain_signer_address(),
                RequestedClass::Proving => Address::ZERO,
            },
        }));
        let nonce = self.approver.signing_nonce().await.unwrap();
        let index_after_insertion = async {
            tokio::time::timeout(Duration::from_secs(60), async {
                while self.approver.signing_nonce().await.unwrap() == nonce {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .expect("insertion did not reach the registry");
            self.indexer
                .set_account(self.approver.leaf_index(), indexed.clone());
        };
        let (outcome, ()) = tokio::join!(
            checked.approve(&self.approver, approval, verified()),
            index_after_insertion
        );
        self.indexed = indexed;
        outcome
    }
}

/// Polls once and expects the session to complete. A completed status is not printed, because
/// it holds the decrypted response.
async fn completed(session: &mut RegistrationRequester) -> RequesterStatus {
    let status = session.poll().await.unwrap();
    assert!(
        matches!(status, RequesterStatus::Completed(_)),
        "registration did not complete"
    );
    status
}

/// Polls once and expects the session to end with `reason`.
async fn assert_error(session: &mut RegistrationRequester, reason: RegistrationErrorReason) {
    let RequesterStatus::Completed(Err(error)) = completed(session).await else {
        panic!("expected {}", reason.code());
    };
    assert_eq!(error.code, reason.code());
}

fn verified() -> UserVerification {
    UserVerification::platform_check_succeeded()
}

fn dummy_zk_source() -> Arc<dyn ZkArtifactSource> {
    Arc::new(DummyZkArtifactSource)
}
