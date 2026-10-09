#![cfg(feature = "authenticator")]

//! End-to-end WIP-109 registrations through the gateway, a V2 registry and a bridge stub.

use std::{sync::Arc, time::Duration};

use alloy::primitives::{Address, U256};
use reqwest::Url;
use world_id_core::{
    Authenticator, Signer,
    artifacts::{ZkArtifactSource, dummy::DummyZkArtifactSource},
    registration::{
        Approval, ApprovalOutcome, ApproverError, AuthenticatorName, BridgeClient,
        CheckedRegistration, DeliveryOutcome, IncomingRegistration, KnownAuthenticator,
        PendingRegistration, RegistrationDigest, RegistrationErrorReason, RegistrationPlan,
        RegistrationRequester, RequestedClass, RequesterStatus, UserVerification, Vault,
        VaultFormat,
    },
};
use world_id_gateway::{
    BatchPolicyConfig, GatewayConfig, RegistryVersion, SignerArgs, defaults,
    spawn_gateway_for_tests,
};
use world_id_primitives::{Config, ServiceEndpoint};
use world_id_test_utils::{
    anvil::TestAnvil,
    bridge::BridgeStub,
    redis_testcontainer,
    stubs::{AccountIndexerStub, StubAccount},
};

const PRIMARY_SEED: [u8; 32] = [42; 32];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_authenticator_registration() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let anvil = TestAnvil::spawn_with_multicall3()
        .await
        .expect("failed to spawn anvil with multicall3");
    let (_redis, redis_url) = redis_testcontainer()
        .await
        .expect("failed to start Redis testcontainer");
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

    let primary = Authenticator::init_or_register(
        &PRIMARY_SEED,
        config.clone(),
        Some(anvil.signer(1).unwrap().address()),
        dummy_zk_source(),
    )
    .await
    .unwrap();
    let mut account = Account {
        leaf_index: primary.leaf_index(),
        authenticators: vec![(PRIMARY_SEED, primary.onchain_address())],
    };
    account.sync(&indexer);

    // A Proving Authenticator is registered and receives the vault.
    let proving_seed = [43u8; 32];
    let mut session = requester(&proving_seed, RequestedClass::Proving, &bridge);
    session.publish().await.unwrap();
    assert_eq!(session.poll().await.unwrap(), RequesterStatus::Waiting);

    let original_uri = session.pairing_uri().unwrap();
    let incoming = receive(&mut session, &bridge).await.unwrap();
    assert_eq!(
        incoming.request().name.as_ref().unwrap().as_str(),
        "Chrome on MacBook"
    );
    assert_eq!(session.poll().await.unwrap(), RequesterStatus::Retrieved);

    let checked = incoming.check(&primary).await.unwrap();
    assert_eq!(checked.plan(), RegistrationPlan::Insert { pubkey_id: 1 });
    let vault = Vault {
        format: VaultFormat::WalletkitPlaintextV1,
        data: b"SQLite format 3".to_vec(),
    };
    let outcome = approve_and_sync(
        checked,
        &primary,
        &mut account,
        (proving_seed, Address::ZERO),
        &indexer,
        Approval {
            vault: Some(vault.clone()),
            authenticators: vec![KnownAuthenticator {
                pubkey_id: 0,
                name: "iPhone".to_string(),
            }],
        },
    )
    .await;
    assert_eq!(outcome.delivery.unwrap(), DeliveryOutcome::Delivered);
    assert_eq!(outcome.result.as_ref().unwrap().pubkey_id, 1);

    let RequesterStatus::Completed(Ok(result)) = completed(&mut session).await else {
        panic!("registration failed");
    };
    assert_eq!(result.leaf_index, account.leaf_index);
    assert_eq!(result.vault, Some(vault));
    assert_eq!(result.authenticators[0].name.as_str(), "iPhone");
    let proving = session
        .verify(&proving_seed, &result, config.clone(), dummy_zk_source())
        .await
        .unwrap();
    assert_eq!(proving.leaf_index(), account.leaf_index);
    assert_eq!(proving.pubkey_id(), U256::from(1));
    assert_eq!(session.poll().await.unwrap(), RequesterStatus::Expired);

    // The same pairing link cannot be used twice.
    let reused = PendingRegistration::receive(&original_uri, bridge_client(&bridge)).await;
    assert!(matches!(reused, Err(ApproverError::Expired)));

    // A retry with the same keys finds the existing registration and inserts nothing.
    let nonce = primary.signing_nonce().await.unwrap();
    let mut retry = requester(&proving_seed, RequestedClass::Proving, &bridge);
    retry.publish().await.unwrap();
    let checked = receive(&mut retry, &bridge)
        .await
        .unwrap()
        .check(&primary)
        .await
        .unwrap();
    assert_eq!(
        checked.plan(),
        RegistrationPlan::AlreadyRegistered { pubkey_id: 1 }
    );
    checked
        .approve(&primary, Approval::default(), verified())
        .await
        .delivery
        .unwrap();
    let RequesterStatus::Completed(Ok(result)) = completed(&mut retry).await else {
        panic!("retry failed");
    };
    assert_eq!((result.pubkey_id, result.vault), (1, None));
    assert_eq!(primary.signing_nonce().await.unwrap(), nonce);

    // Asking for another class with a registered key is a conflict.
    let mut conflicting = requester(&proving_seed, RequestedClass::Admin, &bridge);
    conflicting.publish().await.unwrap();
    let refused = receive(&mut conflicting, &bridge)
        .await
        .unwrap()
        .check(&primary)
        .await;
    assert!(matches!(
        refused,
        Err(ApproverError::Refused {
            reason: RegistrationErrorReason::AuthenticatorConflict,
            ..
        })
    ));
    let RequesterStatus::Completed(Err(error)) = completed(&mut conflicting).await else {
        panic!("expected a conflict");
    };
    assert_eq!(
        error.code,
        RegistrationErrorReason::AuthenticatorConflict.code()
    );

    // A Proving Authenticator cannot approve registrations.
    let admin_seed = [44u8; 32];
    let mut session = requester(&admin_seed, RequestedClass::Admin, &bridge);
    session.publish().await.unwrap();
    let refused = receive(&mut session, &bridge)
        .await
        .unwrap()
        .check(&proving)
        .await;
    assert!(matches!(
        refused,
        Err(ApproverError::Refused {
            reason: RegistrationErrorReason::NotAuthorized,
            ..
        })
    ));

    // The user declines.
    let mut session = requester(&admin_seed, RequestedClass::Admin, &bridge);
    session.publish().await.unwrap();
    let checked = receive(&mut session, &bridge)
        .await
        .unwrap()
        .check(&primary)
        .await
        .unwrap();
    assert_eq!(checked.reject().await.unwrap(), DeliveryOutcome::Delivered);
    let RequesterStatus::Completed(Err(error)) = completed(&mut session).await else {
        panic!("expected a rejection");
    };
    assert_eq!(error.code, RegistrationErrorReason::UserRejected.code());

    // An Admin Authenticator is registered and can find its account by address.
    let mut session = requester(&admin_seed, RequestedClass::Admin, &bridge);
    session.publish().await.unwrap();
    let checked = receive(&mut session, &bridge)
        .await
        .unwrap()
        .check(&primary)
        .await
        .unwrap();
    assert_eq!(checked.plan(), RegistrationPlan::Insert { pubkey_id: 2 });
    let admin_address = Signer::from_seed_bytes(&admin_seed)
        .unwrap()
        .onchain_signer_address();
    approve_and_sync(
        checked,
        &primary,
        &mut account,
        (admin_seed, admin_address),
        &indexer,
        Approval::default(),
    )
    .await
    .delivery
    .unwrap();
    let status = completed(&mut session).await;
    let RequesterStatus::Completed(Ok(result)) = status else {
        panic!("admin registration failed");
    };
    session
        .verify(&admin_seed, &result, config.clone(), dummy_zk_source())
        .await
        .unwrap();
    let admin = Authenticator::init(&admin_seed, config, dummy_zk_source())
        .await
        .unwrap();
    assert_eq!(admin.leaf_index(), account.leaf_index);
    assert_eq!(admin.pubkey_id(), U256::from(2));

    // Approving too close to the deadline submits nothing.
    let nonce = primary.signing_nonce().await.unwrap();
    let mut session = requester(&[46u8; 32], RequestedClass::Proving, &bridge);
    session.publish().await.unwrap();
    let checked = receive(&mut session, &bridge)
        .await
        .unwrap()
        .with_response_deadline(Duration::from_secs(30))
        .check(&primary)
        .await
        .unwrap();
    let outcome = checked
        .approve(&primary, Approval::default(), verified())
        .await;
    assert_eq!(outcome.result, Err(RegistrationErrorReason::InternalError));
    assert_eq!(primary.signing_nonce().await.unwrap(), nonce);
    let RequesterStatus::Completed(Err(error)) = completed(&mut session).await else {
        panic!("expected an internal error");
    };
    assert_eq!(error.code, RegistrationErrorReason::InternalError.code());

    // Failed device verification ends the attempt with `internal_error` and submits nothing.
    let mut session = requester(&[48u8; 32], RequestedClass::Proving, &bridge);
    session.publish().await.unwrap();
    let checked = receive(&mut session, &bridge)
        .await
        .unwrap()
        .check(&primary)
        .await
        .unwrap();
    checked.verification_failed().await.unwrap();
    assert_eq!(primary.signing_nonce().await.unwrap(), nonce);
    let RequesterStatus::Completed(Err(error)) = completed(&mut session).await else {
        panic!("expected an internal error");
    };
    assert_eq!(error.code, RegistrationErrorReason::InternalError.code());

    // A vault too large for the requester to accept is refused before anything is submitted.
    let mut session = requester(&[47u8; 32], RequestedClass::Proving, &bridge);
    session.publish().await.unwrap();
    let checked = receive(&mut session, &bridge)
        .await
        .unwrap()
        .check(&primary)
        .await
        .unwrap();
    let oversized = Approval {
        vault: Some(Vault {
            format: VaultFormat::WalletkitPlaintextV1,
            data: vec![0; 16 * 1024 * 1024],
        }),
        ..Approval::default()
    };
    let outcome = checked.approve(&primary, oversized, verified()).await;
    assert_eq!(outcome.result, Err(RegistrationErrorReason::InternalError));
    assert_eq!(primary.signing_nonce().await.unwrap(), nonce);
    let RequesterStatus::Completed(Err(error)) = completed(&mut session).await else {
        panic!("expected an internal error");
    };
    assert_eq!(error.code, RegistrationErrorReason::InternalError.code());

    // A request that does not match the digest in the link is dropped without a response.
    let mut session = requester(&[45u8; 32], RequestedClass::Proving, &bridge);
    session.publish().await.unwrap();
    let mut tampered = session.pairing_uri().unwrap();
    tampered.digest = RegistrationDigest::from_bytes([0; 32]);
    let mut pending = PendingRegistration::receive(&tampered, bridge_client(&bridge))
        .await
        .unwrap();
    assert_eq!(session.poll().await.unwrap(), RequesterStatus::Retrieved);
    let dropped = pending.authenticate(session.pairing_code().unwrap()).await;
    assert!(matches!(dropped, Err(ApproverError::DigestMismatch)));
    assert_eq!(session.poll().await.unwrap(), RequesterStatus::Retrieved);
}

fn dummy_zk_source() -> Arc<dyn ZkArtifactSource> {
    Arc::new(DummyZkArtifactSource)
}

/// The indexed account state the test keeps in sync with the registry: `(seed, address)` by
/// `pubkey_id`.
struct Account {
    leaf_index: u64,
    authenticators: Vec<([u8; 32], Address)>,
}

impl Account {
    fn sync(&self, indexer: &AccountIndexerStub) {
        indexer.set_account(
            self.leaf_index,
            StubAccount {
                pubkeys: self
                    .authenticators
                    .iter()
                    .map(|(seed, _)| {
                        Some(
                            Signer::from_seed_bytes(seed)
                                .unwrap()
                                .offchain_signer_pubkey(),
                        )
                    })
                    .collect(),
                addresses: self
                    .authenticators
                    .iter()
                    .map(|(_, address)| Some(*address))
                    .collect(),
                recovery_counter: 0,
            },
        );
    }
}

fn verified() -> UserVerification {
    UserVerification::platform_check_succeeded()
}

fn bridge_client(bridge: &BridgeStub) -> BridgeClient {
    BridgeClient::new(Url::parse(&bridge.url).unwrap()).unwrap()
}

fn requester(seed: &[u8; 32], class: RequestedClass, bridge: &BridgeStub) -> RegistrationRequester {
    let name = AuthenticatorName::try_from("Chrome on MacBook".to_string()).unwrap();
    RegistrationRequester::new(seed, class, Some(name), bridge_client(bridge), None).unwrap()
}

async fn completed(requester: &mut RegistrationRequester) -> RequesterStatus {
    let status = requester.poll().await.unwrap();
    // The status is not printed: a completed one holds the decrypted response.
    assert!(
        matches!(status, RequesterStatus::Completed(_)),
        "registration did not complete"
    );
    status
}

async fn receive(
    session: &mut RegistrationRequester,
    bridge: &BridgeStub,
) -> Result<IncomingRegistration, ApproverError> {
    assert!(session.pairing_code().is_none());
    let mut pending =
        PendingRegistration::receive(&session.pairing_uri().unwrap(), bridge_client(bridge))
            .await?;
    assert_eq!(session.poll().await.unwrap(), RequesterStatus::Retrieved);
    assert!(session.pairing_uri().is_none());
    pending.authenticate(session.pairing_code().unwrap()).await
}

async fn approve_and_sync(
    checked: CheckedRegistration,
    primary: &Authenticator,
    account: &mut Account,
    inserted: ([u8; 32], Address),
    indexer: &AccountIndexerStub,
    approval: Approval,
) -> ApprovalOutcome {
    let nonce = primary.signing_nonce().await.unwrap();
    let update_indexer = async {
        tokio::time::timeout(Duration::from_secs(60), async {
            while primary.signing_nonce().await.unwrap() == nonce {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("insertion did not reach the registry");
        account.authenticators.push(inserted);
        account.sync(indexer);
    };
    let (outcome, ()) = tokio::join!(
        checked.approve(primary, approval, verified()),
        update_indexer
    );
    outcome
}
