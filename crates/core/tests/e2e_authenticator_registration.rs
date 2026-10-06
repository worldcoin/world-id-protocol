#![cfg(feature = "authenticator")]

//! End-to-end WIP-109 registrations through the gateway, a V2 registry and a bridge stub.

use std::sync::Arc;

use alloy::primitives::{Address, U256};
use reqwest::Url;
use world_id_core::{
    Authenticator, Signer,
    artifacts::{ZkArtifactSource, dummy::DummyZkArtifactSource},
    registration::{
        Approval, ApproverError, AuthenticatorName, BridgeClient, DeliveryOutcome,
        IncomingRegistration, KnownAuthenticator, RegistrationDigest, RegistrationErrorReason,
        RegistrationPlan, RegistrationRequester, RequestedClass, RequesterStatus, Vault,
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

fn bridge_client(bridge: &BridgeStub) -> BridgeClient {
    BridgeClient::new(Url::parse(&bridge.url).unwrap()).unwrap()
}

fn requester(seed: &[u8; 32], class: RequestedClass, bridge: &BridgeStub) -> RegistrationRequester {
    let name = AuthenticatorName::try_from("Chrome on MacBook".to_string()).unwrap();
    RegistrationRequester::new(seed, class, Some(name), bridge_client(bridge), None).unwrap()
}

async fn completed(requester: &RegistrationRequester) -> RequesterStatus {
    let status = requester.poll().await.unwrap();
    assert!(
        matches!(status, RequesterStatus::Completed(_)),
        "unexpected status {status:?}"
    );
    status
}

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
    let session = requester(&proving_seed, RequestedClass::Proving, &bridge);
    session.publish().await.unwrap();
    assert_eq!(session.poll().await.unwrap(), RequesterStatus::Waiting);

    let incoming = IncomingRegistration::receive(&session.pairing_uri(), bridge_client(&bridge))
        .await
        .unwrap();
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
    let outcome = checked
        .approve(
            &primary,
            Approval {
                vault: Some(vault.clone()),
                authenticators: vec![KnownAuthenticator {
                    pubkey_id: 0,
                    name: AuthenticatorName::try_from("iPhone".to_string()).unwrap(),
                }],
            },
        )
        .await
        .unwrap();
    assert_eq!(outcome.delivery, DeliveryOutcome::Delivered);
    assert_eq!(outcome.result.as_ref().unwrap().pubkey_id, 1);
    account.authenticators.push((proving_seed, Address::ZERO));
    account.sync(&indexer);

    let RequesterStatus::Completed(Ok(result)) = completed(&session).await else {
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
    let reused =
        IncomingRegistration::receive(&session.pairing_uri(), bridge_client(&bridge)).await;
    assert!(matches!(reused, Err(ApproverError::Expired)));

    // A retry with the same keys finds the existing registration and inserts nothing.
    let nonce = primary.signing_nonce().await.unwrap();
    let retry = requester(&proving_seed, RequestedClass::Proving, &bridge);
    retry.publish().await.unwrap();
    let checked = IncomingRegistration::receive(&retry.pairing_uri(), bridge_client(&bridge))
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
        .approve(&primary, Approval::default())
        .await
        .unwrap();
    let RequesterStatus::Completed(Ok(result)) = completed(&retry).await else {
        panic!("retry failed");
    };
    assert_eq!((result.pubkey_id, result.vault), (1, None));
    assert_eq!(primary.signing_nonce().await.unwrap(), nonce);

    // Asking for another class with a registered key is a conflict.
    let conflicting = requester(&proving_seed, RequestedClass::Admin, &bridge);
    conflicting.publish().await.unwrap();
    let refused = IncomingRegistration::receive(&conflicting.pairing_uri(), bridge_client(&bridge))
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
    let RequesterStatus::Completed(Err(error)) = completed(&conflicting).await else {
        panic!("expected a conflict");
    };
    assert_eq!(error.reason, RegistrationErrorReason::AuthenticatorConflict);

    // A Proving Authenticator cannot approve registrations.
    let admin_seed = [44u8; 32];
    let session = requester(&admin_seed, RequestedClass::Admin, &bridge);
    session.publish().await.unwrap();
    let refused = IncomingRegistration::receive(&session.pairing_uri(), bridge_client(&bridge))
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
    let session = requester(&admin_seed, RequestedClass::Admin, &bridge);
    session.publish().await.unwrap();
    let checked = IncomingRegistration::receive(&session.pairing_uri(), bridge_client(&bridge))
        .await
        .unwrap()
        .check(&primary)
        .await
        .unwrap();
    assert_eq!(checked.reject().await.unwrap(), DeliveryOutcome::Delivered);
    let RequesterStatus::Completed(Err(error)) = completed(&session).await else {
        panic!("expected a rejection");
    };
    assert_eq!(error.reason, RegistrationErrorReason::UserRejected);

    // An Admin Authenticator is registered and can find its account by address.
    let session = requester(&admin_seed, RequestedClass::Admin, &bridge);
    session.publish().await.unwrap();
    let checked = IncomingRegistration::receive(&session.pairing_uri(), bridge_client(&bridge))
        .await
        .unwrap()
        .check(&primary)
        .await
        .unwrap();
    assert_eq!(checked.plan(), RegistrationPlan::Insert { pubkey_id: 2 });
    checked
        .approve(&primary, Approval::default())
        .await
        .unwrap();
    let admin_address = Signer::from_seed_bytes(&admin_seed)
        .unwrap()
        .onchain_signer_address();
    account.authenticators.push((admin_seed, admin_address));
    account.sync(&indexer);
    let status = completed(&session).await;
    let RequesterStatus::Completed(Ok(result)) = status else {
        panic!("admin registration failed: {status:?}");
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

    // A request that does not match the digest in the link is dropped without a response.
    let session = requester(&[45u8; 32], RequestedClass::Proving, &bridge);
    session.publish().await.unwrap();
    let mut tampered = session.pairing_uri();
    tampered.digest = RegistrationDigest::from_bytes([0; 32]);
    let dropped = IncomingRegistration::receive(&tampered, bridge_client(&bridge)).await;
    assert!(matches!(dropped, Err(ApproverError::DigestMismatch)));
    assert_eq!(session.poll().await.unwrap(), RequesterStatus::Retrieved);
}
