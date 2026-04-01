use alloy::{
    primitives::{Address, U256},
    signers::local::PrivateKeySigner,
};
use reqwest::StatusCode;
use world_id_core::{
    Authenticator, AuthenticatorError, EdDSAPrivateKey, EdDSAPublicKey, OnchainKeyRepresentable,
    api_types::{
        GatewayRequestId, GatewayRequestKind, GatewayStatusResponse, RecoverAccountRequest,
    },
    primitives::{Config, TREE_DEPTH, merkle::AccountInclusionProof},
    world_id_registry::{domain as ag_domain, sign_recover_account},
};

use world_id_test_utils::{
    fixtures::{MerkleFixture, single_leaf_merkle_fixture},
    stubs::MutableIndexerStub,
};

use crate::common::{TestGateway, spawn_test_gateway, wait_for_finalized};

mod common;

/// `Authenticator::init` builds a `rustls::ClientConfig` internally, which
/// requires a globally-installed crypto provider.
fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

const LEAF_OPS: [GatewayRequestKind; 4] = [
    GatewayRequestKind::InsertAuthenticator,
    GatewayRequestKind::UpdateAuthenticator,
    GatewayRequestKind::RemoveAuthenticator,
    GatewayRequestKind::RecoverAccount,
];

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

fn make_config(gw: &TestGateway, indexer_url: &str) -> Config {
    Config::new(
        Some(gw.rpc_url.clone()),
        gw.chain_id,
        gw.registry_addr,
        indexer_url.to_string(),
        gw.base_url.clone(),
        Vec::new(),
        2,
    )
    .unwrap()
}

fn make_inclusion_proof(
    pubkeys: Vec<EdDSAPublicKey>,
    leaf_index: u64,
) -> AccountInclusionProof<{ TREE_DEPTH }> {
    let MerkleFixture {
        key_set,
        inclusion_proof,
        ..
    } = single_leaf_merkle_fixture(pubkeys, leaf_index).unwrap();
    AccountInclusionProof::<{ TREE_DEPTH }>::new(inclusion_proof, key_set)
}

fn derive_keys_from_seed(seed: [u8; 32]) -> (EdDSAPublicKey, Address) {
    let onchain = PrivateKeySigner::from_bytes(&seed.into()).unwrap();
    let offchain = EdDSAPrivateKey::from_bytes(seed);
    (offchain.public(), onchain.address())
}

/// Register a new account and wait for on-chain finalization.
/// Returns an initialized `Authenticator` backed by a `MutableIndexerStub`.
async fn register_and_init(
    gw: &TestGateway,
    seed: [u8; 32],
    recovery_address: Option<Address>,
) -> (Authenticator, MutableIndexerStub) {
    ensure_crypto_provider();
    let config = make_config(gw, "http://127.0.0.1:0");
    let initializing = Authenticator::register(&seed, config.into(), recovery_address)
        .await
        .expect("register failed");
    wait_for_finalized(&gw.client, &gw.base_url, initializing.request_id()).await;

    let (pubkey, _) = derive_keys_from_seed(seed);
    let tmp_config = make_config(gw, "http://127.0.0.1:0");
    let auth = Authenticator::init(&seed, tmp_config.into())
        .await
        .expect("init failed after register");

    let leaf_index = auth.leaf_index();
    let proof = make_inclusion_proof(vec![pubkey], leaf_index);
    let stub = MutableIndexerStub::spawn(leaf_index, proof)
        .await
        .expect("failed to spawn indexer stub");

    let config = make_config(gw, &stub.url);
    let auth = Authenticator::init(&seed, config.into())
        .await
        .expect("init with indexer stub failed");

    (auth, stub)
}

// ---------------------------------------------------------------------------
// Test-local recover helper (Authenticator has no recover_account method)
// ---------------------------------------------------------------------------

/// Sends a recover-account request using state from the `Authenticator` and
/// signing with the provided recovery key. Returns the same result shape as
/// the Authenticator's own leaf-op methods.
async fn send_recover_via_auth(
    auth: &Authenticator,
    recovery_signer: &PrivateKeySigner,
    new_authenticator_address: Address,
    new_authenticator_pubkey: EdDSAPublicKey,
) -> Result<GatewayRequestId, AuthenticatorError> {
    let leaf_index = auth.leaf_index();
    let nonce = auth.signing_nonce().await?;
    let mut key_set = auth.fetch_authenticator_pubkeys().await?;
    let old_commitment: U256 = key_set.leaf_hash().into();
    let encoded_pubkey = new_authenticator_pubkey
        .to_ethereum_representation()
        .map_err(|e| AuthenticatorError::Generic(e.to_string()))?;

    for i in 0..key_set.len() {
        if key_set.get(i).is_some() {
            key_set
                .try_clear_at_index(i)
                .map_err(|e| AuthenticatorError::Generic(e.to_string()))?;
        }
    }
    key_set
        .try_push(new_authenticator_pubkey)
        .map_err(|e| AuthenticatorError::Generic(e.to_string()))?;
    let new_commitment: U256 = key_set.leaf_hash().into();

    let eip712_domain = ag_domain(auth.config.chain_id(), *auth.config.registry_address());

    let signature = sign_recover_account(
        recovery_signer,
        leaf_index,
        new_authenticator_address,
        encoded_pubkey,
        new_commitment,
        nonce,
        &eip712_domain,
    )
    .await
    .map_err(|e| AuthenticatorError::Generic(format!("Failed to sign recover account: {e}")))?;

    let req = RecoverAccountRequest {
        leaf_index,
        new_authenticator_address,
        old_offchain_signer_commitment: old_commitment,
        new_offchain_signer_commitment: new_commitment,
        signature,
        nonce,
        new_authenticator_pubkey: Some(encoded_pubkey),
    };

    let http = reqwest::Client::new();
    let resp = http
        .post(format!("{}/recover-account", auth.config.gateway_url()))
        .json(&req)
        .send()
        .await?;

    let status = resp.status();
    if status.is_success() {
        let body: GatewayStatusResponse = resp.json().await?;
        Ok(body.request_id)
    } else {
        let body_text = resp.text().await.unwrap_or_default();
        Err(AuthenticatorError::GatewayError {
            status,
            body: body_text,
        })
    }
}

// ---------------------------------------------------------------------------
// Dispatch a leaf operation via the Authenticator (or recover helper)
// ---------------------------------------------------------------------------

async fn dispatch_op(
    auth: &mut Authenticator,
    op: GatewayRequestKind,
    aux_seed: [u8; 32],
    recovery_signer: &PrivateKeySigner,
) -> Result<GatewayRequestId, AuthenticatorError> {
    let (aux_pubkey, aux_addr) = derive_keys_from_seed(aux_seed);
    match op {
        GatewayRequestKind::InsertAuthenticator => {
            auth.insert_authenticator(aux_pubkey, aux_addr).await
        }
        GatewayRequestKind::UpdateAuthenticator => {
            let own_addr = auth.onchain_address();
            auth.update_authenticator(own_addr, aux_addr, aux_pubkey, 0)
                .await
        }
        GatewayRequestKind::RemoveAuthenticator => {
            let own_addr = auth.onchain_address();
            auth.remove_authenticator(own_addr, 0).await
        }
        GatewayRequestKind::RecoverAccount => {
            send_recover_via_auth(auth, recovery_signer, aux_addr, aux_pubkey).await
        }
        other => panic!("dispatch_op called with unexpected kind: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Redis helpers
// ---------------------------------------------------------------------------

async fn redis_key_exists(gw: &TestGateway, key: &str) -> bool {
    let client = redis::Client::open(gw.redis_url.as_str()).expect("redis open");
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("redis async connect");
    redis::cmd("EXISTS")
        .arg(key)
        .query_async(&mut conn)
        .await
        .expect("redis EXISTS")
}

// ---------------------------------------------------------------------------
// Assertion helper
// ---------------------------------------------------------------------------

fn assert_duplicate_in_flight(err: AuthenticatorError, ctx: &str) {
    match err {
        AuthenticatorError::GatewayError { status, body } => {
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{ctx}: expected 400, got {status}"
            );
            assert!(
                body.contains("duplicate_request_in_flight"),
                "{ctx}: expected duplicate_request_in_flight, got {body}"
            );
        }
        other => panic!("{ctx}: expected GatewayError, got {other:?}"),
    }
}

// ===========================================================================
// Tests: Redis lock lifecycle
// ===========================================================================

/// After submitting a request (with a long batch window so it stays in-flight),
/// the corresponding Redis lock key must exist.
///
/// - create-account -> `gateway:inflight:create:{addr}`
/// - insert/update/remove/recover -> `gateway:inflight:leaf:{leaf_index}`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_lock_created_on_submit() {
    ensure_crypto_provider();
    let gw = spawn_test_gateway(Some(30_000)).await;

    // -- create-account --
    let seed: [u8; 32] = rand::random();
    let (_, addr) = derive_keys_from_seed(seed);
    let config = make_config(&gw, "http://127.0.0.1:0");
    let _initializing = Authenticator::register(&seed, config.into(), None)
        .await
        .expect("register failed");
    let auth_key = format!("gateway:inflight:create:{addr}");
    assert!(
        redis_key_exists(&gw, &auth_key).await,
        "auth lock key should exist after create-account"
    );

    // -- leaf ops (insert, update, remove, recover) --
    for op in &LEAF_OPS {
        let op_seed: [u8; 32] = rand::random();
        let recovery_signer = PrivateKeySigner::from_bytes(&op_seed.into()).unwrap();

        let (mut auth, _stub) =
            register_and_init(&gw, op_seed, Some(recovery_signer.address())).await;
        let leaf_index = auth.leaf_index();

        let aux_seed: [u8; 32] = rand::random();
        dispatch_op(&mut auth, *op, aux_seed, &recovery_signer)
            .await
            .unwrap_or_else(|e| panic!("{op:?} should be accepted on leaf {leaf_index}: {e}"));

        let leaf_key = format!("gateway:inflight:leaf:{leaf_index}");
        assert!(
            redis_key_exists(&gw, &leaf_key).await,
            "leaf lock key should exist after {op:?} on leaf {leaf_index}",
        );
    }
}

/// For each first-op in {insert, update, remove, recover}, while the first
/// request is in-flight (long batch window), every second-op on the *same*
/// leaf should be rejected with duplicate_request_in_flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_same_leaf_conflict_matrix() {
    ensure_crypto_provider();
    let gw = spawn_test_gateway(Some(30_000)).await;

    for first_op in &LEAF_OPS {
        let op_seed: [u8; 32] = rand::random();
        let recovery_signer = PrivateKeySigner::from_bytes(&op_seed.into()).unwrap();

        let (mut auth, _stub) =
            register_and_init(&gw, op_seed, Some(recovery_signer.address())).await;
        let leaf_index = auth.leaf_index();

        let aux_seed: [u8; 32] = rand::random();
        dispatch_op(&mut auth, *first_op, aux_seed, &recovery_signer)
            .await
            .unwrap_or_else(|e| {
                panic!("first op ({first_op:?}) should be accepted on leaf {leaf_index}: {e}")
            });

        for second_op in &LEAF_OPS {
            let aux2_seed: [u8; 32] = rand::random();
            let result = dispatch_op(&mut auth, *second_op, aux2_seed, &recovery_signer).await;
            let err = result.expect_err(&format!(
                "{first_op:?} then {second_op:?} on leaf {leaf_index}: expected rejection"
            ));
            assert_duplicate_in_flight(
                err,
                &format!("{first_op:?} then {second_op:?} on leaf {leaf_index}"),
            );
        }
    }
}

/// After a request finalizes on-chain, the Redis lock key is removed.
///
/// Tests create-account and all leaf ops (insert, update, remove, recover).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_lock_removed_after_finalization() {
    ensure_crypto_provider();
    let gw = spawn_test_gateway(Some(200)).await;

    // -- create-account --
    let seed: [u8; 32] = rand::random();
    let (_, addr) = derive_keys_from_seed(seed);
    let config = make_config(&gw, "http://127.0.0.1:0");
    let initializing = Authenticator::register(&seed, config.into(), None)
        .await
        .expect("register failed");
    wait_for_finalized(&gw.client, &gw.base_url, initializing.request_id()).await;
    let auth_key = format!("gateway:inflight:create:{addr}");
    assert!(
        !redis_key_exists(&gw, &auth_key).await,
        "auth lock key should be removed atomically on finalization"
    );

    // -- leaf ops (insert, update, remove, recover) --
    for op in &LEAF_OPS {
        let op_seed: [u8; 32] = rand::random();
        let recovery_signer = PrivateKeySigner::from_bytes(&op_seed.into()).unwrap();

        let (mut auth, stub) =
            register_and_init(&gw, op_seed, Some(recovery_signer.address())).await;
        let leaf_index = auth.leaf_index();

        let aux_seed: [u8; 32] = rand::random();
        let req_id = dispatch_op(&mut auth, *op, aux_seed, &recovery_signer)
            .await
            .unwrap_or_else(|e| panic!("{op:?} should be accepted on leaf {leaf_index}: {e}"));

        wait_for_finalized(&gw.client, &gw.base_url, &req_id).await;
        let leaf_key = format!("gateway:inflight:leaf:{leaf_index}");
        assert!(
            !redis_key_exists(&gw, &leaf_key).await,
            "leaf lock key should be removed after {op:?} finalization on leaf {leaf_index}",
        );

        stub.abort();
    }
}
