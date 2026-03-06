use std::sync::Arc;

use alloy::{
    primitives::{Address, U256},
    signers::local::PrivateKeySigner,
};
use reqwest::{Client, StatusCode};
use world_id_core::{
    Authenticator, AuthenticatorError, EdDSAPrivateKey, EdDSAPublicKey, OnchainKeyRepresentable,
    api_types::{GatewayRequestKind, GatewayStatusResponse, RecoverAccountRequest},
    primitives::{Config, TREE_DEPTH, merkle::AccountInclusionProof},
    proof::CircomGroth16Material,
    world_id_registry::{domain as ag_domain, sign_recover_account},
};
use world_id_gateway::{BatchPolicyConfig, GatewayConfig, SignerArgs, spawn_gateway_for_tests};
use world_id_services_common::ProviderArgs;
use world_id_test_utils::{
    anvil::TestAnvil,
    fixtures::{MerkleFixture, single_leaf_merkle_fixture},
    stubs::MutableIndexerStub,
};

use crate::common::{wait_for_finalized, wait_http_ready};

mod common;

const GW_PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const RPC_FORK_URL: &str = "https://reth-ethereum.ithaca.xyz/rpc";

/// Atomic counter used to assign each test gateway a unique Redis DB index
/// so that concurrent tests don't share in-flight keys.
static REDIS_DB_COUNTER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(1);

/// `Authenticator::init` builds a `rustls::ClientConfig` internally, which
/// requires a globally-installed crypto provider.
fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

// ---------------------------------------------------------------------------
// Test gateway wrapper
// ---------------------------------------------------------------------------

struct TestGateway {
    client: Client,
    base_url: String,
    registry_addr: Address,
    rpc_url: String,
    chain_id: u64,
    redis_url: String,
    _handle: world_id_gateway::GatewayHandle,
    _anvil: TestAnvil,
}

async fn spawn_test_gateway(batch_ms: u64) -> TestGateway {
    let mut fork_url = std::env::var("TESTS_RPC_FORK_URL").unwrap_or_default();
    if fork_url.is_empty() {
        fork_url = RPC_FORK_URL.to_string();
    }
    let anvil = TestAnvil::spawn_fork(&fork_url).expect("failed to spawn forked anvil");
    let deployer = anvil.signer(0).expect("failed to fetch deployer signer");
    let registry_addr = anvil
        .deploy_world_id_registry(deployer)
        .await
        .expect("failed to deploy WorldIDRegistry");
    let rpc_url = anvil.endpoint().to_string();
    let chain_id = anvil.instance.chain_id();

    let signer_args = SignerArgs::from_wallet(GW_PRIVATE_KEY.to_string());

    let max_wait_secs = (batch_ms / 1000).max(1);
    let reeval_ms = batch_ms.min(200);

    let cfg = GatewayConfig {
        registry_addr,
        provider: ProviderArgs {
            http: Some(vec![rpc_url.parse().unwrap()]),
            signer: Some(signer_args),
            ..Default::default()
        },
        batch_policy: BatchPolicyConfig {
            max_wait_secs,
            reeval_ms,
            ..BatchPolicyConfig::default()
        },
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, 0).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
        redis_url: {
            let base =
                std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());
            let db = REDIS_DB_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            format!("{base}/{db}")
        },
        request_timeout_secs: 10,
        rate_limit_window_secs: None,
        rate_limit_max_requests: None,
        sweeper_interval_secs: max_wait_secs + 1,
        stale_queued_threshold_secs: max_wait_secs + 1,
        stale_submitted_threshold_secs: 600,
    };
    {
        let client = redis::Client::open(cfg.redis_url.as_str()).expect("redis open");
        let mut conn = client.get_connection().expect("redis connect");
        redis::cmd("FLUSHDB").exec(&mut conn).expect("FLUSHDB");
    }

    let redis_url = cfg.redis_url.clone();
    let handle = spawn_gateway_for_tests(cfg).await.expect("spawn gateway");

    let addr = handle.listen_addr;
    let base_url = format!("http://{}:{}", addr.ip(), addr.port());

    let client = Client::builder().build().unwrap();
    wait_http_ready(&client, addr.port()).await;

    TestGateway {
        client,
        base_url,
        registry_addr,
        rpc_url,
        chain_id,
        redis_url,
        _handle: handle,
        _anvil: anvil,
    }
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

fn load_embedded_materials() -> (Arc<CircomGroth16Material>, Arc<CircomGroth16Material>) {
    let query = world_id_core::proof::load_embedded_query_material().unwrap();
    let nullifier = world_id_core::proof::load_embedded_nullifier_material().unwrap();
    (Arc::new(query), Arc::new(nullifier))
}

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
    let initializing = Authenticator::register(&seed, config, recovery_address)
        .await
        .expect("register failed");
    wait_for_finalized(&gw.client, &gw.base_url, initializing.request_id()).await;

    let (pubkey, _) = derive_keys_from_seed(seed);
    let (q, n) = load_embedded_materials();
    let tmp_config = make_config(gw, "http://127.0.0.1:0");
    let auth = Authenticator::init(&seed, tmp_config, q.clone(), n.clone())
        .await
        .expect("init failed after register");

    let leaf_index = auth.leaf_index();
    let proof = make_inclusion_proof(vec![pubkey], leaf_index);
    let stub = MutableIndexerStub::spawn(leaf_index, proof)
        .await
        .expect("failed to spawn indexer stub");

    let config = make_config(gw, &stub.url);
    let auth = Authenticator::init(&seed, config, q, n)
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
) -> Result<String, AuthenticatorError> {
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
        signature: signature.as_bytes().to_vec(),
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
) -> Result<String, AuthenticatorError> {
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
    let gw = spawn_test_gateway(30_000).await;

    // -- create-account --
    let seed: [u8; 32] = rand::random();
    let (_, addr) = derive_keys_from_seed(seed);
    let config = make_config(&gw, "http://127.0.0.1:0");
    let _initializing = Authenticator::register(&seed, config, None)
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
    let gw = spawn_test_gateway(30_000).await;

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
    let gw = spawn_test_gateway(200).await;

    // -- create-account --
    let seed: [u8; 32] = rand::random();
    let (_, addr) = derive_keys_from_seed(seed);
    let config = make_config(&gw, "http://127.0.0.1:0");
    let initializing = Authenticator::register(&seed, config, None)
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
