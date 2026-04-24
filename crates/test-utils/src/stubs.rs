use std::{num::NonZeroU16, path::PathBuf, sync::Arc, time::Duration};

use alloy::primitives::{Address, U256};
use ark_serialize::CanonicalSerialize;
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use eyre::{Context as _, Result};
use secrecy::SecretString;
use semver::VersionReq;
use taceo_nodes_common::postgres::PostgresConfig;
use taceo_oprf::service::{
    secret_manager::SecretManagerService as NodeSecretManagerService, web3::HttpRpcProviderConfig,
};
use taceo_oprf_key_gen::{
    StartedServices,
    config::OprfKeyGenServiceConfigMandatoryValues,
    secret_manager::{SecretManager, SecretManagerService as KeyGenSecretManagerService},
};
use taceo_oprf_test_utils::{
    OPRF_PEER_ADDRESS_0, OPRF_PEER_ADDRESS_1, OPRF_PEER_ADDRESS_2, OPRF_PEER_ADDRESS_3,
    OPRF_PEER_ADDRESS_4, OPRF_PEER_PRIVATE_KEY_0, OPRF_PEER_PRIVATE_KEY_1, OPRF_PEER_PRIVATE_KEY_2,
    OPRF_PEER_PRIVATE_KEY_3, OPRF_PEER_PRIVATE_KEY_4,
};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use world_id_oprf_node::config::{WorldIdNodeContracts, WorldOprfNodeConfig};
use world_id_primitives::{
    TREE_DEPTH,
    api_types::{IndexerAuthenticatorPubkeysResponse, IndexerQueryRequest},
    merkle::AccountInclusionProof,
};

use std::sync::RwLock;

use crate::anvil::TestAnvil;

#[derive(Clone)]
struct IndexerState {
    leaf_index: u64,
    proof: AccountInclusionProof<{ TREE_DEPTH }>,
}

fn proof_pubkeys_response(
    proof: &AccountInclusionProof<{ TREE_DEPTH }>,
) -> IndexerAuthenticatorPubkeysResponse {
    let authenticator_pubkeys = proof
        .authenticator_pubkeys
        .iter()
        .map(|pubkey| {
            let mut compressed = Vec::new();
            pubkey.as_ref().map(|pubkey| {
                pubkey
                    .pk
                    .serialize_compressed(&mut compressed)
                    .expect("failed to serialize compressed authenticator pubkey");
                U256::from_le_slice(&compressed)
            })
        })
        .collect();

    IndexerAuthenticatorPubkeysResponse {
        authenticator_pubkeys,
        offchain_signer_commitment: U256::ZERO,
    }
}

/// Spawns a minimal HTTP server that serves the provided inclusion proof.
pub async fn spawn_indexer_stub(
    leaf_index: u64,
    proof: AccountInclusionProof<{ TREE_DEPTH }>,
) -> Result<(String, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .wrap_err("failed to bind indexer stub listener")?;
    let addr = listener
        .local_addr()
        .wrap_err("failed to read listener address")?;
    let state = IndexerState { leaf_index, proof };
    let handle = tokio::spawn(async move {
        let app =
            Router::new()
                .route(
                    "/inclusion-proof",
                    post(
                        |State(state): State<IndexerState>,
                         Json(body): Json<IndexerQueryRequest>| async move {
                            if body.leaf_index != state.leaf_index {
                                return Err(StatusCode::NOT_FOUND);
                            }
                            Ok::<_, StatusCode>(Json(state.proof.clone()))
                        },
                    ),
                )
                .route(
                    "/authenticator-pubkeys",
                    post(
                        |State(state): State<IndexerState>,
                         Json(body): Json<IndexerQueryRequest>| async move {
                            if body.leaf_index != state.leaf_index {
                                return Err(StatusCode::NOT_FOUND);
                            }

                            Ok::<_, StatusCode>(Json(proof_pubkeys_response(&state.proof)))
                        },
                    ),
                )
                .with_state(state);
        axum::serve(listener, app)
            .await
            .expect("indexer stub server crashed");
    });

    Ok((format!("http://{addr}"), handle))
}

/// Handle to a mutable indexer stub that allows updating the proof at runtime.
pub struct MutableIndexerStub {
    pub url: String,
    state: Arc<RwLock<IndexerState>>,
    handle: JoinHandle<()>,
}

impl MutableIndexerStub {
    /// Spawns a new mutable indexer stub server.
    pub async fn spawn(
        leaf_index: u64,
        proof: AccountInclusionProof<{ TREE_DEPTH }>,
    ) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .wrap_err("failed to bind indexer stub listener")?;
        let addr = listener
            .local_addr()
            .wrap_err("failed to read listener address")?;

        let state = Arc::new(RwLock::new(IndexerState { leaf_index, proof }));
        let router_state = Arc::clone(&state);

        let handle = tokio::spawn(async move {
            let app = Router::new()
                .route(
                    "/inclusion-proof",
                    post(
                        |State(state): State<Arc<RwLock<IndexerState>>>,
                         Json(body): Json<IndexerQueryRequest>| async move {
                            let guard = state
                                .read()
                                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                            if body.leaf_index != guard.leaf_index {
                                return Err(StatusCode::NOT_FOUND);
                            }
                            Ok::<_, StatusCode>(Json(guard.proof.clone()))
                        },
                    ),
                )
                .route(
                    "/authenticator-pubkeys",
                    post(
                        |State(state): State<Arc<RwLock<IndexerState>>>,
                         Json(body): Json<IndexerQueryRequest>| async move {
                            let guard = state
                                .read()
                                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                            if body.leaf_index != guard.leaf_index {
                                return Err(StatusCode::NOT_FOUND);
                            }
                            Ok::<_, StatusCode>(Json(proof_pubkeys_response(&guard.proof)))
                        },
                    ),
                )
                .with_state(router_state);
            axum::serve(listener, app)
                .await
                .expect("indexer stub server crashed");
        });

        Ok(Self {
            url: format!("http://{addr}"),
            state,
            handle,
        })
    }

    /// Updates the proof served by this stub.
    ///
    /// # Panics
    /// Panics if the lock is poisoned (e.g., due to a panic while holding the lock).
    pub fn set_proof(&self, proof: AccountInclusionProof<{ TREE_DEPTH }>) {
        let mut guard = self
            .state
            .write()
            .expect("RwLock poisoned: failed to acquire write lock for proof update");
        guard.proof = proof;
    }

    /// Aborts the server task.
    pub fn abort(self) {
        self.handle.abort();
    }
}

async fn spawn_orpf_node(
    id: usize,
    anvil: &TestAnvil,
    secret_manager: NodeSecretManagerService,
    oprf_key_registry_contract: Address,
    world_id_registry_contract: Address,
    rp_registry_contract: Address,
    credential_schema_issuer_registry_contract: Address,
) -> String {
    let url = format!("http://localhost:1{id:04}"); // set port based on id, e.g. 10001 for id 1
    let bind_addr = format!("0.0.0.0:1{id:04}");
    let contracts = WorldIdNodeContracts {
        world_id_registry_contract,
        rp_registry_contract,
        credential_schema_issuer_registry_contract,
        oprf_key_registry_contract,
    };
    let anvil_http = anvil
        .endpoint()
        .parse()
        .expect("anvil endpoint should be valid URL");
    let anvil_ws = anvil
        .ws_endpoint()
        .parse()
        .expect("anvil ws_endpoint should be valid URL");
    let config = WorldOprfNodeConfig::with_default_values(
        taceo_oprf::service::Environment::Dev,
        contracts,
        VersionReq::STAR,
        HttpRpcProviderConfig::with_default_values(vec![anvil_http]),
        anvil_ws,
    );

    tokio::spawn(async move {
        let cancellation_token = CancellationToken::new();
        let (router, _tasks) =
            world_id_oprf_node::start(config, secret_manager, cancellation_token.clone())
                .await
                .expect("Can start");
        let listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .expect("Can bind listener");
        let res = axum::serve(listener, router)
            .with_graceful_shutdown(async move { cancellation_token.cancelled().await })
            .await;
        tracing::error!("service failed to start: {res:?}");
    });
    // very graceful timeout for CI
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if reqwest::get(url.clone() + "/health").await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("can start");
    url
}

pub async fn spawn_oprf_nodes(
    anvil: &TestAnvil,
    [
        secret_manager0,
        secret_manager1,
        secret_manager2,
        secret_manager3,
        secret_manager4,
    ]: [NodeSecretManagerService; 5],
    key_gen_contract: Address,
    world_id_registry_contract: Address,
    rp_registry_contract: Address,
    credential_schema_issuer_registry_contract: Address,
) -> [String; 5] {
    tokio::join!(
        spawn_orpf_node(
            0,
            anvil,
            secret_manager0,
            key_gen_contract,
            world_id_registry_contract,
            rp_registry_contract,
            credential_schema_issuer_registry_contract,
        ),
        spawn_orpf_node(
            1,
            anvil,
            secret_manager1,
            key_gen_contract,
            world_id_registry_contract,
            rp_registry_contract,
            credential_schema_issuer_registry_contract,
        ),
        spawn_orpf_node(
            2,
            anvil,
            secret_manager2,
            key_gen_contract,
            world_id_registry_contract,
            rp_registry_contract,
            credential_schema_issuer_registry_contract,
        ),
        spawn_orpf_node(
            3,
            anvil,
            secret_manager3,
            key_gen_contract,
            world_id_registry_contract,
            rp_registry_contract,
            credential_schema_issuer_registry_contract,
        ),
        spawn_orpf_node(
            4,
            anvil,
            secret_manager4,
            key_gen_contract,
            world_id_registry_contract,
            rp_registry_contract,
            credential_schema_issuer_registry_contract,
        ),
    )
    .into()
}

#[allow(clippy::too_many_arguments)]
async fn spawn_key_gen(
    id: usize,
    chain_http_rpc_url: &str,
    chain_ws_rpc_url: &str,
    wallet_private_key: &str,
    secret_manager: KeyGenSecretManagerService,
    oprf_key_registry_contract: Address,
    expected_threshold: NonZeroU16,
    expected_num_peers: NonZeroU16,
) -> String {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bind_addr = format!("0.0.0.0:2{id:04}");
    let url = format!("http://localhost:2{id:04}"); // set port based on id, e.g. 20001 for id 1
    let config = taceo_oprf_key_gen::config::OprfKeyGenServiceConfig::with_default_values(
        OprfKeyGenServiceConfigMandatoryValues {
            environment: taceo_oprf_key_gen::Environment::Dev,
            oprf_key_registry_contract,
            wallet_private_key: SecretString::from(wallet_private_key),
            zkey_path: dir.join("../../circom/OPRFKeyGen.25.arks.zkey"),
            witness_graph_path: dir.join("../../circom/OPRFKeyGenGraph.25.bin"),
            expected_threshold,
            expected_num_peers,
            rpc_provider_config: HttpRpcProviderConfig::with_default_values(vec![
                chain_http_rpc_url.parse().expect("Is a valid URL"),
            ]),
            ws_rpc_url: chain_ws_rpc_url.parse().expect("Is a valid URL"),
        },
    );

    tokio::spawn(async move {
        let cancellation_token = CancellationToken::new();
        let (router, _) = taceo_oprf_key_gen::start(
            config,
            secret_manager,
            StartedServices::new(),
            cancellation_token.clone(),
        )
        .await
        .expect("Can start");
        let listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .expect("Can bind listener");
        let res = axum::serve(listener, router)
            .with_graceful_shutdown(async move { cancellation_token.cancelled().await })
            .await;
        tracing::error!("service failed to start: {res:?}");
    });
    // very graceful timeout for CI
    tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            if reqwest::get(url.clone() + "/health").await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("can start");
    url
}

pub async fn spawn_key_gens(
    chain_http_rpc_url: &str,
    chain_ws_rpc_url: &str,
    [
        secret_manager0,
        secret_manager1,
        secret_manager2,
        secret_manager3,
        secret_manager4,
    ]: [KeyGenSecretManagerService; 5],
    key_gen_contract: Address,
) -> [String; 5] {
    let threshold = NonZeroU16::new(3).expect("3 is non-zero");
    let num_peers = NonZeroU16::new(5).expect("5 is non-zero");
    tokio::join!(
        spawn_key_gen(
            0,
            chain_http_rpc_url,
            chain_ws_rpc_url,
            OPRF_PEER_PRIVATE_KEY_0,
            secret_manager0,
            key_gen_contract,
            threshold,
            num_peers
        ),
        spawn_key_gen(
            1,
            chain_http_rpc_url,
            chain_ws_rpc_url,
            OPRF_PEER_PRIVATE_KEY_1,
            secret_manager1,
            key_gen_contract,
            threshold,
            num_peers
        ),
        spawn_key_gen(
            2,
            chain_http_rpc_url,
            chain_ws_rpc_url,
            OPRF_PEER_PRIVATE_KEY_2,
            secret_manager2,
            key_gen_contract,
            threshold,
            num_peers
        ),
        spawn_key_gen(
            3,
            chain_http_rpc_url,
            chain_ws_rpc_url,
            OPRF_PEER_PRIVATE_KEY_3,
            secret_manager3,
            key_gen_contract,
            threshold,
            num_peers
        ),
        spawn_key_gen(
            4,
            chain_http_rpc_url,
            chain_ws_rpc_url,
            OPRF_PEER_PRIVATE_KEY_4,
            secret_manager4,
            key_gen_contract,
            threshold,
            num_peers
        ),
    )
    .into()
}

pub async fn init_oprf_secret_manager(
    connection_string: &SecretString,
    schema: &'static str,
    address: Address,
) -> eyre::Result<(KeyGenSecretManagerService, NodeSecretManagerService)> {
    let db_config = PostgresConfig::with_default_values(
        connection_string.clone(),
        schema.parse().expect("should be valid config"),
    );
    let key_gen = Arc::new(
        taceo_oprf_key_gen::secret_manager::postgres::PostgresSecretManager::init(&db_config)
            .await?,
    );
    key_gen.store_wallet_address(address.to_string()).await?;
    let node = Arc::new(
        taceo_oprf::service::secret_manager::postgres::PostgresSecretManager::init(&db_config)
            .await?,
    );
    Ok((key_gen, node))
}

pub async fn init_test_secret_managers(
    connection_string: SecretString,
) -> eyre::Result<(
    [taceo_oprf_key_gen::secret_manager::SecretManagerService; 5],
    [taceo_oprf::service::secret_manager::SecretManagerService; 5],
)> {
    let (res0, res1, res2, res3, res4) = tokio::join!(
        init_oprf_secret_manager(&connection_string, "node0", OPRF_PEER_ADDRESS_0),
        init_oprf_secret_manager(&connection_string, "node1", OPRF_PEER_ADDRESS_1),
        init_oprf_secret_manager(&connection_string, "node2", OPRF_PEER_ADDRESS_2),
        init_oprf_secret_manager(&connection_string, "node3", OPRF_PEER_ADDRESS_3),
        init_oprf_secret_manager(&connection_string, "node4", OPRF_PEER_ADDRESS_4),
    );

    // then handle results
    let (key_gen0, node0) = res0?;
    let (key_gen1, node1) = res1?;
    let (key_gen2, node2) = res2?;
    let (key_gen3, node3) = res3?;
    let (key_gen4, node4) = res4?;

    Ok((
        [key_gen0, key_gen1, key_gen2, key_gen3, key_gen4],
        [node0, node1, node2, node3, node4],
    ))
}
