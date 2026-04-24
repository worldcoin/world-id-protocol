use std::{sync::Arc, time::Duration};

use alloy::primitives::{Address, U256};
use ark_serialize::CanonicalSerialize;
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use eyre::{Context as _, ContextCompat as _, Result};
use secrecy::SecretString;
use semver::VersionReq;
use taceo_nodes_common::postgres::PostgresConfig;
use taceo_oprf::service::web3::HttpRpcProviderConfig;
use taceo_oprf_test_utils::{
    OPRF_PEER_PRIVATE_KEY_0, OPRF_PEER_PRIVATE_KEY_1, OPRF_PEER_PRIVATE_KEY_2,
    OPRF_PEER_PRIVATE_KEY_3, OPRF_PEER_PRIVATE_KEY_4,
};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::HttpWaitStrategy},
    runners::AsyncRunner,
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
    secret_manager: taceo_oprf::service::secret_manager::SecretManagerService,
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
    ]: [taceo_oprf::service::secret_manager::SecretManagerService; 5],
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

const OPRF_KEY_GEN_IMAGE: &str = "ghcr.io/taceolabs/oprf-service/oprf-key-gen";
const OPRF_KEY_GEN_TAG: &str = "v1.1.0-rc.8";
const OPRF_KEY_GEN_INTERNAL_PORT: u16 = 8080;

pub struct SpawnedKeyGens {
    pub urls: [String; 5],
    _containers: [ContainerAsync<GenericImage>; 5],
}

fn host_internal_url(raw_url: &str) -> Result<String> {
    let mut url =
        reqwest::Url::parse(raw_url).wrap_err_with(|| format!("failed to parse URL: {raw_url}"))?;
    url.set_host(Some("host.testcontainers.internal"))
        .wrap_err_with(|| format!("failed to rewrite host for URL: {raw_url}"))?;
    Ok(url.to_string())
}

fn host_exposed_port(raw_url: &str) -> Result<u16> {
    let url =
        reqwest::Url::parse(raw_url).wrap_err_with(|| format!("failed to parse URL: {raw_url}"))?;
    url.port_or_known_default()
        .wrap_err_with(|| format!("URL missing port: {raw_url}"))
}

#[allow(clippy::too_many_arguments)]
async fn spawn_key_gen_container(
    id: usize,
    chain_http_rpc_url: &str,
    chain_ws_rpc_url: &str,
    postgres_connection_string: &str,
    wallet_private_key: &str,
    schema: &str,
    oprf_key_registry_contract: Address,
) -> Result<(String, ContainerAsync<GenericImage>)> {
    let http_port = host_exposed_port(chain_http_rpc_url)?;
    let ws_port = host_exposed_port(chain_ws_rpc_url)?;
    let postgres_port = host_exposed_port(postgres_connection_string)?;

    let container = GenericImage::new(OPRF_KEY_GEN_IMAGE, OPRF_KEY_GEN_TAG)
        .with_exposed_port(OPRF_KEY_GEN_INTERNAL_PORT.tcp())
        .with_wait_for(WaitFor::Http(Box::new(
            HttpWaitStrategy::new("/health").with_expected_status_code(200_u16),
        )))
        .with_exposed_host_ports([http_port, ws_port, postgres_port])
        .with_env_var("RUST_LOG", "taceo=trace,warn")
        .with_env_var("TACEO_OPRF_KEY_GEN__SERVICE__ENVIRONMENT", "dev")
        .with_env_var(
            "TACEO_OPRF_KEY_GEN__BIND_ADDR",
            format!("0.0.0.0:{OPRF_KEY_GEN_INTERNAL_PORT}"),
        )
        .with_env_var(
            "TACEO_OPRF_KEY_GEN__SERVICE__OPRF_KEY_REGISTRY_CONTRACT",
            oprf_key_registry_contract.to_string(),
        )
        .with_env_var(
            "TACEO_OPRF_KEY_GEN__SERVICE__RPC__HTTP_URLS",
            host_internal_url(chain_http_rpc_url)?,
        )
        .with_env_var(
            "TACEO_OPRF_KEY_GEN__SERVICE__RPC__WS_URL",
            host_internal_url(chain_ws_rpc_url)?,
        )
        .with_env_var(
            "TACEO_OPRF_KEY_GEN__SERVICE__WALLET_PRIVATE_KEY",
            wallet_private_key,
        )
        .with_env_var("TACEO_OPRF_KEY_GEN__SERVICE__EXPECTED_NUM_PEERS", "5")
        .with_env_var("TACEO_OPRF_KEY_GEN__SERVICE__EXPECTED_THRESHOLD", "3")
        .with_env_var(
            "TACEO_OPRF_KEY_GEN__SERVICE__ZKEY_PATH",
            "/app/OPRFKeyGen.25.arks.zkey",
        )
        .with_env_var(
            "TACEO_OPRF_KEY_GEN__SERVICE__WITNESS_GRAPH_PATH",
            "/app/OPRFKeyGenGraph.25.bin",
        )
        .with_env_var(
            "TACEO_OPRF_KEY_GEN__SERVICE__CONFIRMATIONS_FOR_TRANSACTION",
            "1",
        )
        .with_env_var(
            "TACEO_OPRF_KEY_GEN__POSTGRES__CONNECTION_STRING",
            host_internal_url(postgres_connection_string)?,
        )
        .with_env_var("TACEO_OPRF_KEY_GEN__POSTGRES__SCHEMA", schema)
        .start()
        .await
        .wrap_err_with(|| format!("failed to start key-gen container {id}"))?;
    let host_port = container
        .get_host_port_ipv4(OPRF_KEY_GEN_INTERNAL_PORT)
        .await
        .wrap_err_with(|| format!("failed to read mapped host port for key-gen container {id}"))?;

    Ok((format!("http://127.0.0.1:{host_port}"), container))
}

pub async fn spawn_key_gens(
    anvil: &TestAnvil,
    postgres_connection_string: &str,
    key_gen_contract: Address,
) -> Result<SpawnedKeyGens> {
    let (res0, res1, res2, res3, res4) = tokio::join!(
        spawn_key_gen_container(
            0,
            anvil.endpoint(),
            anvil.ws_endpoint(),
            postgres_connection_string,
            OPRF_PEER_PRIVATE_KEY_0,
            "node0",
            key_gen_contract,
        ),
        spawn_key_gen_container(
            1,
            anvil.endpoint(),
            anvil.ws_endpoint(),
            postgres_connection_string,
            OPRF_PEER_PRIVATE_KEY_1,
            "node1",
            key_gen_contract,
        ),
        spawn_key_gen_container(
            2,
            anvil.endpoint(),
            anvil.ws_endpoint(),
            postgres_connection_string,
            OPRF_PEER_PRIVATE_KEY_2,
            "node2",
            key_gen_contract,
        ),
        spawn_key_gen_container(
            3,
            anvil.endpoint(),
            anvil.ws_endpoint(),
            postgres_connection_string,
            OPRF_PEER_PRIVATE_KEY_3,
            "node3",
            key_gen_contract,
        ),
        spawn_key_gen_container(
            4,
            anvil.endpoint(),
            anvil.ws_endpoint(),
            postgres_connection_string,
            OPRF_PEER_PRIVATE_KEY_4,
            "node4",
            key_gen_contract,
        ),
    );

    let (url0, container0) = res0?;
    let (url1, container1) = res1?;
    let (url2, container2) = res2?;
    let (url3, container3) = res3?;
    let (url4, container4) = res4?;

    Ok(SpawnedKeyGens {
        urls: [url0, url1, url2, url3, url4],
        _containers: [container0, container1, container2, container3, container4],
    })
}

pub async fn init_oprf_secret_manager(
    connection_string: &SecretString,
    schema: &'static str,
) -> eyre::Result<taceo_oprf::service::secret_manager::SecretManagerService> {
    let db_config = PostgresConfig::with_default_values(
        connection_string.clone(),
        schema.parse().expect("should be valid config"),
    );
    let node = Arc::new(
        taceo_oprf::service::secret_manager::postgres::PostgresSecretManager::init(&db_config)
            .await?,
    );
    Ok(node)
}

pub async fn init_test_secret_managers(
    connection_string: SecretString,
) -> eyre::Result<[taceo_oprf::service::secret_manager::SecretManagerService; 5]> {
    let (node0, node1, node2, node3, node4) = tokio::join!(
        init_oprf_secret_manager(&connection_string, "node0"),
        init_oprf_secret_manager(&connection_string, "node1"),
        init_oprf_secret_manager(&connection_string, "node2"),
        init_oprf_secret_manager(&connection_string, "node3"),
        init_oprf_secret_manager(&connection_string, "node4"),
    );

    Ok([node0?, node1?, node2?, node3?, node4?])
}
