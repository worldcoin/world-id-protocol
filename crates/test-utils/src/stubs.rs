use std::{path::PathBuf, sync::Arc, time::Duration};

use alloy::primitives::{Address, U256};
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use eyre::{Context as _, Result};
use semver::VersionReq;
use taceo_oprf::service::secret_manager::aws::AwsSecretManager as OprfServiceSercretManager;
use taceo_oprf_key_gen::secret_manager::aws::AwsSecretManager as KeyGenSecretManager;
use taceo_oprf_test_utils::{
    OPRF_PEER_ADDRESS_0, OPRF_PEER_ADDRESS_1, OPRF_PEER_ADDRESS_2, OPRF_PEER_ADDRESS_3,
    OPRF_PEER_ADDRESS_4, PEER_PRIVATE_KEYS,
};
use tokio::{net::TcpListener, task::JoinHandle};
use world_id_oprf_node::config::WorldOprfNodeConfig;
use world_id_primitives::{TREE_DEPTH, merkle::AccountInclusionProof};

use std::sync::RwLock;

#[derive(Clone)]
struct IndexerState {
    leaf_index: u64,
    proof: AccountInclusionProof<{ TREE_DEPTH }>,
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
        let app = Router::new()
            .route(
                "/inclusion-proof",
                post(
                    |State(state): State<IndexerState>, Json(body): Json<serde_json::Value>| async move {
                        let requested_leaf_index = body.get("leaf_index")
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse::<U256>().ok())
                            .ok_or(StatusCode::BAD_REQUEST)?;

                        if requested_leaf_index.as_limbs()[0] != state.leaf_index {
                            return Err(StatusCode::NOT_FOUND);
                        }
                        Ok::<_, StatusCode>(Json(state.proof.clone()))
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
                         Json(body): Json<serde_json::Value>| async move {
                            let requested_leaf_index = body
                                .get("leaf_index")
                                .and_then(|v| v.as_str())
                                .and_then(|s| s.parse::<U256>().ok())
                                .ok_or(StatusCode::BAD_REQUEST)?;

                            let guard = state
                                .read()
                                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                            if requested_leaf_index.as_limbs()[0] != guard.leaf_index {
                                return Err(StatusCode::NOT_FOUND);
                            }
                            Ok::<_, StatusCode>(Json(guard.proof.clone()))
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

#[expect(clippy::too_many_arguments)]
async fn spawn_orpf_node(
    id: usize,
    chain_ws_rpc_url: &str,
    localstack_url: &str,
    oprf_key_registry_contract: Address,
    world_id_registry_contract: Address,
    rp_registry_contract: Address,
    credential_schema_issuer_registry_contract: Address,
    wallet_address: Address,
) -> String {
    let oprf_secret_id_prefix = format!("oprf/rp/n{id}");
    let (_, config) = taceo_oprf_test_utils::localstack_client(localstack_url).await;
    let secret_manager = OprfServiceSercretManager::init(config, &oprf_secret_id_prefix).await;
    let url = format!("http://localhost:1{id:04}"); // set port based on id, e.g. 10001 for id 1
    let config = WorldOprfNodeConfig {
        bind_addr: format!("0.0.0.0:1{id:04}").parse().unwrap(),
        max_wait_time_shutdown: Duration::from_secs(10),
        max_merkle_cache_size: 10,
        max_rp_registry_store_size: 1000,
        max_credential_schema_issuer_registry_store_size: 1000,
        current_time_stamp_max_difference: Duration::from_secs(3 * 60),
        world_id_registry_contract,
        rp_registry_contract,
        credential_schema_issuer_registry_contract,
        cache_maintenance_interval: Duration::from_secs(60),
        node_config: taceo_oprf::service::config::OprfNodeConfig {
            environment: taceo_oprf::service::config::Environment::Dev,
            rp_secret_id_prefix: oprf_secret_id_prefix,
            oprf_key_registry_contract,
            chain_ws_rpc_url: chain_ws_rpc_url.into(),
            ws_max_message_size: 512 * 1024,
            session_lifetime: Duration::from_secs(5 * 60),
            wallet_address,
            get_oprf_key_material_timeout: Duration::from_secs(60),
            start_block: Some(0),
            version_req: VersionReq::STAR,
            region: "test-region".to_string(),
        },
    };
    let never = async { futures::future::pending::<()>().await };

    tokio::spawn(async move {
        let res = world_id_oprf_node::start(config, Arc::new(secret_manager), never).await;
        eprintln!("service failed to start: {res:?}");
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
    chain_ws_rpc_url: &str,
    localstack_url: &str,
    key_gen_contract: Address,
    world_id_registry_contract: Address,
    rp_registry_contract: Address,
    credential_schema_issuer_registry_contract: Address,
) -> [String; 5] {
    tokio::join!(
        spawn_orpf_node(
            0,
            chain_ws_rpc_url,
            localstack_url,
            key_gen_contract,
            world_id_registry_contract,
            rp_registry_contract,
            credential_schema_issuer_registry_contract,
            OPRF_PEER_ADDRESS_0,
        ),
        spawn_orpf_node(
            1,
            chain_ws_rpc_url,
            localstack_url,
            key_gen_contract,
            world_id_registry_contract,
            rp_registry_contract,
            credential_schema_issuer_registry_contract,
            OPRF_PEER_ADDRESS_1,
        ),
        spawn_orpf_node(
            2,
            chain_ws_rpc_url,
            localstack_url,
            key_gen_contract,
            world_id_registry_contract,
            rp_registry_contract,
            credential_schema_issuer_registry_contract,
            OPRF_PEER_ADDRESS_2,
        ),
        spawn_orpf_node(
            3,
            chain_ws_rpc_url,
            localstack_url,
            key_gen_contract,
            world_id_registry_contract,
            rp_registry_contract,
            credential_schema_issuer_registry_contract,
            OPRF_PEER_ADDRESS_3,
        ),
        spawn_orpf_node(
            4,
            chain_ws_rpc_url,
            localstack_url,
            key_gen_contract,
            world_id_registry_contract,
            rp_registry_contract,
            credential_schema_issuer_registry_contract,
            OPRF_PEER_ADDRESS_4,
        ),
    )
    .into()
}

async fn spawn_key_gen(
    id: usize,
    chain_ws_rpc_url: &str,
    localstack_url: &str,
    rp_registry_contract: Address,
) -> String {
    let oprf_secret_id_prefix = format!("oprf/rp/n{id}");
    let wallet_private_key_secret_id = format!("wallet/privatekey/n{id}");
    let (client, config) = taceo_oprf_test_utils::localstack_client(localstack_url).await;
    client
        .create_secret()
        .name(wallet_private_key_secret_id.clone())
        .secret_string(PEER_PRIVATE_KEYS[id])
        .send()
        .await
        .expect("can create wallet secret");
    let secret_manager = KeyGenSecretManager::init(
        config,
        &oprf_secret_id_prefix,
        &wallet_private_key_secret_id,
    )
    .await;
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let url = format!("http://localhost:2{id:04}"); // set port based on id, e.g. 20001 for id 1
    let config = taceo_oprf_key_gen::config::OprfKeyGenConfig {
        environment: taceo_oprf_key_gen::config::Environment::Dev,
        bind_addr: format!("0.0.0.0:2{id:04}").parse().unwrap(),
        oprf_key_registry_contract: rp_registry_contract,
        chain_ws_rpc_url: chain_ws_rpc_url.into(),
        rp_secret_id_prefix: oprf_secret_id_prefix,
        wallet_private_key_secret_id,
        key_gen_zkey_path: dir.join("../../circom/OPRFKeyGen.25.arks.zkey"),
        key_gen_witness_graph_path: dir.join("../../circom/OPRFKeyGenGraph.25.bin"),
        max_wait_time_shutdown: Duration::from_secs(10),
        start_block: Some(0),
        max_transaction_attempts: 3,
        max_wait_time_transaction_confirmation: Duration::from_secs(60),
        max_gas_per_transaction: 8000000,
        confirmations_for_transaction: 1, // must be 1 for anvil
        db_connection_string: "not-used-yet".into(),
    };
    let never = async { futures::future::pending::<()>().await };
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(config.bind_addr)
            .await
            .expect("failed to bind key-gen listener");
        let res =
            taceo_oprf_key_gen::start(config, Arc::new(secret_manager), listener, never).await;
        eprintln!("key-gen failed to start: {res:?}");
    });
    url
}

pub async fn spawn_key_gens(
    chain_ws_rpc_url: &str,
    localstack_url: &str,
    key_gen_contract: Address,
) -> [String; 5] {
    tokio::join!(
        spawn_key_gen(0, chain_ws_rpc_url, localstack_url, key_gen_contract),
        spawn_key_gen(1, chain_ws_rpc_url, localstack_url, key_gen_contract),
        spawn_key_gen(2, chain_ws_rpc_url, localstack_url, key_gen_contract),
        spawn_key_gen(3, chain_ws_rpc_url, localstack_url, key_gen_contract),
        spawn_key_gen(4, chain_ws_rpc_url, localstack_url, key_gen_contract),
    )
    .into()
}
