use std::{path::PathBuf, sync::Arc, time::Duration};

use alloy::primitives::Address;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use eyre::{Context as _, Result};
use tokio::{net::TcpListener, task::JoinHandle};
use world_id_oprf_node::config::WorldOprfNodeConfig;
use world_id_primitives::{merkle::AccountInclusionProof, TREE_DEPTH};

use crate::test_secret_manager::TestSecretManager;

#[derive(Clone)]
struct IndexerState {
    account_id: u64,
    proof: AccountInclusionProof<{ TREE_DEPTH }>,
}

/// Spawns a minimal HTTP server that serves the provided inclusion proof.
pub async fn spawn_indexer_stub(
    account_id: u64,
    proof: AccountInclusionProof<{ TREE_DEPTH }>,
) -> Result<(String, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .wrap_err("failed to bind indexer stub listener")?;
    let addr = listener
        .local_addr()
        .wrap_err("failed to read listener address")?;
    let state = IndexerState { account_id, proof };
    let handle = tokio::spawn(async move {
        let app = Router::new()
            .route(
                "/proof/{account_id}",
                get(
                    |Path(requested): Path<u64>, State(state): State<IndexerState>| async move {
                        if requested != state.account_id {
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

async fn spawn_orpf_node(
    id: usize,
    chain_ws_rpc_url: &str,
    secret_manager: TestSecretManager,
    rp_registry_contract: Address,
    account_registry_contract: Address,
) -> String {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let url = format!("http://localhost:1{id:04}"); // set port based on id, e.g. 10001 for id 1
    let config = WorldOprfNodeConfig {
        bind_addr: format!("0.0.0.0:1{id:04}").parse().unwrap(),
        max_wait_time_shutdown: Duration::from_secs(10),
        user_verification_key_path: dir.join("../../circom/OPRFQuery.vk.json"),
        max_merkle_store_size: 10,
        current_time_stamp_max_difference: Duration::from_secs(3 * 60),
        signature_history_cleanup_interval: Duration::from_secs(30),
        account_registry_contract,
        node_config: oprf_service::config::OprfNodeConfig {
            environment: oprf_service::config::Environment::Dev,
            request_lifetime: Duration::from_secs(5 * 60),
            session_cleanup_interval: Duration::from_micros(1000000),
            rp_secret_id_prefix: format!("oprf/rp/n{id}"),
            oprf_key_registry_contract: rp_registry_contract,
            chain_ws_rpc_url: chain_ws_rpc_url.into(),
            key_gen_witness_graph_path: dir.join("../../circom/OPRFKeyGenGraph.13.bin"),
            key_gen_zkey_path: dir.join("../../circom/OPRFKeyGen.13.arks.zkey"),
            wallet_private_key_secret_id: "wallet/privatekey".to_string(),
            ws_max_message_size: 8192,
            session_lifetime: Duration::from_secs(5 * 60),
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
    secret_manager: [TestSecretManager; 3],
    key_gen_contract: Address,
    account_registry_contract: Address,
) -> [String; 3] {
    let [secret_manager0, secret_manager1, secret_manager2] = secret_manager;
    [
        spawn_orpf_node(
            0,
            chain_ws_rpc_url,
            secret_manager0,
            key_gen_contract,
            account_registry_contract,
        )
        .await,
        spawn_orpf_node(
            1,
            chain_ws_rpc_url,
            secret_manager1,
            key_gen_contract,
            account_registry_contract,
        )
        .await,
        spawn_orpf_node(
            2,
            chain_ws_rpc_url,
            secret_manager2,
            key_gen_contract,
            account_registry_contract,
        )
        .await,
    ]
}
