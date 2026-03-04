use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::oneshot;
use world_id_primitives::{Credential, FieldElement, Signer};

pub struct FauxIssuerConfig {
    pub signing_key: [u8; 32],
    pub issuer_schema_id: u64,
    pub listen_addr: SocketAddr,
}

pub struct FauxIssuerHandle {
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<eyre::Result<()>>,
    pub listen_addr: SocketAddr,
}

impl FauxIssuerHandle {
    pub async fn shutdown(mut self) -> eyre::Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        self.task.await??;
        Ok(())
    }

    /// Wait for the server to finish (blocks until shutdown or error).
    pub async fn join(self) -> eyre::Result<()> {
        self.task.await??;
        Ok(())
    }
}

pub async fn spawn(config: FauxIssuerConfig) -> eyre::Result<FauxIssuerHandle> {
    let signer = Signer::from_seed_bytes(&config.signing_key)?;

    let shared_state = Arc::new(AppState {
        signer,
        issuer_schema_id: config.issuer_schema_id,
    });

    let app = Router::new()
        .route("/issue", post(issue_credential))
        .route("/health", axum::routing::get(health_check))
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    let listen_addr = listener.local_addr()?;

    let (tx, rx) = oneshot::channel::<()>();
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = rx.await;
    });
    let task = tokio::spawn(async move { server.await.map_err(Into::into) });

    tracing::info!("Faux-issuer listening on {listen_addr}");

    Ok(FauxIssuerHandle {
        shutdown: Some(tx),
        task,
        listen_addr,
    })
}

struct AppState {
    signer: Signer,
    issuer_schema_id: u64,
}

#[derive(Debug, Deserialize)]
struct IssueCredentialRequest {
    sub: FieldElement,
    #[serde(default)]
    expires_at: Option<u64>,
}

#[derive(Debug, Serialize)]
struct IssueCredentialResponse {
    credential: Credential,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

async fn issue_credential(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IssueCredentialRequest>,
) -> Result<Json<IssueCredentialResponse>, (StatusCode, Json<ErrorResponse>)> {
    tracing::info!("Issuing credential...");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    let expires_at = req.expires_at.unwrap_or(now + 30 * 24 * 60 * 60);

    let credential = Credential::new()
        .issuer_schema_id(state.issuer_schema_id)
        .genesis_issued_at(now)
        .subject(req.sub)
        .expires_at(expires_at);

    let signed_credential = credential
        .sign(state.signer.offchain_signer_private_key().expose_secret())
        .map_err(|e| {
            tracing::error!("Failed to sign credential: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "signing_issue".to_string(),
                }),
            )
        })?;

    tracing::info!(
        "Successfully issued credential with id: {}",
        signed_credential.id
    );

    Ok(Json(IssueCredentialResponse {
        credential: signed_credential,
    }))
}

async fn health_check() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}
