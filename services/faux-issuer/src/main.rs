use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use ruint::aliases::U256;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{env, net::SocketAddr, sync::Arc};
use world_id_primitives::{Credential, FieldElement, Signer};

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Load signing key from environment
    let signing_key_hex = env::var("SIGNING_KEY").expect("SIGNING_KEY must be set in environment");
    let signing_key_bytes = hex::decode(&signing_key_hex).expect("SIGNING_KEY must be valid hex");
    if signing_key_bytes.len() != 32 {
        panic!("SIGNING_KEY must be exactly 32 bytes (64 hex characters)");
    }
    let signer = Signer::from_seed_bytes(&signing_key_bytes).expect("Failed to create signer");

    // Load default issuer schema ID from environment
    let issuer_schema_id = env::var("ISSUER_SCHEMA_ID").expect("ISSUER_SCHEMA_ID must be set");
    let issuer_schema_id: u64 = if let Some(hex_str) = issuer_schema_id.strip_prefix("0x") {
        u64::from_str_radix(hex_str, 16).expect("ISSUER_SCHEMA_ID must be valid hex after 0x")
    } else {
        issuer_schema_id
            .parse()
            .expect("ISSUER_SCHEMA_ID must be a valid u64")
    };

    let shared_state = Arc::new(AppState {
        signer,
        issuer_schema_id,
    });

    // Build the router
    let app = Router::new()
        .route("/issue", post(issue_credential))
        .route("/health", axum::routing::get(health_check))
        .with_state(shared_state);

    // Start the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 7777));
    tracing::info!("Starting faux-issuer on {}", addr);
    println!("🚀 Faux Issuer running on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app)
        .await
        .expect("Failed to start server");
}

struct AppState {
    signer: Signer,
    issuer_schema_id: u64,
}

#[derive(Debug, Deserialize)]
struct IssueCredentialRequest {
    /// The blinded subject (as a hex string)
    sub: U256,
    /// Optional expiration timestamp (unix seconds)
    /// Defaults to 1 year from now
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

    let sub = FieldElement::try_from(req.sub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_field_element".to_string(),
            }),
        )
    })?;

    // Calculate expiration (default to 1 month from now)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    let expires_at = req.expires_at.unwrap_or(now + 30 * 24 * 60 * 60);

    // Create and sign the credential
    let credential = Credential::new()
        .issuer_schema_id(state.issuer_schema_id)
        .genesis_issued_at(now)
        .subject(sub)
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
