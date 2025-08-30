use axum::{extract::Path, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    // Set up logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "service_a=info,axum=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Build router
    let app = Router::new()
        .route("/health", get(health))
        .route("/hello/:name", get(hello));

    // Pick port from env or default
    let port: u16 = std::env::var("SERVICE_A_PORT")
        .or_else(|_| std::env::var("PORT"))
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tracing::info!(%addr, "service-a listening");

    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))
}

async fn hello(Path(name): Path<String>) -> impl IntoResponse {
    let msg = common::greeting(&name);
    Json(serde_json::json!({ "message": msg }))
}

