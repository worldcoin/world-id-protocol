use std::{env, net::SocketAddr};

use axum::{Json, Router, routing::get};
use serde_json::json;

const DEFAULT_HTTP_ADDR: &str = "0.0.0.0:8080";
const HTTP_ADDR_ENV: &str = "HTTP_ADDR";

pub async fn spawn_from_env() -> eyre::Result<SocketAddr> {
    let addr = env::var(HTTP_ADDR_ENV)
        .unwrap_or_else(|_| DEFAULT_HTTP_ADDR.to_owned())
        .parse()?;

    spawn(addr).await?;

    Ok(addr)
}

pub async fn spawn(addr: SocketAddr) -> eyre::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;

    tokio::spawn(async move {
        let app = router();

        if let Err(error) = axum::serve(listener, app).await {
            tracing::error!(?error, "health server exited unexpectedly");
        }
    });

    Ok(())
}

pub fn router() -> Router {
    Router::new().route("/health", get(health))
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}
