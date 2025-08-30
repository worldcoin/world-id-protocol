use axum::{extract::Query, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use serde::Deserialize;
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Deserialize)]
struct SumParams {
    a: i64,
    b: i64,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "service_b=info,axum=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app = Router::new()
        .route("/health", get(health))
        .route("/sum", get(sum));

    let port: u16 = std::env::var("SERVICE_B_PORT")
        .or_else(|_| std::env::var("PORT"))
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4000);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tracing::info!(%addr, "service-b listening");

    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))
}

async fn sum(Query(params): Query<SumParams>) -> impl IntoResponse {
    Json(serde_json::json!({
        "a": params.a,
        "b": params.b,
        "sum": params.a + params.b,
        "message": common::greeting("from service-b"),
    }))
}

