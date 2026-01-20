use alloy::providers::DynProvider;
use std::path::Path;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use world_id_indexer::GlobalConfig;

#[tokio::main]
async fn main() {
    let env_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".env"); // load env vars in the root of this service
    let _ = dotenvy::from_path(&env_path);

    tracing_subscriber::registry()
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| "world_id_indexer=info,axum=info,tower_http=info".into(),
        )))
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .flatten_event(true)
                .with_current_span(true),
        )
        .init();

    tracing::info!("Starting world-id-indexer...");

    let config = GlobalConfig::from_env();
    world_id_indexer::run_indexer(config)
        .await
        .expect("indexer run failed");

    tracing::info!("⚠️ Exiting world-id-indexer...");
}
