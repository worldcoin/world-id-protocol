use authtree_indexer::GlobalConfig;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();

    tracing_subscriber::registry()
        .with(EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "authtree_indexer=info".into()),
        ))
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .flatten_event(true)
                .with_current_span(true),
        )
        .init();

    tracing::info!("Starting world-id-indexer...");

    let config = GlobalConfig::from_env();
    authtree_indexer::run_indexer(config)
        .await
        .expect("indexer run failed");

    tracing::info!("⚠️ Exiting world-id-indexer...");
}
