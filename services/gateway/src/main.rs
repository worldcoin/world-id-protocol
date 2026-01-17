use std::path::Path;

use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".env"); // load env vars in the root of this service
    let _ = dotenvy::from_path(&env_path);

    tracing_subscriber::registry()
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| "world_id_gateway=info,axum=info,tower_http=info".into(),
        )))
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .flatten_event(true)
                .with_current_span(true),
        )
        .init();

    let _ = dotenvy::dotenv();
    tracing::info!("Starting world-id-gateway");
    println!("Starting world-id-gateway");

    world_id_gateway::run().await
}
