use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "registry_gateway=info,axum=info,tower_http=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let _ = dotenvy::dotenv();
    tracing::info!("Starting registry-gateway");
    println!("Starting registry-gateway");

    registry_gateway::run_from_env().await
}

