use std::path::Path;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let env_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".env");
    let _ = dotenvy::from_path(&env_path);

    let _guard = telemetry_batteries::init()?;
    contract_monitor::metrics::describe_metrics();

    tracing::info!("starting contract-monitor");

    let health_addr = contract_monitor::health::spawn_from_env().await?;
    tracing::info!(%health_addr, "health server listening");

    let config = contract_monitor::config::AppConfig::load()?;
    contract_monitor::run(config).await
}
