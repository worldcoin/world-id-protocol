use std::path::Path;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let env_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".env");
    let _ = dotenvy::from_path(&env_path);

    let _guard = telemetry_batteries::init()?;
    world_id_event_watcher::metrics::describe_metrics();

    tracing::info!("starting world-id-event-watcher");

    let config = world_id_event_watcher::config::AppConfig::load()?;
    world_id_event_watcher::run(config).await
}
