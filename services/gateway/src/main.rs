use std::path::Path;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".env"); // load env vars in the root of this service
    let _ = dotenvy::from_path(&env_path);
    let _guard = telemetry_batteries::init();

    let _ = dotenvy::dotenv();
    tracing::info!("Starting world-id-gateway");
    println!("Starting world-id-gateway");

    world_id_gateway::run().await
}
