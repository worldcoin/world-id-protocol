use std::path::Path;

use world_id_gateway::GatewayResult;

#[tokio::main]
async fn main() -> GatewayResult<()> {
    let env_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".env"); // load env vars in the root of this service
    let _ = dotenvy::from_path(&env_path);
    let _guard = telemetry_batteries::init();

    let _ = dotenvy::dotenv();
    tracing::info!("Starting world-id-gateway");

    if let Err(error) = world_id_gateway::run().await {
        tracing::error!(error = ?error, "gateway terminated with error");
        return Err(error);
    }

    Ok(())
}
