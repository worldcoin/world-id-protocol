#![recursion_limit = "256"]

use std::path::Path;

use world_id_gateway::GatewayResult;

use telemetry_batteries::TopLevelResultExt;

#[tokio::main]
async fn main() -> GatewayResult<()> {
    let env_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".env"); // load env vars in the root of this service
    let _ = dotenvy::from_path(&env_path);
    let _guard = telemetry_batteries::init();
    world_id_gateway::metrics::describe_metrics();

    let _ = dotenvy::dotenv();
    tracing::info!("Starting world-id-gateway");

    world_id_gateway::run().await.panic_on_top_level_error();

    Ok(())
}
