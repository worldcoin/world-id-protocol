use eyre::Result;

fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{
        EnvFilter,
        fmt::{self},
    };

    let fmt_layer = fmt::layer().with_target(false).with_line_number(false);
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    install_tracing();

    let chain_url = std::env::var("CHAIN_URL").unwrap_or("http://localhost:6789".to_string());
    let (rp_id, rp_nullifier_key) = oprf_test::register_rp(&chain_url).await?;

    println!("rp_id: {:?}", rp_id);
    println!("rp_nullifier_key: {:?}", rp_nullifier_key);

    Ok(())
}