use std::{env, net::SocketAddr};
use world_id_faux_issuer::{FauxIssuerConfig, spawn};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let signing_key_hex =
        env::var("SIGNING_KEY").expect("SIGNING_KEY must be set in environment");
    let signing_key_bytes = hex::decode(&signing_key_hex).expect("SIGNING_KEY must be valid hex");
    let signing_key: [u8; 32] = signing_key_bytes
        .try_into()
        .expect("SIGNING_KEY must be exactly 32 bytes (64 hex characters)");

    let issuer_schema_id_str =
        env::var("ISSUER_SCHEMA_ID").expect("ISSUER_SCHEMA_ID must be set");
    let issuer_schema_id: u64 = if let Some(hex_str) = issuer_schema_id_str.strip_prefix("0x") {
        u64::from_str_radix(hex_str, 16).expect("ISSUER_SCHEMA_ID must be valid hex after 0x")
    } else {
        issuer_schema_id_str
            .parse()
            .expect("ISSUER_SCHEMA_ID must be a valid u64")
    };

    let listen_addr: SocketAddr = env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:7777".to_string())
        .parse()
        .expect("LISTEN_ADDR must be a valid socket address");

    let handle = spawn(FauxIssuerConfig {
        signing_key,
        issuer_schema_id,
        listen_addr,
    })
    .await?;

    println!("Faux Issuer running on http://{}", handle.listen_addr);

    handle.join().await?;

    Ok(())
}
