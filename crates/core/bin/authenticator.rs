use std::fs::File;

use ark_ff::UniformRand;
use eyre::Result;
use world_id_core::{
    primitives::Config, requests::ProofRequest, Authenticator, Credential, FieldElement,
};

fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{
        fmt::{self},
        EnvFilter,
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
    let json_config = std::fs::read_to_string("config.json").unwrap();
    let config = Config::from_json(&json_config).unwrap();

    let seed = &hex::decode(std::env::var("SEED").expect("SEED is required"))?;
    let authenticator = Authenticator::init_or_create_blocking(seed, config, None).await?;

    let credential_path = std::env::args()
        .nth(1)
        .expect("credential file path is required as first argument");
    let credential: Credential = serde_json::from_reader(File::open(credential_path)?)?;

    let proof_request_path = std::env::args()
        .nth(2)
        .expect("proof request file path is required as second argument");
    let proof_request: ProofRequest =
        ProofRequest::from_json(&std::fs::read_to_string(proof_request_path)?)?;

    let mut rng = rand::thread_rng();
    let message_hash: FieldElement = ark_babyjubjub::Fq::rand(&mut rng).into();

    let (proof, nullifier) = authenticator
        .generate_proof(message_hash, proof_request, credential)
        .await?;

    println!("proof: {proof:?}");
    println!("nullifier: {nullifier:?}");

    Ok(())
}
