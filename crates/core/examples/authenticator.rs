use std::{fs::File, str::FromStr};

use eyre::Result;
use world_id_core::{
    Authenticator, Credential, FieldElement, primitives::Config, requests::ProofRequest,
};

fn install_tracing() {
    use tracing_subscriber::{
        EnvFilter,
        fmt::{self},
        prelude::*,
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
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    install_tracing();
    let json_config = std::fs::read_to_string("config.json").unwrap();
    let config = Config::from_json(&json_config).unwrap();

    let files = world_id_core::proof::load_embedded_circuit_files(Option::<&str>::None)?;
    let query_material = world_id_core::proof::load_query_material_from_bytes(
        &files.query_zkey,
        &files.query_graph,
    )?;
    let nullifier_material = world_id_core::proof::load_nullifier_material_from_bytes(
        &files.nullifier_zkey,
        &files.nullifier_graph,
    )?;

    let seed = &hex::decode(std::env::var("SEED").expect("SEED is required"))?;
    let authenticator = Authenticator::init_or_register(
        seed,
        config.clone(),
        query_material,
        nullifier_material,
        None,
    )
    .await?;

    let credential_path = std::env::args()
        .nth(1)
        .expect("credential file path is required as first argument");
    let credential: Credential = serde_json::from_reader(File::open(credential_path)?)?;

    let proof_request_path = std::env::args()
        .nth(2)
        .expect("proof request file path is required as second argument");
    let proof_request: ProofRequest =
        ProofRequest::from_json(&std::fs::read_to_string(proof_request_path)?)?;

    let cred_sub_blinding_factor = FieldElement::from_str(
        std::env::args()
            .nth(3)
            .expect("credential sub blinding factor is required as third argument")
            .as_str(),
    )?;

    let session_id_r_seed = FieldElement::from_str(
        std::env::args()
            .nth(4)
            .expect("session_id_r_seed is required as fourth argument")
            .as_str(),
    )?;

    let request_item = proof_request
        .find_request_by_issuer_schema_id(credential.issuer_schema_id)
        .expect("the credential is not valid for the ProofRequest");

    let (inclusion_proof, key_set) = authenticator.fetch_inclusion_proof().await?;
    let nullifier = authenticator
        .generate_nullifier(&proof_request, inclusion_proof, key_set)
        .await?;

    let proof_response = authenticator.generate_single_proof(
        nullifier,
        request_item,
        &credential,
        cred_sub_blinding_factor,
        session_id_r_seed,
        None, // Uniqueness Proof
        proof_request.created_at,
    )?;

    println!("response: {proof_response:?}");

    Ok(())
}
