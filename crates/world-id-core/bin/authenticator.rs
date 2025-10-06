use std::{array, fs::File};

use ark_ec::AffineRepr;
use ark_ff::{AdditiveGroup, PrimeField, UniformRand};
use eddsa_babyjubjub::EdDSAPrivateKey;
use eyre::Result;
use oprf_types::{crypto::UserPublicKeyBatch, RpId};
use poseidon2::Poseidon2;
use serde_json::json;
use std::str::FromStr;
use world_id_core::{
    config::Config,
    types::{BaseField, RpRequest},
    Authenticator, Credential,
};

const PK_DS: &[u8] = b"World ID PK";

fn get_pk_ds() -> BaseField {
    BaseField::from_be_bytes_mod_order(PK_DS)
}

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
    let config = Config::from_json("config.json").unwrap();

    let credential_path = std::env::args()
        .nth(1)
        .expect("credential file path is required as first argument");
    let credential: Credential = serde_json::from_reader(File::open(credential_path)?)?;

    let rp_request_path = std::env::args()
        .nth(2)
        .expect("rp request file path is required as second argument");
    let rp_request: RpRequest = serde_json::from_reader(File::open(rp_request_path)?)?;

    let seed = &hex::decode(std::env::var("SEED").expect("SEED is required"))?;
    let mut authenticator = Authenticator::new(seed, config)?;
    let mut rng = rand::thread_rng();

    let message_hash = BaseField::rand(&mut rng);

    let (proof, nullifier) = authenticator
        .generate_proof(message_hash, rp_request, credential)
        .await?;

    println!("proof: {:?}", proof);
    println!("nullifier: {:?}", nullifier);

    Ok(())
}
