use std::array;

use ark_ff::{AdditiveGroup, PrimeField, UniformRand};
use eddsa_babyjubjub::EdDSAPrivateKey;
use eyre::Result;
use oprf_client::BaseField;
use oprf_types::RpId;
use poseidon2::Poseidon2;
use world_id_core::{config::Config, Authenticator};

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

    let seed = &hex::decode(std::env::var("SEED").expect("SEED is required"))?;
    let mut authenticator = Authenticator::new(seed, config).await?;
    let mut rng = rand::thread_rng();

    println!("auth pubkey: {:?}", authenticator.onchain_address());

    let poseidon2_16 = Poseidon2::<_, 16, 5>::default();
    let mut input = array::from_fn(|_| BaseField::ZERO);
    input[0] = get_pk_ds();
    input[1] = authenticator.offchain_pubkey().pk.x;
    input[2] = authenticator.offchain_pubkey().pk.y;
    let leaf_hash = poseidon2_16.permutation(&input)[1];
    println!("leaf hash: {:?}", leaf_hash);

    let dummy_rp_sk = EdDSAPrivateKey::from_bytes([0; 32]);
    let nonce = BaseField::rand(&mut rng);
    let action_id = BaseField::rand(&mut rng);
    let message_hash = BaseField::rand(&mut rng);

    let (proof, nullifier) = authenticator
        .generate_proof(
            RpId::new(1),
            action_id,
            message_hash,
            dummy_rp_sk.sign(nonce),
            nonce,
        )
        .await?;

    println!("proof: {:?}", proof);
    println!("nullifier: {:?}", nullifier);

    Ok(())
}
