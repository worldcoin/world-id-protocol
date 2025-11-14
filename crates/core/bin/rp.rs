#![cfg(not(target_arch = "wasm32"))]

use std::time::{Duration, SystemTime};

use alloy::{
    primitives::{address, Address},
    providers::ProviderBuilder,
    signers::k256::{self, ecdsa::signature::SignerMut, SecretKey},
};
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_ff::UniformRand;
use eyre::Result;
use oprf_test::{
    rp_registry_scripts::init_key_gen, EcDsaPubkeyCompressed, RpRegistry, TACEO_ADMIN_PRIVATE_KEY,
};
use oprf_types::crypto::RpNullifierKey;
use serde_json::json;
use world_id_core::types::RpRequest;
use world_id_core::FieldElement;

const DEFAULT_KEY_GEN_CONTRACT_ADDRESS: Address =
    address!("0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9");

#[tokio::main]
async fn main() -> Result<()> {
    let mut rng = rand::thread_rng();
    let chain_url = std::env::var("CHAIN_URL").unwrap_or("ws://localhost:8545".to_string());
    let action_id: FieldElement = ark_babyjubjub::Fq::rand(&mut rng).into();

    let sk = SecretKey::random(&mut rng);

    let rp_pk = EcDsaPubkeyCompressed::try_from(sk.public_key())?;
    let rp_id = init_key_gen(
        &chain_url,
        DEFAULT_KEY_GEN_CONTRACT_ADDRESS,
        rp_pk,
        TACEO_ADMIN_PRIVATE_KEY,
    )?;

    let nonce: FieldElement = ark_babyjubjub::Fq::rand(&mut rand::thread_rng()).into();
    let current_time_stamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system time is after unix epoch")
        .as_secs();

    let mut msg = Vec::new();
    msg.extend(nonce.into_bigint().to_bytes_le());
    msg.extend(current_time_stamp.to_le_bytes());
    let signature = k256::ecdsa::SigningKey::from(sk.clone()).sign(&msg);

    // fetch rp nullifier key
    let provider = ProviderBuilder::new().connect_http(chain_url.parse()?);
    let contract = RpRegistry::new(DEFAULT_KEY_GEN_CONTRACT_ADDRESS, provider.clone());
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    let rp_nullifier_key = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            interval.tick().await;
            let maybe_rp_nullifier_key =
                contract.getRpNullifierKey(rp_id.into_inner()).call().await;
            if let Ok(rp_nullifier_key) = maybe_rp_nullifier_key {
                return eyre::Ok(RpNullifierKey::new(rp_nullifier_key.try_into()?));
            }
        }
    })
    .await??;

    let rp_request = RpRequest {
        rp_id: rp_id.into_inner().to_string(),
        rp_nullifier_key,
        signature,
        current_time_stamp,
        action_id,
        nonce,
    };

    println!("{}", json!(rp_request));

    Ok(())
}
