use std::time::SystemTime;

use alloy::{
    network::EthereumWallet,
    primitives::{address, Address},
    signers::local::PrivateKeySigner,
};
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_ff::UniformRand;
use eyre::Result;
use oprf_test::key_gen_sc_mock::KeyGenProxy;
use serde_json::json;
use world_id_core::types::RpRequest;
use world_id_core::BaseField;

const DEFAULT_KEY_GEN_CONTRACT_ADDRESS: Address =
    address!("0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9");
const PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

#[tokio::main]
async fn main() -> Result<()> {
    let mut rng = rand::thread_rng();
    let chain_url = std::env::var("CHAIN_URL").unwrap_or("ws://localhost:8545".to_string());
    let action_id = BaseField::rand(&mut rng);

    let wallet = EthereumWallet::from(PRIVATE_KEY.parse::<PrivateKeySigner>()?);
    let mut key_gen_proxy =
        KeyGenProxy::connect(&chain_url, DEFAULT_KEY_GEN_CONTRACT_ADDRESS, wallet).await?;

    let (rp_id, rp_nullifier_key) = key_gen_proxy.init_key_gen().await?;

    let nonce = ark_babyjubjub::Fq::rand(&mut rand::thread_rng());
    let current_time_stamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system time is after unix epoch")
        .as_secs();

    let mut msg = Vec::new();
    msg.extend(nonce.into_bigint().to_bytes_le());
    msg.extend(current_time_stamp.to_le_bytes());
    let signature = key_gen_proxy
        .sign(rp_id, &msg)
        .ok_or_else(|| eyre::eyre!("unknown rp id {rp_id}"))?;

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
