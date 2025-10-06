use std::{env::args, str::FromStr};

use ark_ff::UniformRand;
use eyre::Result;
use oprf_test::sc_mock;
use oprf_types::sc_mock::SignNonceResponse;
use ruint::aliases::U256;
use serde_json::json;
use world_id_core::types::{BaseField, RpRequest};

#[tokio::main]
async fn main() -> Result<()> {
    let mut rng = rand::thread_rng();
    let nonce: U256 = U256::from_str(&args().nth(1).expect("nonce is required"))?;
    let chain_url = std::env::var("CHAIN_URL").unwrap_or("http://localhost:6789".to_string());
    let (rp_id, rp_nullifier_key) = sc_mock::register_rp(&chain_url).await?;
    let action_id = BaseField::rand(&mut rng);

    let SignNonceResponse {
        signature,
        current_time_stamp,
    } = sc_mock::sign_nonce(&chain_url, rp_id, nonce.try_into()?).await?;

    let rp_request = RpRequest {
        rp_id: rp_id.into_inner().to_string(),
        rp_nullifier_key,
        signature,
        current_time_stamp,
        action_id,
        nonce: nonce.try_into()?,
    };

    println!("{}", json!(rp_request));

    Ok(())
}
