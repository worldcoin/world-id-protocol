use std::env::args;

use chrono::Utc;
use eyre::Result;
use serde_json::json;
use world_id_core::{Credential, EdDSAPrivateKey, HashableCredential};

static ISSUER_SCHEMA_ID: u64 = 1;
static EXPIRATION_TIME: u64 = 3600;

#[tokio::main]
async fn main() -> Result<()> {
    let mut rng = rand::thread_rng();
    let user_id: u64 = args().nth(1).expect("user_id is required").parse::<u64>()?;
    let sk = EdDSAPrivateKey::random(&mut rng);
    let current_timestamp = Utc::now().timestamp() as u64;
    let credential = Credential::new()
        .leaf_index(user_id)
        .issuer_schema_id(ISSUER_SCHEMA_ID)
        .genesis_issued_at(current_timestamp)
        .expires_at(current_timestamp + EXPIRATION_TIME)
        .sign(&sk)?;

    println!("{}", json!(credential));

    Ok(())
}
