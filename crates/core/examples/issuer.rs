use std::env::args;

use chrono::Utc;
use eyre::Result;
use serde_json::json;
use world_id_core::{Credential, EdDSAPrivateKey, FieldElement};

static ISSUER_SCHEMA_ID: u64 = 1;
static EXPIRATION_TIME: u64 = 3600;

#[tokio::main]
async fn main() -> Result<()> {
    let mut rng = rand::thread_rng();
    let leaf_index: u64 = args()
        .nth(1)
        .expect("leaf_index is required")
        .parse::<u64>()?;
    let sk = EdDSAPrivateKey::random(&mut rng);
    let cred_sub_blinding_factor = FieldElement::random(&mut rng);
    let current_timestamp = Utc::now().timestamp() as u64;
    let sub = Credential::compute_sub(leaf_index, cred_sub_blinding_factor);
    let credential = Credential::new()
        .subject(sub)
        .issuer_schema_id(ISSUER_SCHEMA_ID)
        .genesis_issued_at(current_timestamp)
        .expires_at(current_timestamp + EXPIRATION_TIME)
        .sign(&sk)?;

    println!("{}", json!(credential));

    Ok(())
}
