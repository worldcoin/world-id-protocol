use std::fs::File;

use backon::{ExponentialBuilder, Retryable};
use eyre::Result;
use world_id_core::{
    primitives::Config, requests::ProofRequest, types::GatewayRequestState, Authenticator,
    AuthenticatorError, Credential,
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
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    install_tracing();
    let json_config = std::fs::read_to_string("config.json").unwrap();
    let config = Config::from_json(&json_config).unwrap();

    let seed = &hex::decode(std::env::var("SEED").expect("SEED is required"))?;
    let authenticator = Authenticator::init(seed, config.clone()).await;

    let authenticator = match authenticator {
        Ok(authenticator) => authenticator,
        Err(err) => {
            if matches!(err, AuthenticatorError::AccountDoesNotExist) {
                let initializing_account =
                    Authenticator::register(seed, config.clone(), None).await?;
                let poller = || async {
                    match initializing_account.poll_status().await {
                        Ok(GatewayRequestState::Finalized { .. }) => Ok(()),
                        _ => Err("not finalized"),
                    }
                };

                poller
                    .retry(ExponentialBuilder::default())
                    .sleep(tokio::time::sleep)
                    .await
                    .map_err(|_| eyre::eyre!("failed to poll for account creation"))?;

                Authenticator::init(seed, config.clone()).await?
            } else {
                return Err(err.into());
            }
        }
    };

    let credential_path = std::env::args()
        .nth(1)
        .expect("credential file path is required as first argument");
    let credential: Credential = serde_json::from_reader(File::open(credential_path)?)?;

    let proof_request_path = std::env::args()
        .nth(2)
        .expect("proof request file path is required as second argument");
    let proof_request: ProofRequest =
        ProofRequest::from_json(&std::fs::read_to_string(proof_request_path)?)?;

    let (proof, nullifier) = authenticator
        .generate_proof(proof_request, credential)
        .await?;

    println!("proof: {proof:?}");
    println!("nullifier: {nullifier:?}");

    Ok(())
}
