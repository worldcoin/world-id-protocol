#![cfg(feature = "issuer")]

use alloy::primitives::U256;
use eyre::Result;
use test_utils::anvil::{CredentialSchemaIssuerRegistry, TestAnvil};
use world_id_core::config::Config;
use world_id_core::Issuer;

/// Complete test for registering an issuer schema
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_register_issuer_schema() -> Result<()> {
    let anvil = TestAnvil::spawn()?;

    let issuer_signer = anvil.signer(0)?;
    let issuer_seed_bytes: [u8; 32] = issuer_signer.to_bytes().into();

    let registry_address = anvil
        .deploy_credential_schema_issuer_registry(issuer_signer.clone())
        .await?;

    let mut issuer = Issuer::new(
        issuer_seed_bytes.as_slice(),
        Config::new(
            anvil.endpoint().to_string(),
            registry_address,
            "http://127.0.0.1:0".to_string(),
            "http://127.0.0.1:0".to_string(),
            Vec::new(),
        ),
    )?;

    let issuer_schema_id = issuer.register_schema().await?;
    assert_eq!(issuer_schema_id, U256::from(1u64));

    let provider = anvil.provider()?;
    let registry = CredentialSchemaIssuerRegistry::new(registry_address, provider);

    let signer_address = issuer_signer.address();

    let registered_signer = registry
        .getSignerForIssuerSchemaId(issuer_schema_id)
        .call()
        .await?;
    assert_eq!(registered_signer, signer_address);

    let next_id = registry.nextIssuerSchemaId().call().await?;
    assert_eq!(next_id, U256::from(2u64));

    Ok(())
}
