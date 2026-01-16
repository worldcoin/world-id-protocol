#![cfg(feature = "issuer")]

use alloy::primitives::U256;
use eyre::Result;
use test_utils::anvil::{CredentialSchemaIssuerRegistry, TestAnvil};
use world_id_core::Issuer;
use world_id_primitives::Config;

/// Complete test for registering an issuer schema
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_register_issuer_schema() -> Result<()> {
    let anvil = TestAnvil::spawn()?;

    let issuer_signer = anvil.signer(0)?;
    let issuer_seed_bytes: [u8; 32] = issuer_signer.to_bytes().into();

    let oprf_key_registry = anvil
        .deploy_oprf_key_registry(issuer_signer.clone())
        .await?;

    // Register OPRF nodes (required before initKeyGen can be called)
    let oprf_node_signers = [anvil.signer(5)?, anvil.signer(6)?, anvil.signer(7)?];
    anvil
        .register_oprf_nodes(
            oprf_key_registry,
            issuer_signer.clone(),
            oprf_node_signers.iter().map(|s| s.address()).collect(),
        )
        .await?;

    let registry_address = anvil
        .deploy_credential_schema_issuer_registry(issuer_signer.clone(), oprf_key_registry)
        .await?;

    // Add CredentialSchemaIssuerRegistry as OprfKeyRegistry admin so it can call initKeyGen
    anvil
        .add_oprf_key_registry_admin(oprf_key_registry, issuer_signer.clone(), registry_address)
        .await?;

    let mut issuer = Issuer::new(
        issuer_seed_bytes.as_slice(),
        Config::new(
            Some(anvil.endpoint().to_string()),
            anvil.instance.chain_id(),
            registry_address,
            "http://127.0.0.1:0".to_string(),
            "http://127.0.0.1:0".to_string(),
            Vec::new(),
            2,
        )?,
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
