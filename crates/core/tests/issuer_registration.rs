#![cfg(feature = "issuer")]

use eyre::Result;
use taceo_oprf_test_utils::PEER_ADDRESSES;
use test_utils::anvil::{CredentialSchemaIssuerRegistry, TestAnvil};
use world_id_core::Issuer;

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
    anvil
        .register_oprf_nodes(
            oprf_key_registry,
            issuer_signer.clone(),
            PEER_ADDRESSES.to_vec(),
        )
        .await?;

    let issuer_registry_address = anvil
        .deploy_credential_schema_issuer_registry(issuer_signer.clone(), oprf_key_registry)
        .await?;

    // Add CredentialSchemaIssuerRegistry as OprfKeyRegistry admin so it can call initKeyGen
    anvil
        .add_oprf_key_registry_admin(
            oprf_key_registry,
            issuer_signer.clone(),
            issuer_registry_address,
        )
        .await?;

    let mut issuer = Issuer::new(
        issuer_seed_bytes.as_slice(),
        anvil.endpoint().to_string(),
        issuer_registry_address,
    )?;

    let issuer_schema_id = 1u64;
    issuer.register_schema(issuer_schema_id).await?;

    let provider = anvil.provider()?;
    let registry = CredentialSchemaIssuerRegistry::new(issuer_registry_address, provider);

    let signer_address = issuer_signer.address();

    let registered_signer = registry
        .getSignerForIssuerSchemaId(issuer_schema_id)
        .call()
        .await?;
    assert_eq!(registered_signer, signer_address);

    Ok(())
}
