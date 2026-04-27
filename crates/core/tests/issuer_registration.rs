#![cfg(feature = "issuer")]

use alloy::{primitives::U256, providers::Provider as _};
use eyre::Result;
use taceo_oprf_test_utils::PEER_ADDRESSES;
use world_id_core::Issuer;
use world_id_primitives::Signer;
use world_id_test_utils::anvil::{CredentialSchemaIssuerRegistry, TestAnvil};

/// Complete test for registering an issuer schema
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_register_issuer_schema() -> Result<()> {
    let anvil = TestAnvil::spawn()?;

    let deployer = anvil.signer(0)?;

    let oprf_key_registry = anvil.deploy_oprf_key_registry(deployer.clone()).await?;

    // Register OPRF nodes (required before initKeyGen can be called)
    anvil
        .register_oprf_nodes(oprf_key_registry, deployer.clone(), PEER_ADDRESSES.to_vec())
        .await?;

    let issuer_registry_address = anvil
        .deploy_credential_schema_issuer_registry(deployer.clone(), oprf_key_registry)
        .await?;

    // Add CredentialSchemaIssuerRegistry as OprfKeyRegistry admin so it can call initKeyGen
    anvil
        .add_oprf_key_registry_admin(oprf_key_registry, deployer.clone(), issuer_registry_address)
        .await?;

    // The issuer's on-chain SECP256K1 key is derived from `issuer_seed_bytes` via a
    // domain-separated KDF (see `Signer::from_seed_bytes`), so the resulting on-chain
    // address is **not** equal to any of anvil's pre-funded mnemonic accounts. We
    // therefore pre-fund the derived address with `anvil_setBalance` so the issuer
    // can pay for its own gas when calling `register`.
    let issuer_seed_bytes: [u8; 32] = [42u8; 32];
    let issuer_signer_address =
        Signer::from_seed_bytes(&issuer_seed_bytes)?.onchain_signer_address();

    let provider = anvil.provider()?;
    let one_eth = U256::from(10).pow(U256::from(18));
    let _: () = provider
        .client()
        .request("anvil_setBalance", (issuer_signer_address, one_eth))
        .await?;

    let mut issuer = Issuer::new(
        issuer_seed_bytes.as_slice(),
        anvil.endpoint().to_string(),
        issuer_registry_address,
    )?;

    let issuer_schema_id = 1u64;
    issuer.register_schema(issuer_schema_id).await?;

    let registry = CredentialSchemaIssuerRegistry::new(issuer_registry_address, provider);

    let registered_signer = registry
        .getSignerForIssuerSchemaId(issuer_schema_id)
        .call()
        .await?;
    assert_eq!(registered_signer, issuer_signer_address);

    Ok(())
}
