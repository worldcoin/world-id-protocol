use std::path::PathBuf;

use alloy::{network::EthereumWallet, providers::ProviderBuilder, sol_types::SolEvent};
use ark_ff::PrimeField;
use eddsa_babyjubjub::EdDSAPrivateKey;
use eyre::{eyre, WrapErr as _};
use oprf_zk::{Groth16Material, NULLIFIER_FINGERPRINT, QUERY_FINGERPRINT};
use rand::thread_rng;
use ruint::aliases::U256;
use test_utils::anvil::{CredentialSchemaIssuerRegistry, TestAnvil};

#[tokio::test]
async fn e2e_nullifier() -> eyre::Result<()> {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../circom");

    let query_zkey = base.join("query.zkey");
    let query_graph = base.join("query_graph.bin");
    let nullifier_zkey = base.join("nullifier.zkey");
    let nullifier_graph = base.join("nullifier_graph.bin");

    assert!(
        query_zkey.exists() && query_graph.exists(),
        "missing query proving material in {:?}",
        base
    );
    assert!(
        nullifier_zkey.exists() && nullifier_graph.exists(),
        "missing nullifier proving material in {:?}",
        base
    );

    let _query_material = Groth16Material::new(&query_zkey, Some(QUERY_FINGERPRINT), &query_graph)
        .wrap_err("failed to load query groth16 material")?;
    let _nullifier_material = Groth16Material::new(
        &nullifier_zkey,
        Some(NULLIFIER_FINGERPRINT),
        &nullifier_graph,
    )
    .wrap_err("failed to load nullifier groth16 material")?;

    let anvil = TestAnvil::spawn().wrap_err("failed to launch anvil")?;
    let signer = anvil
        .signer(0)
        .wrap_err("failed to fetch default anvil signer")?;

    let issuer_registry = anvil
        .deploy_credential_schema_issuer_registry(signer.clone())
        .await
        .wrap_err("failed to deploy credential schema issuer registry proxy")?;
    let account_registry = anvil
        .deploy_account_registry(signer.clone())
        .await
        .wrap_err("failed to deploy account registry proxy")?;

    assert!(
        !issuer_registry.is_zero(),
        "issuer registry proxy address must be non-zero"
    );
    assert!(
        !account_registry.is_zero(),
        "account registry proxy address must be non-zero"
    );

    let mut rng = thread_rng();
    let issuer_sk = EdDSAPrivateKey::random(&mut rng);
    let issuer_pk = issuer_sk.public();

    let issuer_pubkey = CredentialSchemaIssuerRegistry::Pubkey {
        x: U256::from_limbs(issuer_pk.pk.x.into_bigint().0),
        y: U256::from_limbs(issuer_pk.pk.y.into_bigint().0),
    };

    let issuer_signer = signer.clone();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(issuer_signer.clone()))
        .connect_http(
            anvil
                .endpoint()
                .parse()
                .wrap_err("invalid anvil endpoint URL")?,
        );

    let registry_contract = CredentialSchemaIssuerRegistry::new(issuer_registry, provider);

    let receipt = registry_contract
        .register(issuer_pubkey.clone(), issuer_signer.address())
        .send()
        .await
        .wrap_err("failed to send issuer registration transaction")?
        .get_receipt()
        .await
        .wrap_err("failed to fetch issuer registration receipt")?;

    let issuer_schema_id = receipt
        .logs()
        .iter()
        .find_map(|log| {
            CredentialSchemaIssuerRegistry::IssuerSchemaRegistered::decode_log(log.inner.as_ref())
                .ok()
        })
        .ok_or_else(|| eyre!("IssuerSchemaRegistered event not emitted"))?
        .issuerSchemaId;

    let onchain_pubkey = registry_contract
        .issuerSchemaIdToPubkey(issuer_schema_id)
        .call()
        .await
        .wrap_err("failed to fetch issuer pubkey from chain")?;

    assert_eq!(onchain_pubkey.x, issuer_pubkey.x);
    assert_eq!(onchain_pubkey.y, issuer_pubkey.y);

    Ok(())
}
