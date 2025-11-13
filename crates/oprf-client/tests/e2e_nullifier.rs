use std::path::PathBuf;

use eyre::WrapErr as _;
use oprf_zk::{Groth16Material, NULLIFIER_FINGERPRINT, QUERY_FINGERPRINT};
use test_utils::anvil::TestAnvil;

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
        .deploy_account_registry(signer)
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

    Ok(())
}
