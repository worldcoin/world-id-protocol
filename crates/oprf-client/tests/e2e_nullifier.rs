use std::path::PathBuf;

use eyre::WrapErr as _;
use oprf_zk::{Groth16Material, NULLIFIER_FINGERPRINT, QUERY_FINGERPRINT};

#[test]
fn load_groth16_material() -> eyre::Result<()> {
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

    Groth16Material::new(&query_zkey, Some(QUERY_FINGERPRINT), &query_graph)
        .wrap_err("failed to load query groth16 material")?;
    Groth16Material::new(
        &nullifier_zkey,
        Some(NULLIFIER_FINGERPRINT),
        &nullifier_graph,
    )
    .wrap_err("failed to load nullifier groth16 material")?;

    Ok(())
}

