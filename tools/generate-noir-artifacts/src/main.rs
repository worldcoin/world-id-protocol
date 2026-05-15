use std::{env, fs, path::Path, process::Command};

use provekit_common::{NoirProofScheme, Prover, Verifier};
use provekit_r1cs_compiler::NoirProofSchemeBuilder as _;

fn main() -> eyre::Result<()> {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| eyre::eyre!("failed to resolve workspace root"))?;

    let circuit_dir = workspace_root.join("crates/proof/noir/ownership-proof");
    let artifact_dir = circuit_dir.join("artifacts");

    let nargo_output = Command::new("nargo")
        .arg("compile")
        .current_dir(&circuit_dir)
        .output()
        .map_err(|e| eyre::eyre!("failed to run nargo: {e}"))?;

    if !nargo_output.status.success() {
        let stderr = String::from_utf8_lossy(&nargo_output.stderr);
        eyre::bail!(
            "nargo compile failed:\n{stderr}\n\nCheck your Noir version - must be run with v1.0.0-beta.11\ninstall with noirup --version v1.0.0-beta.11"
        );
    }

    fs::create_dir_all(&artifact_dir)?;

    let scheme = NoirProofScheme::from_file(circuit_dir.join("target/ownership_proof.json"))
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    provekit_common::file::write(
        &Prover::from_noir_proof_scheme(scheme.clone()),
        &artifact_dir.join("ownership_proof.pkp"),
    )
    .map_err(|e| eyre::eyre!(e.to_string()))?;

    provekit_common::file::write(
        &Verifier::from_noir_proof_scheme(scheme),
        &artifact_dir.join("ownership_proof.pkv"),
    )
    .map_err(|e| eyre::eyre!(e.to_string()))?;

    Ok(())
}
