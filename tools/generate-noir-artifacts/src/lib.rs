use std::{fs, path::PathBuf, process::Command};

use provekit_common::{NoirProofScheme, Prover, Verifier};
use provekit_r1cs_compiler::NoirProofSchemeBuilder as _;

pub const OWNERSHIP_PROOF_PKP: &str = "ownership_proof.pkp";
pub const OWNERSHIP_PROOF_PKV: &str = "ownership_proof.pkv";
const OWNERSHIP_PROOF_JSON: &str = "target/ownership_proof.json";

#[derive(Debug, Clone)]
pub struct OwnershipProofArtifactConfig {
    pub circuit_dir: PathBuf,
    pub artifact_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct OwnershipProofArtifacts {
    pub pkp_path: PathBuf,
    pub pkv_path: PathBuf,
}

pub fn ownership_proof_artifact_config(
    workspace_root: impl Into<PathBuf>,
) -> OwnershipProofArtifactConfig {
    let circuit_dir = workspace_root
        .into()
        .join("crates/proof/noir/ownership-proof");
    let artifact_dir = circuit_dir.join("artifacts");

    OwnershipProofArtifactConfig {
        circuit_dir,
        artifact_dir,
    }
}

pub fn generate_ownership_proof_artifacts(
    config: &OwnershipProofArtifactConfig,
) -> eyre::Result<OwnershipProofArtifacts> {
    let nargo_output = Command::new("nargo")
        .arg("compile")
        .current_dir(&config.circuit_dir)
        .output()
        .map_err(|e| eyre::eyre!("failed to run nargo: {e}"))?;

    if !nargo_output.status.success() {
        let stderr = String::from_utf8_lossy(&nargo_output.stderr);
        eyre::bail!(
            "nargo compile failed:\n{stderr}\n\nCheck your Noir version - must be run with v1.0.0-beta.11\ninstall with noirup --version v1.0.0-beta.11"
        );
    }

    fs::create_dir_all(&config.artifact_dir)?;

    let scheme = NoirProofScheme::from_file(config.circuit_dir.join(OWNERSHIP_PROOF_JSON))
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    let pkp_path = config.artifact_dir.join(OWNERSHIP_PROOF_PKP);
    let pkv_path = config.artifact_dir.join(OWNERSHIP_PROOF_PKV);

    provekit_common::file::write(&Prover::from_noir_proof_scheme(scheme.clone()), &pkp_path)
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    provekit_common::file::write(&Verifier::from_noir_proof_scheme(scheme), &pkv_path)
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    Ok(OwnershipProofArtifacts { pkp_path, pkv_path })
}
