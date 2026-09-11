//! Compiles the `authenticator-assertion-bench` Noir circuit and embeds its
//! ProveKit prover. Mirrors the artifact rules in `crates/proof/build.rs`.

use std::{env, path::PathBuf, process::Command};

use provekit_common::{NoirProofScheme, Prover};
use provekit_r1cs_compiler::NoirProofSchemeBuilder as _;

/// Must match the pin in `crates/proof/build.rs`, `flake.nix` and provekit.
const REQUIRED_NARGO_VERSION: &str = "1.0.0-beta.11";

const CIRCUIT_DIR: &str = "../proof/noir/authenticator-assertion-bench";
const TARGET_NAME: &str = "authenticator_assertion_bench";

fn main() -> eyre::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let circuit_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?).join(CIRCUIT_DIR);

    println!(
        "cargo:rerun-if-changed={}",
        circuit_dir.join("src").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        circuit_dir.join("Nargo.toml").display()
    );

    check_nargo()?;

    let nargo_output = Command::new("nargo")
        .arg("compile")
        .current_dir(&circuit_dir)
        .output()
        .map_err(|e| eyre::eyre!("failed to run nargo: {e}"))?;
    if !nargo_output.status.success() {
        let stderr = String::from_utf8_lossy(&nargo_output.stderr);
        eyre::bail!("nargo compile failed:\n{stderr}");
    }

    let scheme = NoirProofScheme::from_file(circuit_dir.join(format!("target/{TARGET_NAME}.json")))
        .map_err(|e| eyre::eyre!(e.to_string()))?;
    provekit_common::file::write(
        &Prover::from_noir_proof_scheme(scheme),
        &out_dir.join(format!("{TARGET_NAME}.pkp")),
    )
    .map_err(|e| eyre::eyre!(e.to_string()))?;

    Ok(())
}

/// Fails hard on a missing or wrong-version `nargo`, since a different version
/// produces different proving keys (see `crates/proof/build.rs`).
fn check_nargo() -> eyre::Result<()> {
    let output = Command::new("nargo")
        .arg("--version")
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                eyre::eyre!(
                    "`nargo` was not found on PATH. Install it with `nix develop` or \
                     `noirup --version v{REQUIRED_NARGO_VERSION}`"
                )
            } else {
                eyre::eyre!("failed to run `nargo --version`: {e}")
            }
        })?;

    let version_output = String::from_utf8_lossy(&output.stdout);
    if !version_output.contains(REQUIRED_NARGO_VERSION) {
        eyre::bail!(
            "wrong nargo version: need exactly {REQUIRED_NARGO_VERSION}, `nargo --version` \
             reported:\n{version_output}"
        );
    }
    Ok(())
}
