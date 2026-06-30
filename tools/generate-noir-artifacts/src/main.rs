use std::path::Path;

use generate_noir_artifacts::{
    generate_ownership_proof_artifacts, ownership_proof_artifact_config,
};

fn main() -> eyre::Result<()> {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| eyre::eyre!("failed to resolve workspace root"))?;

    let config = ownership_proof_artifact_config(workspace_root);
    generate_ownership_proof_artifacts(&config)?;

    Ok(())
}
