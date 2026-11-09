//! Embedded prover for the WIP-202 `embedding-similarity` circuit, and its committed
//! `Prover.toml`, which the benchmark's typed fixture must encode exactly.

#[cfg(test)]
use provekit_common::{Format, InputMap};
use world_id_proof::artifacts::{ZkArtifactSource as _, embedded::EmbeddedZkArtifacts};

#[cfg(test)]
const PROVER_TOML: &str = include_str!("../../proof/noir/embedding-similarity/Prover.toml");

/// Loads the WIP-202 prover `world-id-proof` embeds.
///
/// # Errors
/// Fails if the embedded bytes cannot be deserialized.
pub fn load_embedded_prover() -> eyre::Result<provekit_common::Prover> {
    Ok(EmbeddedZkArtifacts.embedding_similarity_prover()?)
}

/// Loads the WIP-202 verifier `world-id-proof` embeds.
///
/// # Errors
/// Fails if the embedded bytes cannot be deserialized.
#[cfg(test)]
pub fn load_embedded_verifier() -> eyre::Result<provekit_common::Verifier> {
    Ok(EmbeddedZkArtifacts.embedding_similarity_verifier()?)
}

/// Parses the committed witness against the prover's ABI.
///
/// # Errors
/// Fails if `Prover.toml` does not match the circuit's ABI.
#[cfg(test)]
pub fn inputs(prover: &provekit_common::Prover) -> eyre::Result<InputMap> {
    Format::Toml
        .parse(PROVER_TOML, prover.witness_generator.abi())
        .map_err(|e| eyre::eyre!(e.to_string()))
}

#[cfg(test)]
mod tests {
    use provekit_prover::Prove as _;
    use provekit_verifier::Verify as _;

    use super::{inputs, load_embedded_prover, load_embedded_verifier};

    #[test]
    #[ignore = "expensive: proves the full circuit; run with --release --include-ignored"]
    fn proves_and_verifies() {
        let prover = load_embedded_prover().unwrap();
        let input = inputs(&prover).unwrap();
        let proof = prover.prove(input).unwrap();
        load_embedded_verifier().unwrap().verify(&proof).unwrap();
    }
}
