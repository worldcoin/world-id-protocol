//! UNAUDITED. The embedded ProveKit artifacts of the WIP-202 Proof of Embedding Similarity
//! circuit (`noir/embedding-similarity`), built by `build.rs` like the ownership proof's.

#[cfg(all(feature = "embed-embedding-similarity-prover", not(docsrs)))]
const PKP_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/embedding_similarity.pkp"));

#[cfg(all(feature = "embed-embedding-similarity-prover", docsrs))]
const PKP_BYTES: &[u8] = &[];

#[cfg(all(
    not(target_arch = "wasm32"),
    feature = "embed-embedding-similarity-verifier",
    not(docsrs)
))]
const PKV_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/embedding_similarity.pkv"));

#[cfg(all(
    not(target_arch = "wasm32"),
    feature = "embed-embedding-similarity-verifier",
    docsrs
))]
const PKV_BYTES: &[u8] = &[];

/// Loads the embedded WIP-202 prover.
///
/// # Errors
/// Returns an error if the embedded bytes cannot be deserialized.
#[cfg(feature = "embed-embedding-similarity-prover")]
pub fn embedded_prover() -> eyre::Result<provekit_common::Prover> {
    provekit_common::register_ntt();
    provekit_common::file::deserialize(PKP_BYTES).map_err(|e| eyre::eyre!(e.to_string()))
}

/// Loads the embedded WIP-202 verifier.
///
/// # Errors
/// Returns an error if the embedded bytes cannot be deserialized.
#[cfg(all(
    not(target_arch = "wasm32"),
    feature = "embed-embedding-similarity-verifier"
))]
pub fn embedded_verifier() -> eyre::Result<provekit_common::Verifier> {
    provekit_common::register_ntt();
    provekit_common::file::deserialize(PKV_BYTES).map_err(|e| eyre::eyre!(e.to_string()))
}
