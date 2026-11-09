//! ZK artifact source abstractions.

use std::sync::Arc;

use crate::{
    EmbeddingSimilarityProver, EmbeddingSimilarityVerifier, OwnershipProver, OwnershipVerifier,
    nullifier_proof::CircomGroth16Material,
};

/// Source of ZK artifacts required by World ID proof generation.
pub trait ZkArtifactSource: Send + Sync {
    /// Loads query proof material.
    ///
    /// # Errors
    /// Returns an error if the material cannot be loaded or verified.
    fn query_material(&self) -> Result<Arc<CircomGroth16Material>, error::ZkArtifactError>;

    /// Loads nullifier proof material.
    ///
    /// # Errors
    /// Returns an error if the material cannot be loaded or verified.
    fn nullifier_material(&self) -> Result<Arc<CircomGroth16Material>, error::ZkArtifactError>;

    /// Loads ownership proof prover material.
    ///
    /// # Errors
    /// Returns an error if the material cannot be loaded or is unavailable on the target platform.
    fn ownership_prover(&self) -> Result<OwnershipProver, error::ZkArtifactError>;

    /// Loads ownership proof verifier material.
    ///
    /// # Errors
    /// Returns an error if the material cannot be loaded or is unavailable on the target platform.
    fn ownership_verifier(&self) -> Result<OwnershipVerifier, error::ZkArtifactError>;

    /// Loads embedding similarity proof prover material.
    ///
    /// # Errors
    /// Returns an error if the material cannot be loaded or is unavailable on the target platform.
    fn embedding_similarity_prover(
        &self,
    ) -> Result<EmbeddingSimilarityProver, error::ZkArtifactError>;

    /// Loads embedding similarity proof verifier material.
    ///
    /// # Errors
    /// Returns an error if the material cannot be loaded or is unavailable on the target platform.
    fn embedding_similarity_verifier(
        &self,
    ) -> Result<EmbeddingSimilarityVerifier, error::ZkArtifactError>;
}

pub mod cached;
pub mod dummy;
#[cfg(any(
    feature = "embed-zkeys",
    feature = "embed-ownership-prover",
    feature = "embed-ownership-verifier",
    feature = "embed-embedding-similarity-prover",
    feature = "embed-embedding-similarity-verifier"
))]
pub mod embedded;
pub mod error;
#[cfg(not(target_arch = "wasm32"))]
pub mod filesystem;

pub use error::{ZkArtifactError, ZkArtifactKind};

/// Extension helpers for [`ZkArtifactSource`].
pub trait ZkArtifactSourceExt: ZkArtifactSource + Sized + 'static {
    /// Wraps this source in a caching layer.
    #[must_use]
    fn cached(self) -> cached::CachedZkArtifactSource {
        cached::CachedZkArtifactSource::new(self)
    }
}

impl<T> ZkArtifactSourceExt for T where T: ZkArtifactSource + Sized + 'static {}
