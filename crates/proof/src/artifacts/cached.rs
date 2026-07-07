use std::sync::Arc;

use once_cell::sync::OnceCell;

use crate::{
    OwnershipProver, OwnershipVerifier,
    artifacts::{ZkArtifactError, ZkArtifactSource},
    proof::CircomGroth16Material,
};

/// Caching layer over another [`ZkArtifactSource`].
pub struct CachedZkArtifactSource {
    inner: Arc<dyn ZkArtifactSource>,
    query: OnceCell<Arc<CircomGroth16Material>>,
    nullifier: OnceCell<Arc<CircomGroth16Material>>,
    ownership_prover: OnceCell<OwnershipProver>,
    ownership_verifier: OnceCell<OwnershipVerifier>,
}

impl CachedZkArtifactSource {
    /// Wraps a source in a caching layer.
    #[must_use]
    pub fn new(inner: impl ZkArtifactSource + 'static) -> Self {
        Self::from_arc(Arc::new(inner))
    }

    /// Wraps an already shared source in a caching layer.
    #[must_use]
    pub fn from_arc(inner: Arc<dyn ZkArtifactSource>) -> Self {
        Self {
            inner,
            query: OnceCell::new(),
            nullifier: OnceCell::new(),
            ownership_prover: OnceCell::new(),
            ownership_verifier: OnceCell::new(),
        }
    }
}

impl ZkArtifactSource for CachedZkArtifactSource {
    fn query_material(&self) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        self.query
            .get_or_try_init(|| self.inner.query_material())
            .map(Arc::clone)
    }

    fn nullifier_material(&self) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        self.nullifier
            .get_or_try_init(|| self.inner.nullifier_material())
            .map(Arc::clone)
    }

    fn ownership_prover(&self) -> Result<OwnershipProver, ZkArtifactError> {
        self.ownership_prover
            .get_or_try_init(|| self.inner.ownership_prover())
            .cloned()
    }

    fn ownership_verifier(&self) -> Result<OwnershipVerifier, ZkArtifactError> {
        self.ownership_verifier
            .get_or_try_init(|| self.inner.ownership_verifier())
            .cloned()
    }
}
