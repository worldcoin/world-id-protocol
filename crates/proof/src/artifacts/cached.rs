use std::sync::{Arc, OnceLock};

use crate::{
    OwnershipProver, OwnershipVerifier,
    artifacts::{ZkArtifactError, ZkArtifactSource},
    proof::CircomGroth16Material,
};

/// Caching layer over another [`ZkArtifactSource`].
pub struct CachedZkArtifactSource {
    inner: Arc<dyn ZkArtifactSource>,
    query: OnceLock<Arc<CircomGroth16Material>>,
    nullifier: OnceLock<Arc<CircomGroth16Material>>,
    ownership_prover: OnceLock<OwnershipProver>,
    ownership_verifier: OnceLock<OwnershipVerifier>,
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
            query: OnceLock::new(),
            nullifier: OnceLock::new(),
            ownership_prover: OnceLock::new(),
            ownership_verifier: OnceLock::new(),
        }
    }
}

impl ZkArtifactSource for CachedZkArtifactSource {
    fn query_material(&self) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        if let Some(material) = self.query.get() {
            return Ok(Arc::clone(material));
        }

        let material = self.inner.query_material()?;
        let _ = self.query.set(Arc::clone(&material));
        Ok(self.query.get().map_or(material, Arc::clone))
    }

    fn nullifier_material(&self) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        if let Some(material) = self.nullifier.get() {
            return Ok(Arc::clone(material));
        }

        let material = self.inner.nullifier_material()?;
        let _ = self.nullifier.set(Arc::clone(&material));
        Ok(self.nullifier.get().map_or(material, Arc::clone))
    }

    fn ownership_prover(&self) -> Result<OwnershipProver, ZkArtifactError> {
        if let Some(prover) = self.ownership_prover.get() {
            return Ok(prover.clone());
        }

        let prover = self.inner.ownership_prover()?;
        let _ = self.ownership_prover.set(prover.clone());
        Ok(self.ownership_prover.get().cloned().unwrap_or(prover))
    }

    fn ownership_verifier(&self) -> Result<OwnershipVerifier, ZkArtifactError> {
        if let Some(verifier) = self.ownership_verifier.get() {
            return Ok(verifier.clone());
        }

        let verifier = self.inner.ownership_verifier()?;
        let _ = self.ownership_verifier.set(verifier.clone());
        Ok(self.ownership_verifier.get().cloned().unwrap_or(verifier))
    }
}
