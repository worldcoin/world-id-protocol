use std::sync::Arc;

use crate::{
    OwnershipProver, OwnershipVerifier,
    artifacts::{ZkArtifactError, ZkArtifactKind, ZkArtifactSource},
    nullifier_proof::CircomGroth16Material,
};

/// ZK artifact source that intentionally provides no artifacts.
///
/// Useful for tests or code paths that only exercise non-proof operations.
#[derive(Debug, Default, Clone, Copy)]
pub struct DummyZkArtifactSource;

fn not_provided(kind: ZkArtifactKind) -> ZkArtifactError {
    ZkArtifactError::NotProvided {
        kind,
        detail: Some("dummy ZK artifact source".to_owned()),
    }
}

impl ZkArtifactSource for DummyZkArtifactSource {
    fn query_material(&self) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        Err(not_provided(ZkArtifactKind::QueryMaterial))
    }

    fn nullifier_material(&self) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        Err(not_provided(ZkArtifactKind::NullifierMaterial))
    }

    fn ownership_prover(&self) -> Result<OwnershipProver, ZkArtifactError> {
        Err(not_provided(ZkArtifactKind::OwnershipProver))
    }

    fn ownership_verifier(&self) -> Result<OwnershipVerifier, ZkArtifactError> {
        Err(not_provided(ZkArtifactKind::OwnershipVerifier))
    }
}
