use std::sync::Arc;

use crate::{
    OwnershipProver, OwnershipVerifier,
    artifacts::{ZkArtifactError, ZkArtifactKind, ZkArtifactSource},
    proof::CircomGroth16Material,
};

/// ZK artifacts embedded into the binary.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmbeddedZkArtifacts;

impl ZkArtifactSource for EmbeddedZkArtifacts {
    fn query_material(&self) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        #[cfg(feature = "embed-zkeys")]
        {
            crate::proof::load_embedded_query_material()
                .map(Arc::new)
                .map_err(|e| ZkArtifactError::load(ZkArtifactKind::QueryMaterial, e))
        }

        #[cfg(not(feature = "embed-zkeys"))]
        {
            Err(ZkArtifactError::Unavailable {
                kind: ZkArtifactKind::QueryMaterial,
                reason: "enable `embed-zkeys`",
            })
        }
    }

    fn nullifier_material(&self) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        #[cfg(feature = "embed-zkeys")]
        {
            crate::proof::load_embedded_nullifier_material()
                .map(Arc::new)
                .map_err(|e| ZkArtifactError::load(ZkArtifactKind::NullifierMaterial, e))
        }

        #[cfg(not(feature = "embed-zkeys"))]
        {
            Err(ZkArtifactError::Unavailable {
                kind: ZkArtifactKind::NullifierMaterial,
                reason: "enable `embed-zkeys`",
            })
        }
    }

    fn ownership_prover(&self) -> Result<OwnershipProver, ZkArtifactError> {
        #[cfg(all(not(target_arch = "wasm32"), feature = "embed-ownership-prover"))]
        {
            crate::ownership_proof::load_embedded_ownership_prover()
                .map_err(|e| ZkArtifactError::load(ZkArtifactKind::OwnershipProver, e))
        }

        #[cfg(any(target_arch = "wasm32", not(feature = "embed-ownership-prover")))]
        {
            Err(ZkArtifactError::Unavailable {
                kind: ZkArtifactKind::OwnershipProver,
                reason: "enable `embed-ownership-prover` on a native target",
            })
        }
    }

    fn ownership_verifier(&self) -> Result<OwnershipVerifier, ZkArtifactError> {
        #[cfg(all(not(target_arch = "wasm32"), feature = "embed-ownership-verifier"))]
        {
            crate::ownership_proof::load_embedded_ownership_verifier()
                .map_err(|e| ZkArtifactError::load(ZkArtifactKind::OwnershipVerifier, e))
        }

        #[cfg(any(target_arch = "wasm32", not(feature = "embed-ownership-verifier")))]
        {
            Err(ZkArtifactError::Unavailable {
                kind: ZkArtifactKind::OwnershipVerifier,
                reason: "enable `embed-ownership-verifier` on a native target",
            })
        }
    }
}
