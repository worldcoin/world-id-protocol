use std::sync::Arc;

use crate::{
    OwnershipProver, OwnershipVerifier,
    artifacts::{ZkArtifactError, ZkArtifactKind, ZkArtifactSource},
    proof::{
        CircomGroth16Material, load_embedded_nullifier_material, load_embedded_query_material,
    },
};

/// ZK artifacts embedded into the binary.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmbeddedZkArtifacts;

impl ZkArtifactSource for EmbeddedZkArtifacts {
    fn query_material(&self) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        load_embedded_query_material()
            .map(Arc::new)
            .map_err(|e| ZkArtifactError::load(ZkArtifactKind::QueryMaterial, e))
    }

    fn nullifier_material(&self) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        load_embedded_nullifier_material()
            .map(Arc::new)
            .map_err(|e| ZkArtifactError::load(ZkArtifactKind::NullifierMaterial, e))
    }

    fn ownership_prover(&self) -> Result<OwnershipProver, ZkArtifactError> {
        // NOTE: Relying on wasm32 as a gate might seem weird here
        //       but it's because the relevant code from provekit that allows
        //       deserializing ProveKit artifacts has io/fs dependencies (and some C-based
        //       libraries) - once that's resolved we should only rely on the embed-noir-artifacts
        //       feature gate only

        #[cfg(all(not(target_arch = "wasm32"), feature = "embed-noir-artifacts"))]
        {
            crate::ownership_proof::load_embedded_ownership_prover()
                .map_err(|e| ZkArtifactError::load(ZkArtifactKind::OwnershipProver, e))
        }

        #[cfg(any(target_arch = "wasm32", not(feature = "embed-noir-artifacts")))]
        {
            Err(ZkArtifactError::Unavailable {
                kind: ZkArtifactKind::OwnershipProver,
                reason: "enable `embed-noir-artifacts` on a native target",
            })
        }
    }

    fn ownership_verifier(&self) -> Result<OwnershipVerifier, ZkArtifactError> {
        // NOTE: Relying on wasm32 as a gate might seem weird here
        //       but it's because the relevant code from provekit that allows
        //       deserializing ProveKit artifacts has io/fs dependencies (and some C-based
        //       libraries) - once that's resolved we should only rely on the embed-noir-artifacts
        //       feature gate only

        #[cfg(all(not(target_arch = "wasm32"), feature = "embed-noir-artifacts"))]
        {
            crate::ownership_proof::load_embedded_ownership_verifier()
                .map_err(|e| ZkArtifactError::load(ZkArtifactKind::OwnershipVerifier, e))
        }

        #[cfg(any(target_arch = "wasm32", not(feature = "embed-noir-artifacts")))]
        {
            Err(ZkArtifactError::Unavailable {
                kind: ZkArtifactKind::OwnershipVerifier,
                reason: "enable `embed-noir-artifacts` on a native target",
            })
        }
    }
}
