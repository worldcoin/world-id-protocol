use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    OwnershipProver, OwnershipVerifier,
    artifacts::{ZkArtifactError, ZkArtifactKind, ZkArtifactSource},
    proof::{
        CircomGroth16Material, load_nullifier_material_from_paths, load_query_material_from_paths,
    },
};

#[cfg(not(target_arch = "wasm32"))]
use crate::ownership_proof::{load_ownership_prover_from_path, load_ownership_verifier_from_path};

/// ZK artifacts loaded from files on disk.
#[derive(Debug, Default, Clone)]
pub struct FileSystemZkArtifacts {
    query_zkey_path: Option<PathBuf>,
    query_graph_path: Option<PathBuf>,
    nullifier_zkey_path: Option<PathBuf>,
    nullifier_graph_path: Option<PathBuf>,
    ownership_prover_path: Option<PathBuf>,
    ownership_verifier_path: Option<PathBuf>,
}

impl FileSystemZkArtifacts {
    /// Creates an empty filesystem artifact source.
    ///
    /// Use the `with_*` methods to configure the artifacts this source supports.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the query proof zkey and witness graph paths.
    #[must_use]
    pub fn with_query_paths(
        mut self,
        zkey_path: impl Into<PathBuf>,
        graph_path: impl Into<PathBuf>,
    ) -> Self {
        self.query_zkey_path = Some(zkey_path.into());
        self.query_graph_path = Some(graph_path.into());
        self
    }

    /// Sets the nullifier proof zkey and witness graph paths.
    #[must_use]
    pub fn with_nullifier_paths(
        mut self,
        zkey_path: impl Into<PathBuf>,
        graph_path: impl Into<PathBuf>,
    ) -> Self {
        self.nullifier_zkey_path = Some(zkey_path.into());
        self.nullifier_graph_path = Some(graph_path.into());
        self
    }

    /// Sets the ownership proof prover and verifier paths.
    #[must_use]
    pub fn with_ownership_paths(
        mut self,
        prover_path: impl Into<PathBuf>,
        verifier_path: impl Into<PathBuf>,
    ) -> Self {
        self.ownership_prover_path = Some(prover_path.into());
        self.ownership_verifier_path = Some(verifier_path.into());
        self
    }

    /// Sets the query proof zkey path.
    #[must_use]
    pub fn with_query_zkey_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.query_zkey_path = Some(path.into());
        self
    }

    /// Sets the query proof witness graph path.
    #[must_use]
    pub fn with_query_graph_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.query_graph_path = Some(path.into());
        self
    }

    /// Sets the nullifier proof zkey path.
    #[must_use]
    pub fn with_nullifier_zkey_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.nullifier_zkey_path = Some(path.into());
        self
    }

    /// Sets the nullifier proof witness graph path.
    #[must_use]
    pub fn with_nullifier_graph_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.nullifier_graph_path = Some(path.into());
        self
    }

    /// Sets the ownership proof prover path.
    #[must_use]
    pub fn with_ownership_prover_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.ownership_prover_path = Some(path.into());
        self
    }

    /// Sets the ownership proof verifier path.
    #[must_use]
    pub fn with_ownership_verifier_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.ownership_verifier_path = Some(path.into());
        self
    }
}

impl ZkArtifactSource for FileSystemZkArtifacts {
    fn query_material(&self) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        let kind = ZkArtifactKind::QueryMaterial;
        load_query_material_from_paths(
            required_path(&self.query_zkey_path, kind, "query zkey path not set")?,
            required_path(
                &self.query_graph_path,
                kind,
                "query witness graph path not set",
            )?,
        )
        .map(Arc::new)
        .map_err(|e| ZkArtifactError::load(kind, e))
    }

    fn nullifier_material(&self) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        let kind = ZkArtifactKind::NullifierMaterial;
        load_nullifier_material_from_paths(
            required_path(
                &self.nullifier_zkey_path,
                kind,
                "nullifier zkey path not set",
            )?,
            required_path(
                &self.nullifier_graph_path,
                kind,
                "nullifier witness graph path not set",
            )?,
        )
        .map(Arc::new)
        .map_err(|e| ZkArtifactError::load(kind, e))
    }

    fn ownership_prover(&self) -> Result<OwnershipProver, ZkArtifactError> {
        let kind = ZkArtifactKind::OwnershipProver;

        #[cfg(not(target_arch = "wasm32"))]
        {
            load_ownership_prover_from_path(required_path(
                &self.ownership_prover_path,
                kind,
                "ownership prover path not set",
            )?)
            .map_err(|e| ZkArtifactError::load(kind, e))
        }

        #[cfg(target_arch = "wasm32")]
        {
            Err(ZkArtifactError::Unavailable {
                kind,
                reason: "not supported on wasm32",
            })
        }
    }

    fn ownership_verifier(&self) -> Result<OwnershipVerifier, ZkArtifactError> {
        let kind = ZkArtifactKind::OwnershipVerifier;

        #[cfg(not(target_arch = "wasm32"))]
        {
            load_ownership_verifier_from_path(required_path(
                &self.ownership_verifier_path,
                kind,
                "ownership verifier path not set",
            )?)
            .map_err(|e| ZkArtifactError::load(kind, e))
        }

        #[cfg(target_arch = "wasm32")]
        {
            Err(ZkArtifactError::Unavailable {
                kind,
                reason: "not supported on wasm32",
            })
        }
    }
}

fn required_path<'a>(
    path: &'a Option<PathBuf>,
    kind: ZkArtifactKind,
    detail: &str,
) -> Result<&'a Path, ZkArtifactError> {
    path.as_deref().ok_or_else(|| ZkArtifactError::NotProvided {
        kind,
        detail: Some(detail.to_owned()),
    })
}
