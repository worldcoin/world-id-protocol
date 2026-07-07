//! ZK artifact source abstractions.

use std::sync::Arc;

use crate::{OwnershipProver, OwnershipVerifier, proof::CircomGroth16Material};

pub mod cached;
pub mod dummy;
#[cfg(feature = "embed-zkeys")]
pub mod embedded;
#[cfg(not(target_arch = "wasm32"))]
pub mod filesystem;

/// Identifies one of the ZK artifacts a [`ZkArtifactSource`] can provide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ZkArtifactKind {
    QueryMaterial,
    NullifierMaterial,
    OwnershipProver,
    OwnershipVerifier,
}

impl std::fmt::Display for ZkArtifactKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::QueryMaterial => "query proof material",
            Self::NullifierMaterial => "nullifier proof material",
            Self::OwnershipProver => "ownership prover",
            Self::OwnershipVerifier => "ownership verifier",
        };
        f.write_str(name)
    }
}

/// Error returned by [`ZkArtifactSource`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum ZkArtifactError {
    /// The source is not configured to provide this artifact (e.g. no path was
    /// set on a filesystem source, or a dummy source was used).
    #[error(
        "{kind} is not provided by this ZK artifact source{}",
        fmt_detail(detail)
    )]
    NotProvided {
        kind: ZkArtifactKind,
        /// Optional source-specific hint on how to make the artifact available.
        detail: Option<String>,
    },
    /// The artifact can never be provided on this target/feature combination.
    #[error("{kind} is unavailable: {reason}")]
    Unavailable {
        kind: ZkArtifactKind,
        reason: &'static str,
    },
    /// The artifact exists but its bytes could not be read, parsed, or verified.
    #[error("failed to load {kind}: {message}")]
    Load {
        kind: ZkArtifactKind,
        message: String,
    },
}

impl ZkArtifactError {
    /// The artifact this error refers to.
    #[must_use]
    pub fn kind(&self) -> ZkArtifactKind {
        match self {
            Self::NotProvided { kind, .. }
            | Self::Unavailable { kind, .. }
            | Self::Load { kind, .. } => *kind,
        }
    }

    /// Wraps an underlying load failure, preserving its full error chain in the message.
    pub fn load(kind: ZkArtifactKind, error: impl Into<eyre::Report>) -> Self {
        Self::Load {
            kind,
            message: format!("{:#}", error.into()),
        }
    }
}

fn fmt_detail(detail: &Option<String>) -> String {
    detail
        .as_deref()
        .map(|d| format!(" ({d})"))
        .unwrap_or_default()
}

/// Source of ZK artifacts required by World ID proof generation.
pub trait ZkArtifactSource: Send + Sync {
    /// Loads query proof material.
    ///
    /// # Errors
    /// Returns an error if the material cannot be loaded or verified.
    fn query_material(&self) -> Result<Arc<CircomGroth16Material>, ZkArtifactError>;

    /// Loads nullifier proof material.
    ///
    /// # Errors
    /// Returns an error if the material cannot be loaded or verified.
    fn nullifier_material(&self) -> Result<Arc<CircomGroth16Material>, ZkArtifactError>;

    /// Loads ownership proof prover material.
    ///
    /// # Errors
    /// Returns an error if the material cannot be loaded or is unavailable on the target platform.
    fn ownership_prover(&self) -> Result<OwnershipProver, ZkArtifactError>;

    /// Loads ownership proof verifier material.
    ///
    /// # Errors
    /// Returns an error if the material cannot be loaded or is unavailable on the target platform.
    fn ownership_verifier(&self) -> Result<OwnershipVerifier, ZkArtifactError>;
}

/// Extension helpers for [`ZkArtifactSource`].
pub trait ZkArtifactSourceExt: ZkArtifactSource + Sized + 'static {
    /// Wraps this source in a caching layer.
    #[must_use]
    fn cached(self) -> cached::CachedZkArtifactSource {
        cached::CachedZkArtifactSource::new(self)
    }
}

impl<T> ZkArtifactSourceExt for T where T: ZkArtifactSource + Sized + 'static {}
