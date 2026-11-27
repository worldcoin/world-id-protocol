#![doc = include_str!("../README.md")]

use sha2::{Digest as _, Sha256};
use world_id_primitives::{DomainSeparator, FieldElement, poseidon};

pub mod engine_provider;
pub mod error_code;
pub mod pipeline_type;
pub mod release_manifest;
pub mod request;
mod token;

pub use engine_provider::{EngineProviderMetadata, ReleaseStatus};
pub use error_code::{ENGINE_TIMEOUT, UNLISTED_ERROR, VerifierErrorCode};
pub use pipeline_type::{MAX_TYPE_BYTES, PipelineType, TypeError};
pub use release_manifest::{MAX_PIPELINE_INPUTS, ManifestError, ReleaseManifest, ResponseSlots};
pub use request::{AatInputs, Payload, PayloadCommitments, Request, RequestError};
pub use token::{
    AatFlags, EAT_PROFILE, FlamingoAatClaims, FlamingoClaims, FlamingoToken, TokenError,
};

/// Version of the request map.
pub const REQUEST_VERSION: u64 = 1;
/// Maximum age of an attestation document at verification, in seconds.
pub const MAX_ATTESTATION_AGE: u64 = 10_800;
/// Maximum time from the Verifier's time to a request's `expires_at`, in seconds.
pub const MAX_REQUEST_LIFETIME: u64 = 600;
/// Maximum `debug_report` size, in bytes.
pub const MAX_DEBUG_REPORT: usize = 65_536;
/// Domain of the request channel.
pub const CHANNEL_DOMAIN: &[u8] = b"WORLD-ID/WIP-201/CHANNEL";
/// Domain of the channel key commitment, including the trailing `0x00`.
pub const CHANNEL_KEY_DOMAIN: &[u8] = b"WORLD-ID/WIP-201/CHANNEL-KEY\0";

/// Maximum committed roles of a type, one per `entry_hash_k` claim of a Flamingo Token.
pub const MAX_COMMITTED: usize = 4;
/// Domain of [`pipeline_type`], including the trailing `0x00`.
pub const TYPE_DOMAIN: &[u8] = b"WORLD-ID/WIP-201/TYPE\0";

/// Separates the signed digest of a Flamingo Token, over its 14 claims.
pub const DS_TOKEN: DomainSeparator<14> = DomainSeparator::new(b"WORLD-ID/WIP-201/TOKEN");
/// Separates [`engine_config_hash`].
pub const DS_ENGINE: DomainSeparator<3> = DomainSeparator::new(b"WORLD-ID/WIP-201/ENGINE");

/// `pipeline_type = R(SHA-256(TYPE_DOMAIN || type))`, the hash of a pipeline's type string.
#[must_use]
pub fn pipeline_type(type_string: &str) -> FieldElement {
    let digest = Sha256::new()
        .chain_update(TYPE_DOMAIN)
        .chain_update(type_string)
        .finalize();
    FieldElement::from_digest(&digest.into())
}

/// `engine_config_hash = H_4(DS_ENGINE; R(release_hash), pipeline_id, strictness)`, the value
/// RPs allowlist.
#[must_use]
pub fn engine_config_hash(
    release_hash: &[u8; 32],
    pipeline_id: u16,
    strictness: u8,
) -> FieldElement {
    poseidon::hash(
        DS_ENGINE,
        [
            FieldElement::from_digest(release_hash),
            u64::from(pipeline_id).into(),
            u64::from(strictness).into(),
        ],
    )
}
