#![doc = include_str!("../README.md")]

use world_id_primitives::{DomainSeparator, FieldElement, poseidon};

pub mod engine_provider;
pub mod release_manifest;
pub mod request;
mod token;

pub use engine_provider::{EngineProviderMetadata, ReleaseStatus};
pub use release_manifest::{MAX_PIPELINE_INPUTS, ManifestError, ReleaseManifest, ResponseSlots};
pub use request::{AatInputs, Entry, Payload, Request, RequestError};
pub use token::{
    EAT_PROFILE, FlamingoAatClaims, FlamingoClaims, FlamingoToken, MAX_COMPARED, TokenError,
};

/// Version of the request map.
pub const REQUEST_VERSION: u64 = 1;
/// Maximum size of the request-level `hints`, in bytes.
pub const MAX_HINTS_BYTES: usize = 1024;
/// Maximum size of one entry's `meta`, in bytes.
pub const MAX_ENTRY_META_BYTES: usize = 256;
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

/// Separates the signed digest of a Flamingo Token. The digest runs at `t=16`, so the
/// separator pins 15 inputs.
pub const DS_SIGN: DomainSeparator<15> = DomainSeparator::new(b"WORLD-ID/WIP-201/SIGN");
/// Separates [`engine_config_hash`].
pub const DS_ENGINE: DomainSeparator<3> = DomainSeparator::new(b"WORLD-ID/WIP-201/ENGINE");

/// `engine_config_hash = H_4(DS_ENGINE; R(release_hash), pipeline_id, match_strictness)`, the
/// value RPs allowlist.
#[must_use]
pub fn engine_config_hash(
    release_hash: &[u8; 32],
    pipeline_id: u16,
    match_strictness: u8,
) -> FieldElement {
    poseidon::hash(
        DS_ENGINE,
        [
            FieldElement::from_digest(release_hash),
            u64::from(pipeline_id).into(),
            u64::from(match_strictness).into(),
        ],
    )
}
