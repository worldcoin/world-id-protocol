#![doc = include_str!("../README.md")]

use sha2::{Digest as _, Sha256};
use world_id_primitives::{
    DomainSeparator, FieldElement,
    cbor::{self, Value},
    poseidon,
};

pub mod engine_provider;
pub mod release_manifest;
pub mod request;
mod token;

pub use engine_provider::{EngineProviderMetadata, ReleaseStatus};
pub use release_manifest::{ManifestError, ReleaseManifest, ResponseSlots};
pub use request::{AatInputs, Compared, Entry, Payload, Request, RequestError};
pub use token::{
    EAT_PROFILE, FlamingoAatClaims, FlamingoClaims, FlamingoToken, MAX_COMPARED, TokenError,
};

/// Version of the request map.
pub const REQUEST_VERSION: u64 = 1;
/// Captures plus references per request.
pub const MAX_ENTRIES: usize = 8;
/// Maximum size of the request-level `hints`, in bytes.
pub const MAX_HINTS_BYTES: usize = 1024;
/// Maximum size of one entry's `meta`, in bytes.
pub const MAX_ENTRY_META_BYTES: usize = 256;
/// Maximum age of an attestation document at verification, in seconds.
pub const MAX_ATTESTATION_AGE: u64 = 10_800;
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
pub const DS_ENGINE: DomainSeparator<4> = DomainSeparator::new(b"WORLD-ID/WIP-201/ENGINE");

/// The role of each compared position: a capture's `role`, or `None` for a reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout(pub Vec<Option<String>>);

impl Layout {
    /// `R(SHA-256(layout))` over the deterministic CBOR array of roles and `null`s.
    #[must_use]
    pub fn hash(&self) -> FieldElement {
        let array = Value::Array(
            self.0
                .iter()
                .map(|role| {
                    role.as_ref()
                        .map_or(Value::Null, |r| Value::Text(r.clone()))
                })
                .collect(),
        );
        FieldElement::from_digest(&Sha256::digest(cbor::encode(&array)).into())
    }
}

/// `engine_config_hash = H_8(DS_ENGINE; R(release_hash), pipeline, match_strictness,
/// R(SHA-256(layout)))`, the value RPs allowlist.
#[must_use]
pub fn engine_config_hash(
    release_hash: &[u8; 32],
    pipeline: u16,
    match_strictness: u8,
    layout: &Layout,
) -> FieldElement {
    poseidon::hash(
        DS_ENGINE,
        [
            FieldElement::from_digest(release_hash),
            u64::from(pipeline).into(),
            u64::from(match_strictness).into(),
            layout.hash(),
        ],
    )
}
