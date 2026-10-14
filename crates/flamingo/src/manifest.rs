//! Engine release manifests, Engine Provider metadata (WIP-201 §3.5.2) and response slots
//! (§3.5.4).

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    EncodedPoint,
    ecdsa::{Signature, VerifyingKey, signature::Verifier as _},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// The JWS `typ` of a release manifest.
pub const MANIFEST_TYP: &str = "world-id-engine-manifest";
/// Path of the Engine Provider metadata file.
pub const METADATA_PATH: &str = "/.well-known/world-id-engine.json";

/// Why a release manifest or metadata file was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    /// Not a compact JWS with the required header, or not the specified JSON.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// A field breaks a rule of WIP-201 §3.5.2.
    #[error("invalid {0}")]
    Invalid(&'static str),
    /// The signature does not verify under the given key.
    #[error("invalid manifest signature")]
    SignatureInvalid,
}

/// A release manifest: a compact JWS signed with `ES256` by an Engine Provider's release key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseManifest {
    compact: String,
    kid: String,
    payload_bytes: Vec<u8>,
    payload: ManifestPayload,
}

/// The JWS Payload of a release manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestPayload {
    /// `SHA-256` of the Engine bundle, lowercase hex.
    pub engine_hash: String,
    /// The Engine Provider's label for the release, for people and logs.
    pub version: String,
    /// The release's pipelines.
    pub pipelines: Vec<Pipeline>,
    /// The release's strictness levels, ascending.
    pub match_strictness_levels: Vec<MatchStrictnessLevel>,
}

/// One pipeline of a release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pipeline {
    /// Pipeline identifier, unique within the manifest.
    pub pipeline: u16,
    /// Its checks and the meaning of each `compare` position.
    pub description: String,
    /// When the Verifier may release responses.
    pub response_slots: ResponseSlots,
    /// The largest sealed request the pipeline accepts, in bytes.
    pub max_request_bytes: u64,
}

/// One strictness level of a release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchStrictnessLevel {
    /// Level identifier, unique within the manifest.
    pub match_strictness: u8,
    /// What a pass at this level means.
    pub description: String,
}

/// A pipeline's response release times (WIP-201 §3.5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseSlots {
    /// First slot, in milliseconds after the request's arrival.
    pub min: u64,
    /// Last slot, in milliseconds; a request still running then fails.
    pub max: u64,
    /// Number of slots.
    pub count: u32,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: String,
    typ: String,
}

impl ReleaseManifest {
    /// Parses a compact JWS and checks the header and payload rules, but not the signature.
    ///
    /// # Errors
    /// Fails for a header other than `ES256`/`world-id-engine-manifest` with a `kid`, a payload
    /// that is not the specified JSON, or a rule of WIP-201 §3.5.2 it breaks.
    pub fn parse(compact: &str) -> Result<Self, ManifestError> {
        let malformed = || ManifestError::Malformed("release manifest");
        let mut parts = compact.split('.');
        let (Some(header), Some(payload), Some(_signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(malformed());
        };
        let header: Header = URL_SAFE_NO_PAD
            .decode(header)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or_else(malformed)?;
        if header.alg != "ES256" || header.typ != MANIFEST_TYP {
            return Err(malformed());
        }
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| malformed())?;
        let payload: ManifestPayload =
            serde_json::from_slice(&payload_bytes).map_err(|_| malformed())?;
        payload.validate()?;
        Ok(Self {
            compact: compact.to_owned(),
            kid: header.kid,
            payload_bytes,
            payload,
        })
    }

    /// `release_hash = SHA-256(JWS Payload)`; re-signing a release keeps it.
    #[must_use]
    pub fn release_hash(&self) -> [u8; 32] {
        Sha256::digest(&self.payload_bytes).into()
    }

    /// The `kid` of the release key that signed the manifest.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The decoded payload.
    #[must_use]
    pub const fn payload(&self) -> &ManifestPayload {
        &self.payload
    }

    /// The compact JWS.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.compact
    }

    /// Verifies the `ES256` signature under `key`, whose `kid` must match the header's.
    ///
    /// RPs and Authenticators MUST call this with an active release key of an Engine Provider
    /// they trust; the Verifier does not.
    ///
    /// # Errors
    /// Returns [`ManifestError::SignatureInvalid`] for another key or a bad signature.
    pub fn verify(&self, key: &ReleaseKeyJwk) -> Result<(), ManifestError> {
        if key.kid != self.kid {
            return Err(ManifestError::SignatureInvalid);
        }
        let verifying_key = key.verifying_key()?;
        let (signing_input, signature) = self
            .compact
            .rsplit_once('.')
            .ok_or(ManifestError::Malformed("release manifest"))?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .ok()
            .and_then(|bytes| Signature::from_slice(&bytes).ok())
            .ok_or(ManifestError::SignatureInvalid)?;
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| ManifestError::SignatureInvalid)
    }

    /// The pipeline `pipeline`, if the release defines it.
    #[must_use]
    pub fn pipeline(&self, pipeline: u16) -> Option<&Pipeline> {
        self.payload
            .pipelines
            .iter()
            .find(|p| p.pipeline == pipeline)
    }

    /// Whether the release defines `match_strictness`.
    #[must_use]
    pub fn defines_strictness(&self, match_strictness: u8) -> bool {
        self.payload
            .match_strictness_levels
            .iter()
            .any(|l| l.match_strictness == match_strictness)
    }

    /// The largest `max_request_bytes` of the release's pipelines.
    #[must_use]
    pub fn max_request_bytes(&self) -> u64 {
        self.payload
            .pipelines
            .iter()
            .map(|p| p.max_request_bytes)
            .max()
            .unwrap_or(0)
    }
}

impl ManifestPayload {
    /// Checks the rules of WIP-201 §3.5.2 that do not need the bundle.
    ///
    /// # Errors
    /// Returns [`ManifestError::Invalid`] naming the first violated field.
    pub fn validate(&self) -> Result<(), ManifestError> {
        let invalid = |ok: bool, field| {
            if ok {
                Ok(())
            } else {
                Err(ManifestError::Invalid(field))
            }
        };
        invalid(self.engine_hash().is_some(), "engine_hash")?;
        invalid(!self.pipelines.is_empty(), "pipelines")?;
        let unique_pipelines = self
            .pipelines
            .iter()
            .enumerate()
            .all(|(i, p)| self.pipelines[..i].iter().all(|q| q.pipeline != p.pipeline));
        invalid(
            unique_pipelines && self.pipelines.iter().all(|p| p.pipeline != 0),
            "pipeline",
        )?;
        invalid(
            self.pipelines.iter().all(|p| p.response_slots.is_valid()),
            "response_slots",
        )?;
        invalid(
            self.pipelines.iter().all(|p| p.max_request_bytes > 0),
            "max_request_bytes",
        )?;
        let ascending = self
            .match_strictness_levels
            .windows(2)
            .all(|w| w[0].match_strictness < w[1].match_strictness);
        invalid(
            !self.match_strictness_levels.is_empty() && ascending,
            "match_strictness_levels",
        )
    }

    /// The Engine bundle's `SHA-256`, if `engine_hash` is 64 lowercase hex digits.
    #[must_use]
    pub fn engine_hash(&self) -> Option<[u8; 32]> {
        let lowercase = self
            .engine_hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !lowercase {
            return None;
        }
        hex_32(&self.engine_hash)
    }
}

impl ResponseSlots {
    /// Whether `count >= 1` and `0 < min <= max`, with `min < max` if `count > 1`.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.count >= 1
            && self.min > 0
            && self.min <= self.max
            && (self.count == 1 || self.min < self.max)
    }

    /// The release times in milliseconds: `min * (max / min)^(i / (count - 1))` rounded down,
    /// or only `max` when `count = 1`.
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "durations in milliseconds are far below 2^52"
    )]
    pub fn times(&self) -> Vec<u64> {
        if self.count == 1 {
            return vec![self.max];
        }
        let last = self.count - 1;
        let ratio = self.max as f64 / self.min as f64;
        (0..self.count)
            .map(|i| match i {
                0 => self.min,
                i if i == last => self.max,
                i => (self.min as f64 * ratio.powf(f64::from(i) / f64::from(last))).floor() as u64,
            })
            .collect()
    }

    /// The slot at which a response whose Engine finished after `elapsed` milliseconds is
    /// released, or `None` if it finished after the last slot and the request fails.
    #[must_use]
    pub fn release_at(&self, elapsed: u64) -> Option<u64> {
        self.times().into_iter().find(|&slot| slot >= elapsed)
    }

    /// Bits a response reveals about its run time, `log2(count)`.
    #[must_use]
    pub fn leakage_bits(&self) -> f64 {
        f64::from(self.count).log2()
    }
}

/// An Engine Provider's metadata file at [`METADATA_PATH`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineMetadata {
    /// Schema version; MUST be `1`.
    pub version: u32,
    /// Stable identifier, which RPs MAY allowlist.
    pub provider_id: String,
    /// The provider's release keys.
    pub release_keys: Vec<ReleaseKey>,
    /// The provider's release manifests.
    pub manifests: Vec<MetadataManifest>,
}

/// A release key entry of [`EngineMetadata`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseKey {
    /// The P-256 public key.
    pub jwk: ReleaseKeyJwk,
    /// Whether the key may be relied on.
    pub status: ReleaseStatus,
}

/// A manifest entry of [`EngineMetadata`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataManifest {
    /// The compact JWS.
    pub manifest: String,
    /// Whether the release may be relied on.
    pub status: ReleaseStatus,
}

/// Status of a release key or manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseStatus {
    /// In use.
    Active,
    /// No longer in use.
    Retired,
    /// Must not be trusted.
    Revoked,
}

/// A P-256 JWK ([RFC 7518 §6.2](https://www.rfc-editor.org/rfc/rfc7518#section-6.2)) with
/// `kid`. Other members are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseKeyJwk {
    /// MUST be `EC`.
    pub kty: String,
    /// MUST be `P-256`.
    pub crv: String,
    /// Base64url x coordinate.
    pub x: String,
    /// Base64url y coordinate.
    pub y: String,
    /// Key identifier, matched against a manifest's `kid`.
    pub kid: String,
}

impl ReleaseKeyJwk {
    /// The ECDSA verifying key.
    ///
    /// # Errors
    /// Returns [`ManifestError::Malformed`] for another key type or an invalid point.
    pub fn verifying_key(&self) -> Result<VerifyingKey, ManifestError> {
        let malformed = || ManifestError::Malformed("release key");
        if self.kty != "EC" || self.crv != "P-256" {
            return Err(malformed());
        }
        let coordinate =
            |c: &str| -> Option<[u8; 32]> { URL_SAFE_NO_PAD.decode(c).ok()?.try_into().ok() };
        let (x, y) = coordinate(&self.x)
            .zip(coordinate(&self.y))
            .ok_or_else(malformed)?;
        let point = EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false);
        VerifyingKey::from_encoded_point(&point).map_err(|_| malformed())
    }
}

impl EngineMetadata {
    /// Parses the metadata file and checks its `version`.
    ///
    /// # Errors
    /// Fails for invalid JSON or a `version` other than `1`.
    pub fn parse(json: &[u8]) -> Result<Self, ManifestError> {
        let metadata: Self =
            serde_json::from_slice(json).map_err(|_| ManifestError::Malformed("metadata"))?;
        if metadata.version != 1 {
            return Err(ManifestError::Invalid("metadata version"));
        }
        Ok(metadata)
    }

    /// The active release key with `kid`, if any.
    #[must_use]
    pub fn active_key(&self, kid: &str) -> Option<&ReleaseKeyJwk> {
        self.release_keys
            .iter()
            .find(|k| k.status == ReleaseStatus::Active && k.jwk.kid == kid)
            .map(|k| &k.jwk)
    }

    /// The active manifests that parse and verify under an active release key.
    #[must_use]
    pub fn active_manifests(&self) -> Vec<ReleaseManifest> {
        self.manifests
            .iter()
            .filter(|m| m.status == ReleaseStatus::Active)
            .filter_map(|m| ReleaseManifest::parse(&m.manifest).ok())
            .filter(|m| {
                self.active_key(m.kid())
                    .is_some_and(|key| m.verify(key).is_ok())
            })
            .collect()
    }
}

fn hex_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests;
