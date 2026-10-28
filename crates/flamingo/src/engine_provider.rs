//! Engine Provider metadata (WIP-201 §4.3.4).

use serde::{Deserialize, Serialize};

use crate::release_manifest::{ManifestError, ReleaseKeyJwk, ReleaseManifest, is_issuer};

/// Path of the Engine Provider metadata file, relative to `iss`.
pub const METADATA_PATH: &str = "/.well-known/world-id-engine.json";

/// An Engine Provider's metadata file at `<iss>` + [`METADATA_PATH`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineProviderMetadata {
    /// Schema version; MUST be `1`.
    pub version: u32,
    /// The Engine Provider; MUST equal the URL the file was fetched from, minus [`METADATA_PATH`].
    pub iss: String,
    /// The provider's release keys.
    pub release_keys: Vec<ReleaseKey>,
    /// The release manifests the provider offers, each a compact JWS.
    pub manifests: Vec<String>,
}

/// A release key entry of [`EngineProviderMetadata`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseKey {
    /// The P-256 public key.
    pub jwk: ReleaseKeyJwk,
    /// Whether the key may be relied on.
    pub status: ReleaseStatus,
}

/// Status of a release key.
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

impl EngineProviderMetadata {
    /// Parses the metadata file fetched for `iss` and checks its `version` and `iss`.
    ///
    /// # Errors
    /// Fails for invalid JSON, a `version` other than `1`, or an `iss` that is not the
    /// requested one (RFC 8414 §3.3).
    pub fn parse(json: &[u8], iss: &str) -> Result<Self, ManifestError> {
        let metadata: Self =
            serde_json::from_slice(json).map_err(|_| ManifestError::Malformed("metadata"))?;
        if metadata.version != 1 {
            return Err(ManifestError::Invalid("metadata version"));
        }
        if !is_issuer(&metadata.iss) || metadata.iss != iss {
            return Err(ManifestError::Invalid("metadata iss"));
        }
        Ok(metadata)
    }

    /// The active release key with `kid`, if any.
    #[must_use]
    pub fn active_key(&self, kid: &str) -> Option<&ReleaseKeyJwk> {
        self.release_keys
            .iter()
            .find(|k| k.status == ReleaseStatus::Active && k.jwk.prm.kid.as_deref() == Some(kid))
            .map(|k| &k.jwk)
    }

    /// The listed manifests of this `iss` that parse and verify under an active release key.
    #[must_use]
    pub fn verified_manifests(&self) -> Vec<ReleaseManifest> {
        self.manifests
            .iter()
            .filter_map(|m| ReleaseManifest::from_jws(m).ok())
            .filter(|m| m.payload().iss == self.iss)
            .filter(|m| {
                self.active_key(m.kid())
                    .is_some_and(|key| m.verify(key).is_ok())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;

    use super::*;
    use crate::release_manifest::{MANIFEST_TYP, fixtures::*};

    #[test]
    fn reads_verified_manifests_from_metadata() {
        let active = sign(&payload());
        let other_key = SigningKey::from_bytes(&[0x22; 32].into()).unwrap();
        let unsigned = sign_raw(
            &header("ES256", MANIFEST_TYP),
            &serde_json::to_vec(&payload()).unwrap(),
            &other_key,
        );
        let mut foreign = payload();
        foreign.iss = "https://other.example".into();
        let foreign = sign(&foreign);
        let metadata = EngineProviderMetadata {
            version: 1,
            iss: ISS.into(),
            release_keys: vec![ReleaseKey {
                jwk: jwk(&signing_key(), KID),
                status: ReleaseStatus::Active,
            }],
            manifests: vec![active.clone(), unsigned, foreign, "not.a.jws".into()],
        };
        let json = serde_json::to_vec(&metadata).unwrap();
        let parsed = EngineProviderMetadata::parse(&json, ISS).unwrap();
        let manifests = parsed.verified_manifests();
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].as_jws(), active);

        // A revoked key no longer vouches for its manifests.
        let mut revoked = parsed;
        revoked.release_keys[0].status = ReleaseStatus::Revoked;
        assert!(revoked.verified_manifests().is_empty());

        // The metadata must name the issuer it was fetched for.
        assert_eq!(
            EngineProviderMetadata::parse(&json, "https://other.example"),
            Err(ManifestError::Invalid("metadata iss"))
        );

        let mut wrong_version = metadata;
        wrong_version.version = 2;
        assert_eq!(
            EngineProviderMetadata::parse(&serde_json::to_vec(&wrong_version).unwrap(), ISS),
            Err(ManifestError::Invalid("metadata version"))
        );
    }
}
