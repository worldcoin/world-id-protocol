//! Engine release manifests (WIP-201 §3.5.2).

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{MAX_COMPARED, MAX_ENTRIES};

/// The JWS `typ` of a release manifest.
pub const MANIFEST_TYP: &str = "world-id-engine-manifest";

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
    /// The JWS as received, in compact serialization; `ES256` signs its `header.payload` text.
    jws: String,
    kid: String,
    /// `SHA-256` of the JWS Payload, computed once.
    release_hash: [u8; 32],
    payload: ManifestPayload,
}

/// The JWS Payload of a release manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestPayload {
    /// `SHA-256` of the Engine bundle; 64 lowercase hex digits on the wire.
    #[serde(with = "lowercase_hex")]
    pub engine_hash: [u8; 32],
    /// Greater than the `version` of every earlier release of the Engine Provider.
    pub version: u64,
    /// The release's pipelines.
    pub pipelines: Vec<Pipeline>,
}

/// One pipeline of a release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pipeline {
    /// Pipeline identifier, unique within the manifest.
    pub pipeline: u16,
    /// Roles the Engine reads, with their `min` and `max` counts; `entries` follow this order.
    pub inputs: Vec<PipelineInput>,
    /// Compared positions: each names a `role` and an `index` below that role's `min`.
    pub compare: Vec<CompareEntry>,
    /// Strictness levels this pipeline supports, strictly ascending.
    pub match_strictness_levels: Vec<u8>,
    /// When the Verifier may release responses.
    pub response_slots: ResponseSlots,
    /// The largest sealed request the pipeline accepts, in bytes.
    pub max_request_bytes: u64,
}

/// One role in a pipeline's `inputs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineInput {
    /// Role name; unique within the pipeline's `inputs`.
    pub role: String,
    /// Minimum number of entries of this role.
    pub min: u64,
    /// Maximum number of entries of this role.
    pub max: u64,
}

/// One compared position in a pipeline's `compare`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompareEntry {
    /// A `role` listed in `inputs`.
    pub role: String,
    /// Index among that role's entries; MUST be below the role's `min`.
    pub index: u64,
}

/// A pipeline's response release times, in milliseconds after a request's arrival (WIP-201
/// §3.5.4). A request still running at the last slot fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResponseSlots(pub Vec<u64>);

impl ResponseSlots {
    /// Whether the slots are non-empty, positive and strictly ascending.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.0.first().is_some_and(|&first| first > 0) && self.0.windows(2).all(|w| w[0] < w[1])
    }

    /// The first slot, if any.
    #[must_use]
    pub fn first(&self) -> Option<u64> {
        self.0.first().copied()
    }

    /// The last slot, if any.
    #[must_use]
    pub fn last(&self) -> Option<u64> {
        self.0.last().copied()
    }

    /// The slot at which a response whose Engine finished after `elapsed` milliseconds is
    /// released, or `None` if it finished after the last slot and the request fails.
    #[must_use]
    pub fn release_at(&self, elapsed: u64) -> Option<u64> {
        self.0.iter().copied().find(|&slot| slot >= elapsed)
    }

    /// Bits a response reveals about its run time, `log2(n)` for `n` slots.
    #[must_use]
    #[expect(clippy::cast_precision_loss, reason = "slot counts are tiny")]
    pub fn leakage_bits(&self) -> f64 {
        (self.0.len() as f64).log2()
    }
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: String,
    typ: String,
    #[serde(flatten)]
    extensions: serde_json::Map<String, serde_json::Value>,
}

impl ReleaseManifest {
    /// Parses a compact JWS and checks the header and payload rules, but not the signature.
    ///
    /// # Errors
    /// Fails for a header other than `ES256`/`world-id-engine-manifest` with a `kid`, a payload
    /// that is not the specified JSON, or a rule of WIP-201 §3.5.2 it breaks.
    pub fn from_jws(jws: &str) -> Result<Self, ManifestError> {
        let malformed = || ManifestError::Malformed("release manifest");
        let mut parts = jws.split('.');
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
        // No critical extensions are supported. RFC 7515 §4.1.11 requires rejecting them.
        if header.alg != "ES256"
            || header.typ != MANIFEST_TYP
            || header.extensions.contains_key("crit")
        {
            return Err(malformed());
        }
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| malformed())?;
        let payload: ManifestPayload =
            serde_json::from_slice(&payload_bytes).map_err(|_| malformed())?;
        payload.validate()?;
        Ok(Self {
            jws: jws.to_owned(),
            kid: header.kid,
            release_hash: Sha256::digest(&payload_bytes).into(),
            payload,
        })
    }

    /// `release_hash = SHA-256(JWS Payload)`; re-signing a release keeps it.
    #[must_use]
    pub const fn release_hash(&self) -> [u8; 32] {
        self.release_hash
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

    /// The JWS in compact serialization, as received.
    #[must_use]
    pub fn as_jws(&self) -> &str {
        &self.jws
    }

    /// Verifies the `ES256` signature under `key`, whose `kid` must match the header's, and returns
    /// the payload.
    ///
    /// RPs and Authenticators MUST call this with an active release key of an Engine Provider
    /// they trust; the Verifier does not.
    ///
    /// # Errors
    /// Returns [`ManifestError::SignatureInvalid`] for another key or a bad signature.
    pub fn verify(&self, key: &ReleaseKeyJwk) -> Result<&ManifestPayload, ManifestError> {
        if key.prm.kid.as_deref() != Some(self.kid.as_str()) {
            return Err(ManifestError::SignatureInvalid);
        }
        let verifying_key = verifying_key(key)?;
        let (signing_input, signature) = self
            .jws
            .rsplit_once('.')
            .ok_or(ManifestError::Malformed("release manifest"))?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .ok()
            .and_then(|bytes| Signature::from_slice(&bytes).ok())
            .ok_or(ManifestError::SignatureInvalid)?;
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| ManifestError::SignatureInvalid)?;
        Ok(&self.payload)
    }

    /// The pipeline `pipeline`, if the release defines it.
    #[must_use]
    pub fn pipeline(&self, pipeline: u16) -> Option<&Pipeline> {
        self.payload
            .pipelines
            .iter()
            .find(|p| p.pipeline == pipeline)
    }

    /// Whether the pipeline `pipeline` lists `match_strictness`.
    #[must_use]
    pub fn has_match_strictness(&self, pipeline: u16, match_strictness: u8) -> bool {
        self.pipeline(pipeline)
            .is_some_and(|p| p.match_strictness_levels.contains(&match_strictness))
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
        for pipeline in &self.pipelines {
            pipeline.validate()?;
        }
        Ok(())
    }
}

impl Pipeline {
    /// Checks the rules of WIP-201 §3.5.2 for one pipeline.
    fn validate(&self) -> Result<(), ManifestError> {
        let invalid = |ok: bool, field| {
            if ok {
                Ok(())
            } else {
                Err(ManifestError::Invalid(field))
            }
        };
        invalid(!self.inputs.is_empty(), "inputs")?;
        let unique_roles = self.inputs.iter().enumerate().all(|(i, input)| {
            self.inputs[..i]
                .iter()
                .all(|other| other.role != input.role)
        });
        invalid(
            unique_roles && self.inputs.iter().all(|i| !i.role.is_empty()),
            "inputs",
        )?;
        invalid(self.inputs.iter().all(|i| i.max >= i.min), "inputs")?;
        // A pipeline whose minimum entries exceed `MAX_ENTRIES` accepts no request.
        let min_entries = self
            .inputs
            .iter()
            .try_fold(0_u64, |sum, i| sum.checked_add(i.min));
        invalid(
            min_entries.is_some_and(|sum| sum <= MAX_ENTRIES as u64),
            "inputs",
        )?;
        let distinct = self
            .compare
            .iter()
            .enumerate()
            .all(|(i, entry)| !self.compare[..i].contains(entry));
        invalid(
            (2..=MAX_COMPARED).contains(&self.compare.len()) && distinct,
            "compare",
        )?;
        for entry in &self.compare {
            let Some(input) = self.inputs.iter().find(|i| i.role == entry.role) else {
                return Err(ManifestError::Invalid("compare"));
            };
            if entry.index >= input.min {
                return Err(ManifestError::Invalid("compare"));
            }
        }
        let ascending = self.match_strictness_levels.windows(2).all(|w| w[0] < w[1]);
        invalid(
            !self.match_strictness_levels.is_empty() && ascending,
            "match_strictness_levels",
        )
    }
}

/// A release key: a public P-256 JWK ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)) with
/// `kid`. Other members are accepted and ignored.
pub type ReleaseKeyJwk = jose_jwk::Jwk;

/// The ECDSA verifying key of a public P-256 release key.
///
/// # Errors
/// [`ManifestError::Malformed`] for another key type or curve, a private key or an invalid point.
pub fn verifying_key(jwk: &ReleaseKeyJwk) -> Result<VerifyingKey, ManifestError> {
    let malformed = || ManifestError::Malformed("release key");
    match &jwk.key {
        jose_jwk::Key::Ec(ec) if ec.d.is_none() => p256::PublicKey::try_from(ec)
            .map(VerifyingKey::from)
            .map_err(|_| malformed()),
        _ => Err(malformed()),
    }
}

/// A 32-byte hash as exactly 64 lowercase hex digits.
mod lowercase_hex {
    use serde::{Deserialize as _, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(hash: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(hash))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let hex = String::deserialize(deserializer)?;
        let mut hash = [0u8; 32];
        if hex.bytes().any(|b| b.is_ascii_uppercase())
            || hex::decode_to_slice(&hex, &mut hash).is_err()
        {
            return Err(D::Error::custom("expected 64 lowercase hex digits"));
        }
        Ok(hash)
    }
}

/// Signed manifests and keys shared by the manifest and metadata tests.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer as _};

    pub const KID: &str = "release-1";

    pub fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32].into()).unwrap()
    }

    pub fn jwk(key: &SigningKey, kid: &str) -> ReleaseKeyJwk {
        ReleaseKeyJwk {
            key: jose_jwk::Key::Ec(p256::PublicKey::from(key.verifying_key()).into()),
            prm: jose_jwk::Parameters {
                kid: Some(kid.into()),
                ..jose_jwk::Parameters::default()
            },
        }
    }

    pub fn payload() -> ManifestPayload {
        ManifestPayload {
            engine_hash: [0x2a; 32],
            version: 1,
            pipelines: vec![Pipeline {
                pipeline: 1,
                inputs: vec![
                    PipelineInput {
                        role: "credential_image".into(),
                        min: 1,
                        max: 1,
                    },
                    PipelineInput {
                        role: "live_frame".into(),
                        min: 1,
                        max: 1,
                    },
                    PipelineInput {
                        role: "challenge".into(),
                        min: 1,
                        max: 1,
                    },
                ],
                compare: vec![
                    CompareEntry {
                        role: "credential_image".into(),
                        index: 0,
                    },
                    CompareEntry {
                        role: "live_frame".into(),
                        index: 0,
                    },
                    CompareEntry {
                        role: "challenge".into(),
                        index: 0,
                    },
                ],
                match_strictness_levels: vec![1, 2],
                response_slots: ResponseSlots(vec![500, 1587, 5039, 16_000]),
                max_request_bytes: 8 << 20,
            }],
        }
    }

    pub fn sign_raw(header: &str, payload: &[u8], key: &SigningKey) -> String {
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let signature: Signature = key.sign(signing_input.as_bytes());
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    pub fn header(alg: &str, typ: &str) -> String {
        format!(r#"{{"alg":"{alg}","kid":"{KID}","typ":"{typ}"}}"#)
    }

    pub fn sign(payload: &ManifestPayload) -> String {
        sign_raw(
            &header("ES256", MANIFEST_TYP),
            &serde_json::to_vec(payload).unwrap(),
            &signing_key(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{fixtures::*, *};
    use p256::ecdsa::SigningKey;

    #[test]
    fn release_keys_accept_extra_members_but_not_private_keys() {
        let manifest = ReleaseManifest::from_jws(&sign(&payload())).unwrap();
        let mut value = serde_json::to_value(jwk(&signing_key(), KID)).unwrap();
        value["alg"] = "ES256".into();
        value["use"] = "sig".into();
        let key: ReleaseKeyJwk = serde_json::from_value(value).unwrap();
        assert!(manifest.verify(&key).is_ok());

        let private = ReleaseKeyJwk {
            key: jose_jwk::Key::Ec(p256::SecretKey::from(signing_key()).into()),
            prm: key.prm,
        };
        assert_eq!(
            manifest.verify(&private),
            Err(ManifestError::Malformed("release key"))
        );
    }

    #[test]
    fn parses_and_verifies_a_manifest() {
        let compact = sign(&payload());
        let manifest = ReleaseManifest::from_jws(&compact).unwrap();
        assert_eq!(manifest.kid(), KID);
        assert_eq!(manifest.payload(), &payload());
        assert_eq!(manifest.payload().engine_hash, [0x2a; 32]);
        assert!(manifest.verify(&jwk(&signing_key(), KID)).is_ok());
        assert!(manifest.pipeline(1).is_some() && manifest.pipeline(2).is_none());
        assert!(manifest.has_match_strictness(1, 2) && !manifest.has_match_strictness(1, 3));
        assert_eq!(manifest.max_request_bytes(), 8 << 20);
    }

    #[test]
    fn release_hash_covers_only_the_payload() {
        let bytes = serde_json::to_vec(&payload()).unwrap();
        let manifest = ReleaseManifest::from_jws(&sign(&payload())).unwrap();
        assert_eq!(
            manifest.release_hash(),
            <[u8; 32]>::from(Sha256::digest(&bytes))
        );

        // Re-signing with another key keeps the hash.
        let other_key = SigningKey::from_bytes(&[0x22; 32].into()).unwrap();
        let resigned = sign_raw(&header("ES256", MANIFEST_TYP), &bytes, &other_key);
        let resigned = ReleaseManifest::from_jws(&resigned).unwrap();
        assert_eq!(resigned.release_hash(), manifest.release_hash());
    }

    #[test]
    fn rejects_other_keys_and_tampered_payloads() {
        let manifest = ReleaseManifest::from_jws(&sign(&payload())).unwrap();
        let other = SigningKey::from_bytes(&[0x22; 32].into()).unwrap();
        assert_eq!(
            manifest.verify(&jwk(&other, KID)),
            Err(ManifestError::SignatureInvalid)
        );
        assert_eq!(
            manifest.verify(&jwk(&signing_key(), "other")),
            Err(ManifestError::SignatureInvalid)
        );

        let compact = sign(&payload());
        let (header, rest) = compact.split_once('.').unwrap();
        let (_, signature) = rest.split_once('.').unwrap();
        let mut changed = payload();
        changed.version = 2;
        let tampered = format!(
            "{header}.{}.{signature}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&changed).unwrap())
        );
        let tampered = ReleaseManifest::from_jws(&tampered).unwrap();
        assert_eq!(
            tampered.verify(&jwk(&signing_key(), KID)),
            Err(ManifestError::SignatureInvalid)
        );
    }

    #[test]
    fn rejects_other_headers() {
        let bytes = serde_json::to_vec(&payload()).unwrap();
        for header in [header("HS256", MANIFEST_TYP), header("ES256", "JWT")] {
            let compact = sign_raw(&header, &bytes, &signing_key());
            assert!(matches!(
                ReleaseManifest::from_jws(&compact),
                Err(ManifestError::Malformed(_))
            ));
        }
        assert!(ReleaseManifest::from_jws("a.b").is_err());
    }

    #[test]
    fn rejects_unsupported_critical_headers_even_with_a_valid_signature() {
        let payload = serde_json::to_vec(&payload()).unwrap();
        for critical in [
            serde_json::json!(["urn:example:must-understand"]),
            serde_json::json!([]),
            serde_json::Value::Null,
        ] {
            let protected = serde_json::json!({
                "alg": "ES256", "kid": KID, "typ": MANIFEST_TYP,
                "crit": critical, "urn:example:must-understand": true,
            });
            let jws = sign_raw(&protected.to_string(), &payload, &signing_key());
            assert!(matches!(
                ReleaseManifest::from_jws(&jws),
                Err(ManifestError::Malformed(_))
            ));
        }
        // Unknown non-critical parameters remain compatible with ordinary JWS extensions.
        let protected = serde_json::json!({
            "alg": "ES256", "kid": KID, "typ": MANIFEST_TYP,
            "urn:example:hint": true,
        });
        let jws = sign_raw(&protected.to_string(), &payload, &signing_key());
        assert!(
            ReleaseManifest::from_jws(&jws)
                .unwrap()
                .verify(&jwk(&signing_key(), KID))
                .is_ok()
        );
    }

    type Change = Box<dyn Fn(&mut ManifestPayload)>;

    #[test]
    fn rejects_payloads_that_break_the_rules() {
        let slots = |times: &[u64]| ResponseSlots(times.to_vec());
        let cases: Vec<(Change, &str)> = vec![
            (Box::new(|p| p.pipelines.clear()), "pipelines"),
            (
                Box::new(|p| p.pipelines.push(p.pipelines[0].clone())),
                "pipeline",
            ),
            (Box::new(|p| p.pipelines[0].pipeline = 0), "pipeline"),
            (
                Box::new(move |p| p.pipelines[0].response_slots = slots(&[0, 10])),
                "response_slots",
            ),
            (
                Box::new(move |p| p.pipelines[0].response_slots = slots(&[10, 5])),
                "response_slots",
            ),
            (
                Box::new(move |p| p.pipelines[0].response_slots = slots(&[10, 10])),
                "response_slots",
            ),
            (
                Box::new(move |p| p.pipelines[0].response_slots = slots(&[])),
                "response_slots",
            ),
            (
                Box::new(|p| p.pipelines[0].max_request_bytes = 0),
                "max_request_bytes",
            ),
            (Box::new(|p| p.pipelines[0].inputs.clear()), "inputs"),
            (Box::new(|p| p.pipelines[0].inputs[0].max = 0), "inputs"),
            (
                Box::new(|p| {
                    p.pipelines[0].inputs.push(PipelineInput {
                        role: "credential_image".into(),
                        min: 1,
                        max: 1,
                    });
                }),
                "inputs",
            ),
            (Box::new(|p| p.pipelines[0].compare.clear()), "compare"),
            (Box::new(|p| p.pipelines[0].compare.truncate(1)), "compare"),
            (
                Box::new(|p| {
                    let first = p.pipelines[0].compare[0].clone();
                    p.pipelines[0].compare[1] = first;
                }),
                "compare",
            ),
            (
                Box::new(|p| {
                    p.pipelines[0].inputs[1].min = 7;
                    p.pipelines[0].inputs[1].max = 7;
                }),
                "inputs",
            ),
            (
                Box::new(|p| p.pipelines[0].compare[0].role = "unknown".into()),
                "compare",
            ),
            (Box::new(|p| p.pipelines[0].compare[0].index = 1), "compare"),
            (
                Box::new(|p| p.pipelines[0].match_strictness_levels.reverse()),
                "match_strictness_levels",
            ),
            (
                Box::new(|p| p.pipelines[0].match_strictness_levels[1] = 1),
                "match_strictness_levels",
            ),
            (
                Box::new(|p| p.pipelines[0].match_strictness_levels.clear()),
                "match_strictness_levels",
            ),
        ];
        for (change, field) in cases {
            let mut payload = payload();
            change(&mut payload);
            assert_eq!(
                ReleaseManifest::from_jws(&sign(&payload)),
                Err(ManifestError::Invalid(field))
            );
        }
    }

    #[test]
    fn engine_hash_must_be_64_lowercase_hex_digits() {
        for engine_hash in [
            "2A".repeat(32),
            "2a".repeat(31),
            "2a".repeat(33),
            "zz".repeat(32),
        ] {
            let mut payload = serde_json::to_value(payload()).unwrap();
            payload["engine_hash"] = engine_hash.into();
            let compact = sign_raw(
                &header("ES256", MANIFEST_TYP),
                &serde_json::to_vec(&payload).unwrap(),
                &signing_key(),
            );
            assert!(matches!(
                ReleaseManifest::from_jws(&compact),
                Err(ManifestError::Malformed(_))
            ));
        }
        assert_eq!(
            serde_json::to_value(payload()).unwrap()["engine_hash"],
            "2a".repeat(32)
        );
    }

    #[test]
    fn allows_a_single_slot() {
        let mut payload = payload();
        payload.pipelines[0].response_slots = ResponseSlots(vec![3000]);
        assert!(ReleaseManifest::from_jws(&sign(&payload)).is_ok());
    }

    #[test]
    fn releases_at_the_next_slot() {
        let slots = ResponseSlots(vec![1000, 1200, 3000, 16_000]);
        assert_eq!(slots.release_at(0), Some(1000));
        assert_eq!(slots.release_at(1000), Some(1000));
        assert_eq!(slots.release_at(1001), Some(1200));
        assert_eq!(slots.release_at(16_001), None);
        assert_eq!((slots.first(), slots.last()), (Some(1000), Some(16_000)));
        assert!((slots.leakage_bits() - 2.0).abs() < f64::EPSILON);
        assert!(ResponseSlots(vec![3000]).leakage_bits().abs() < f64::EPSILON);
    }
}
