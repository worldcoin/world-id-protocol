//! The Verifier request (WIP-201 §4.5.1) with its Engine request (§4.4.1) and optional
//! Authenticator Assertion.
//!
//! Both the request and its nested `payload` are deterministic CBOR maps. Decoding accepts
//! only the canonical encoding, so `cdh` and every party see the same bytes.

use eddsa_babyjubjub::EdDSAPublicKey;
use sha2::{Digest as _, Sha256};
use world_id_primitives::{
    FieldElement,
    authenticator_assertion::{
        AuthenticatorAssertionError, AuthenticatorAssertionPrivateInputs,
        AuthenticatorAssertionToken, TrustAnchorKeyToken, verify,
    },
    cbor::{self, CborError, Fields, Value},
};

use crate::{
    FlamingoAatClaims, MAX_COMMITTED, MAX_PIPELINE_INPUTS, MAX_REQUEST_LIFETIME, REQUEST_VERSION,
    ReleaseManifest, engine_config_hash,
    pipeline_type::{Cardinality, PipelineType},
    release_manifest::{Input, Pipeline},
};

/// Why a request could not be encoded, decoded or accepted.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    /// The bytes are not the canonical encoding of the expected map.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// A field is outside the bounds of WIP-201 §4.4.1 and §4.5.1, or does not fit the release.
    #[error("{0} out of bounds")]
    OutOfBounds(&'static str),
    /// The TAKT or AAT failed to decode or a WIP-106 §3.8 check.
    #[error("AAT rejected: {0}")]
    AatRejected(AuthenticatorAssertionError),
}

/// The request the Authenticator seals to the Verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The `rpId` of the request.
    pub aud: FieldElement,
    /// Nonzero, fresh per request and bound to the RP's request as the consuming protocol defines.
    pub nonce: FieldElement,
    /// Unix seconds after which the Verifier rejects the request.
    pub expires_at: u64,
    /// The WIP-107 `billingNullifier` of the Authenticator's registration for `aud`, or `0`.
    pub billing_nullifier: FieldElement,
    /// The encoded [`Payload`], kept as bytes so `cdh` commits to its exact encoding.
    pub payload: Vec<u8>,
    /// Inputs for verifying an AAT, if the Authenticator has one.
    pub aat_inputs: Option<AatInputs>,
}

impl Request {
    /// Builds a request over `payload`, checking its bounds.
    ///
    /// # Errors
    /// Fails when `payload` or `nonce` is out of bounds.
    pub fn new(
        aud: FieldElement,
        nonce: FieldElement,
        expires_at: u64,
        billing_nullifier: FieldElement,
        payload: &Payload,
        aat_inputs: Option<AatInputs>,
    ) -> Result<Self, RequestError> {
        let request = Self {
            aud,
            nonce,
            expires_at,
            billing_nullifier,
            payload: payload.encode()?,
            aat_inputs,
        };
        request.validate()?;
        Ok(request)
    }

    /// The canonical encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut fields = vec![
            ("version", Value::Integer(REQUEST_VERSION.into())),
            ("payload", Value::Bytes(self.payload.clone())),
            ("aud", cbor::field_element(self.aud)),
            ("nonce", cbor::field_element(self.nonce)),
            (
                "billing_nullifier",
                cbor::field_element(self.billing_nullifier),
            ),
        ];
        if let Some(aat) = &self.aat_inputs {
            fields.push(("aat_inputs", aat.to_value()));
        }
        fields.push(("expires_at", Value::Integer(self.expires_at.into())));
        cbor::encode(&map(fields))
    }

    /// Decodes a canonical request and checks its bounds, including the payload's. Rejects a
    /// request larger than `max_bytes`, a size limit the caller chooses, before parsing it.
    ///
    /// # Errors
    /// Fails for any other encoding, version or shape, or a bound violation.
    pub fn decode(bytes: &[u8], max_bytes: u64) -> Result<Self, RequestError> {
        if u64::try_from(bytes.len()).map_or(true, |len| len > max_bytes) {
            return Err(RequestError::OutOfBounds("request"));
        }
        let malformed = || RequestError::Malformed("request");
        let mut fields = Fields::of(cbor::decode(bytes, "request")?, "request")?;
        let aud = fields.field_element("aud")?;
        let nonce = fields.field_element("nonce")?;
        let payload = fields.byte_string("payload")?;
        if fields.uint::<u64>("version")? != REQUEST_VERSION {
            return Err(malformed());
        }
        let aat_inputs = fields
            .optional("aat_inputs")
            .map(AatInputs::from_value)
            .transpose()?;
        let request = Self {
            aud,
            nonce,
            expires_at: fields.uint("expires_at")?,
            billing_nullifier: fields.field_element("billing_nullifier")?,
            payload,
            aat_inputs,
        };
        fields.finish()?;
        if request.encode() != bytes {
            return Err(malformed());
        }
        request.validate()?;
        Ok(request)
    }

    /// The decoded payload.
    ///
    /// # Errors
    /// Fails when the payload is not canonical or out of bounds.
    pub fn payload(&self) -> Result<Payload, RequestError> {
        Payload::decode(&self.payload)
    }

    /// `cdh = R(SHA-256(payload))`, binding an AAT to the exact payload bytes.
    #[must_use]
    pub fn cdh(&self) -> FieldElement {
        FieldElement::from_digest(&Sha256::digest(&self.payload).into())
    }

    /// Verifies the AAT, if any, against this request at the Verifier's time `now`, in Unix
    /// seconds, and returns the claims it yields.
    ///
    /// # Errors
    /// Returns [`RequestError::AatRejected`] if any WIP-106 §3.8 check fails, and
    /// [`RequestError::OutOfBounds`] for an `aud` not below `2^64`.
    pub fn verify_aat(&self, now: u32) -> Result<Option<FlamingoAatClaims>, RequestError> {
        self.aat_inputs
            .as_ref()
            .map(|aat| aat.verify(now, self.aud, self.nonce, self.cdh()))
            .transpose()
    }

    /// Checks `expires_at` against the Verifier's time `now`, in Unix seconds.
    ///
    /// # Errors
    /// Fails when the request has expired or expires more than `MAX_REQUEST_LIFETIME` after `now`.
    pub const fn check_expiry(&self, now: u64) -> Result<(), RequestError> {
        if now > self.expires_at || self.expires_at - now > MAX_REQUEST_LIFETIME {
            return Err(RequestError::OutOfBounds("expires_at"));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), RequestError> {
        if self.nonce == FieldElement::ZERO {
            return Err(RequestError::OutOfBounds("nonce"));
        }
        self.payload().map(|_| ())
    }
}

/// The Engine request (WIP-201 §4.4.1): what the Engine receives, unchanged.
#[derive(Clone, PartialEq, Eq)]
pub struct Payload {
    /// A pipeline of the loaded release, nonzero.
    pub pipeline_id: u16,
    /// A strictness level of that pipeline.
    pub strictness: u8,
    /// `entries[i]` is the pipeline's `inputs[i]`: an encoded image or embedding, or `None` for
    /// an absent entry.
    pub entries: Vec<Option<Vec<u8>>>,
}

/// Omits the entries, which are biometric data.
impl std::fmt::Debug for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Payload")
            .field("pipeline_id", &self.pipeline_id)
            .field("strictness", &self.strictness)
            .finish_non_exhaustive()
    }
}

/// The values a Flamingo Token derives from a request that fits the loaded release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadCommitments {
    /// `entry_hash_k`: `R(SHA-256)` of the entry of committed role `k`, or `0`.
    pub entry_hashes: [FieldElement; MAX_COMMITTED],
    /// The `pipeline_type` of the pipeline that runs.
    pub pipeline_type: FieldElement,
    /// `engine_config_hash` of the release, pipeline and strictness.
    pub engine_config_hash: FieldElement,
}

impl Payload {
    /// The canonical encoding, after checking the bounds.
    ///
    /// # Errors
    /// Fails when a field is out of bounds.
    pub fn encode(&self) -> Result<Vec<u8>, RequestError> {
        self.validate()?;
        Ok(cbor::encode(&self.to_value()))
    }

    /// Decodes a canonical payload and checks its bounds.
    ///
    /// # Errors
    /// Fails for any other encoding or shape, or a bound violation.
    pub fn decode(bytes: &[u8]) -> Result<Self, RequestError> {
        // Canonical key order: shorter keys first, then bytewise.
        let mut fields = Fields::of(cbor::decode(bytes, "payload")?, "payload")?;
        let entries = fields
            .take("entries")?
            .into_array()
            .map_err(|_| CborError("payload"))?
            .into_iter()
            .map(|entry| match entry {
                Value::Null => Ok(None),
                Value::Bytes(data) => Ok(Some(data)),
                _ => Err(CborError("payload")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let strictness = fields.uint("strictness")?;
        let payload = Self {
            pipeline_id: fields.uint("pipeline_id")?,
            strictness,
            entries,
        };
        fields.finish()?;
        if cbor::encode(&payload.to_value()) != bytes {
            return Err(RequestError::Malformed("payload"));
        }
        payload.validate()?;
        Ok(payload)
    }

    /// Checks the bounds of WIP-201 §4.4.1 that do not need the release.
    ///
    /// # Errors
    /// Returns [`RequestError::OutOfBounds`] naming the first violated field.
    pub fn validate(&self) -> Result<(), RequestError> {
        if self.pipeline_id == 0 {
            return Err(RequestError::OutOfBounds("pipeline_id"));
        }
        if !(1..=MAX_PIPELINE_INPUTS).contains(&self.entries.len()) {
            return Err(RequestError::OutOfBounds("entries"));
        }
        Ok(())
    }

    /// Checks that the payload fits `release` (WIP-201 §4.4.2 item 1, apart from media types) and
    /// returns what the Flamingo Token commits to.
    ///
    /// # Errors
    /// Returns [`RequestError::OutOfBounds`] when the release has no such pipeline, the pipeline
    /// does not list `strictness`, `entries` does not have one entry per input, or an entry is
    /// absent for a role that is not optional (`?`).
    pub fn fit(&self, release: &ReleaseManifest) -> Result<PayloadCommitments, RequestError> {
        let pipeline = release
            .pipeline(self.pipeline_id)
            .ok_or(RequestError::OutOfBounds("pipeline_id"))?;
        let pipeline_type = pipeline
            .parsed_type()
            .map_err(|_| RequestError::OutOfBounds("pipeline_id"))?;
        if !pipeline.has_strictness(self.strictness) {
            return Err(RequestError::OutOfBounds("strictness"));
        }
        if self.entries.len() != pipeline.inputs.len() {
            return Err(RequestError::OutOfBounds("entries"));
        }
        let absent_allowed = |input: &Input| {
            pipeline_type
                .member(&input.role)
                .is_some_and(|m| m.cardinality == Cardinality::Optional)
        };
        if !self
            .entries
            .iter()
            .zip(&pipeline.inputs)
            .all(|(entry, input)| entry.is_some() || absent_allowed(input))
        {
            return Err(RequestError::OutOfBounds("entries"));
        }
        Ok(PayloadCommitments {
            entry_hashes: self.entry_hashes(pipeline, &pipeline_type),
            pipeline_type: pipeline_type.hash(),
            engine_config_hash: engine_config_hash(
                &release.release_hash(),
                self.pipeline_id,
                self.strictness,
            ),
        })
    }

    /// `entry_hash_k = R(SHA-256(entries[i]))` for the input `i` of committed role `k`, `0` if
    /// that entry is absent or the type has no committed role `k`.
    fn entry_hashes(
        &self,
        pipeline: &Pipeline,
        pipeline_type: &PipelineType,
    ) -> [FieldElement; MAX_COMMITTED] {
        let mut hashes = [FieldElement::ZERO; MAX_COMMITTED];
        for (hash, role) in hashes.iter_mut().zip(pipeline_type.committed_roles()) {
            // Conformance gives a committed role exactly one input.
            let entry = pipeline
                .inputs
                .iter()
                .position(|input| input.role == role)
                .and_then(|i| self.entries.get(i))
                .and_then(Option::as_ref);
            if let Some(data) = entry {
                *hash = FieldElement::from_digest(&Sha256::digest(data).into());
            }
        }
        hashes
    }

    fn to_value(&self) -> Value {
        let entries = self
            .entries
            .iter()
            .map(|entry| entry.clone().map_or(Value::Null, Value::Bytes))
            .collect();
        map(vec![
            ("pipeline_id", Value::Integer(self.pipeline_id.into())),
            ("strictness", Value::Integer(self.strictness.into())),
            ("entries", Value::Array(entries)),
        ])
    }
}

/// The TAKT, the AAT and the minimum build, as the Authenticator sends them (WIP-201 §4.5.1).
#[derive(Clone, PartialEq, Eq)]
pub struct AatInputs {
    /// Compressed `trust_anchor_key` that signed the TAKT.
    pub trust_anchor_key: [u8; 32],
    /// The TAKT's CWT encoding.
    pub takt: Vec<u8>,
    /// The AAT's CWT encoding.
    pub aat: Vec<u8>,
    /// Minimum `build_version`, as the consuming protocol defines; `0` sets no minimum.
    pub min_build_version: u32,
}

impl std::fmt::Debug for AatInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AatInputs").finish_non_exhaustive()
    }
}

impl AatInputs {
    /// Verifies the TAKT and AAT at the Verifier's time `now` for a request with `cdh` and returns
    /// the claims a token carries.
    ///
    /// # Errors
    /// Returns [`RequestError::AatRejected`] if a token fails to decode or any WIP-106 §3.8 check
    /// fails, [`RequestError::OutOfBounds`] for an `aud` not below `2^64`, and
    /// [`RequestError::Malformed`] for an undecodable key.
    pub fn verify(
        &self,
        now: u32,
        aud: FieldElement,
        nonce: FieldElement,
        cdh: FieldElement,
    ) -> Result<FlamingoAatClaims, RequestError> {
        let aud_bytes = aud.to_be_bytes();
        if aud_bytes[..24].iter().any(|b| *b != 0) {
            return Err(RequestError::OutOfBounds("aud"));
        }
        let aud = u64::from_be_bytes(std::array::from_fn(|i| aud_bytes[24 + i]));
        let private = AuthenticatorAssertionPrivateInputs {
            trust_anchor_key: EdDSAPublicKey::from_compressed_bytes(self.trust_anchor_key)
                .map_err(|_| RequestError::Malformed("aat_inputs"))?,
            takt: TrustAnchorKeyToken::from_cwt(&self.takt).map_err(RequestError::AatRejected)?,
            aat: AuthenticatorAssertionToken::from_cwt(&self.aat)
                .map_err(RequestError::AatRejected)?,
            cdh,
        };
        let public = private.public_inputs(now, aud, nonce, self.min_build_version);
        verify(&public, &private).map_err(RequestError::AatRejected)?;
        Ok(FlamingoAatClaims {
            trust_anchor_key_hash: public.trust_anchor_key_hash,
            aat_flags: u64::from(public.platform)
                | (u64::from(public.sec_level) << 8)
                | (u64::from(public.min_build_version) << 16)
                | (u64::from(public.sec_meta) << 48)
                | (u64::from(public.authenticator_meta.pack()) << 52),
        })
    }

    fn to_value(&self) -> Value {
        map(vec![
            (
                "trust_anchor_key",
                Value::Bytes(self.trust_anchor_key.to_vec()),
            ),
            ("takt", Value::Bytes(self.takt.clone())),
            ("aat", Value::Bytes(self.aat.clone())),
            (
                "min_build_version",
                Value::Integer(self.min_build_version.into()),
            ),
        ])
    }

    fn from_value(value: Value) -> Result<Self, RequestError> {
        let mut fields = Fields::of(value, "aat_inputs")?;
        let aat = fields.byte_string("aat")?;
        let takt = fields.byte_string("takt")?;
        let trust_anchor_key = fields.bytes("trust_anchor_key")?;
        let min_build_version = fields.uint("min_build_version")?;
        fields.finish()?;
        Ok(Self {
            trust_anchor_key,
            takt,
            aat,
            min_build_version,
        })
    }
}

/// A deterministic CBOR map with text keys.
fn map(entries: Vec<(&str, Value)>) -> Value {
    cbor::map(entries.into_iter().map(|(k, v)| (k.into(), v)).collect())
}

impl From<CborError> for RequestError {
    fn from(error: CborError) -> Self {
        Self::Malformed(error.0)
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;
    use world_id_primitives::{
        EdDSAPrivateKey,
        authenticator_assertion::{AatClaims, AuthenticatorMeta, UserPresence},
    };

    use super::*;
    use crate::release_manifest::{
        ManifestPayload,
        fixtures::{self, TYPE, input},
    };

    // WIP-201 Appendix A1, "Request".
    const PAYLOAD: &str = "a367656e7472696573824f7265666572656e636520696d6167654a6c69766520696d6167656a7374726963746e657373026b706970656c696e655f696401";
    const CDH: &str = "2bfe8011f17415c59b014210e47d84ff25001d60730b51653a820760c77911d5";
    const TAKT: &str = "84582aa2013a000100000458202d4bdf6ee60feda0975c770bb7a23dc6e4e0ed1e35ff3c2426cded4ec030d987a05885a4041a6a4e8b7008a101a4010220012158207135fa4fd93a09dce98bbf681b4bfcf50e7c0d6354e62afb0bff2a3429617865225820ed4c1f02ddb9023ee56a557e515d6a9dc66c11f220960de594334df588776724190109781d68747470733a2f2f776f726c642e6f72672f6561742f74616b742f76313a0001116f480003000007d6010258409a97b6c24c4873234fc4e72a4a239cedec22652cc9206f87a7b9735db9d54885aa069707c532d0ae86c41add78279ac40c949459193361e166c2705d3cca4c05";
    const AAT: &str = "8443a10126a058a3a6034800000000001d6bb6041a6a4d3d8d0a5820000000000000000000000000000000000000000000000000000000000000002a190109781c68747470733a2f2f776f726c642e6f72672f6561742f6161742f76313a0001387f58202bfe8011f17415c59b014210e47d84ff25001d60730b51653a820760c77911d53a000138805820000000000000000000000000000000000000000000000000000000000000000a5840d2a8a0e35f69c266cc55a0ea5b29420cbbbadb5f31d83c7670a9f795192384dcb1068b3ecd721a02a79c1b05b7a13ff458d9358834c9dc5ed2c313a3e2a3f6de";
    const TRUST_ANCHOR_KEY_HASH: &str =
        "14b904063236db16ecda3a3fa9aaa42b3f605706baa2fdb25afeab8df8f252d8";
    const ENTRY_HASHES: [&str; 2] = [
        "24fd129204ff263484224657d234fd2eb3438b02900efdc8d1afb07a81064b03",
        "010cff8544f0007179c076ddb49de551bd5743797bfe05cb3b26f55c696f507b",
    ];

    type Case = (fn(&mut Payload), &'static str);

    /// A `max_bytes` no test request reaches.
    const LIMIT: u64 = 1 << 20;
    const AUD: u64 = 1_928_118;
    const EXPIRES_AT: u64 = 1_783_446_300;
    /// The Verifier's time in the vectors.
    const NOW: u32 = 1_783_446_000;
    /// The vector AAT's `exp`.
    const AAT_EXP: u32 = 1_783_446_925;

    fn hex_field(hex: &str) -> FieldElement {
        FieldElement::from_be_bytes(&hex::decode(hex).unwrap().try_into().unwrap()).unwrap()
    }

    fn sha256_field(data: &[u8]) -> FieldElement {
        FieldElement::from_digest(&Sha256::digest(data).into())
    }

    /// Pipeline 1 of the fixture release, `EXAMPLE<2>(reference#,live#,evidence*)`.
    fn payload() -> Payload {
        Payload {
            pipeline_id: 1,
            strictness: 2,
            entries: vec![
                Some(b"reference image".to_vec()),
                Some(b"live image".to_vec()),
            ],
        }
    }

    fn release(payload: &ManifestPayload) -> ReleaseManifest {
        ReleaseManifest::from_jws(&fixtures::sign(payload)).unwrap()
    }

    /// The AAT over `cdh`, signed with the WIP-106 vector `assertion_key`.
    fn aat_cwt(cdh: FieldElement) -> Vec<u8> {
        let meta = AuthenticatorMeta::new(UserPresence::PresentVerified, 0b01).unwrap();
        let claims = AatClaims::new(NOW, AUD, AAT_EXP, 42u64.into(), cdh, meta).unwrap();
        let assertion_key = SigningKey::from_bytes(&[0x09; 32].into()).unwrap();
        AuthenticatorAssertionToken::sign(claims, &assertion_key)
            .to_cwt()
            .unwrap()
    }

    fn aat_inputs() -> AatInputs {
        AatInputs {
            trust_anchor_key: EdDSAPrivateKey::from_bytes([0x07; 32])
                .public()
                .to_compressed_bytes()
                .unwrap(),
            takt: hex::decode(TAKT).unwrap(),
            aat: hex::decode(AAT).unwrap(),
            min_build_version: 0,
        }
    }

    fn request_for(payload: &Payload, aat: Option<AatInputs>) -> Request {
        Request::new(
            AUD.into(),
            42u64.into(),
            EXPIRES_AT,
            FieldElement::ZERO,
            payload,
            aat,
        )
        .unwrap()
    }

    fn request(aat: Option<AatInputs>) -> Request {
        request_for(&payload(), aat)
    }

    #[test]
    fn payload_matches_the_vector() {
        let request = request(None);
        assert_eq!(hex::encode(&request.payload), PAYLOAD);
        assert_eq!(request.cdh(), hex_field(CDH));
        assert_eq!(hex::encode(aat_cwt(request.cdh())), AAT);
        assert_eq!(Payload::decode(&request.payload), Ok(payload()));
    }

    #[test]
    fn vectors_match_the_spec() {
        let spec = include_str!("../../../docs/WIPs/wip-201.md");
        for vector in [
            format!("payload = {PAYLOAD}"),
            format!("cdh     = 0x{CDH}"),
            format!("aat     = {AAT}"),
        ] {
            assert!(
                spec.contains(&vector),
                "WIP-201 Appendix A1 lacks `{vector}`"
            );
        }
    }

    #[test]
    fn fits_the_release_and_commits_to_its_type() {
        let release = release(&fixtures::payload());
        let commitments = payload().fit(&release).unwrap();
        assert_eq!(
            commitments,
            PayloadCommitments {
                entry_hashes: [
                    hex_field(ENTRY_HASHES[0]),
                    hex_field(ENTRY_HASHES[1]),
                    FieldElement::ZERO,
                    FieldElement::ZERO,
                ],
                pipeline_type: crate::pipeline_type(TYPE),
                engine_config_hash: engine_config_hash(&release.release_hash(), 1, 2),
            }
        );
    }

    /// Appendix A2's pipeline 2: the unlit `evidence` frame is checked but not committed, and
    /// committed roles fill `entry_hash_k` in type order, not input order.
    #[test]
    fn commits_only_committed_roles_in_type_order() {
        let mut manifest = fixtures::payload();
        manifest.pipelines[0].inputs = vec![
            input("evidence", "unlit_frame"),
            input("live", "lit_frame"),
            input("reference", "stored_image"),
        ];
        let release = release(&manifest);
        let payload = Payload {
            entries: vec![
                Some(b"unlit frame".to_vec()),
                Some(b"live image".to_vec()),
                Some(b"reference image".to_vec()),
            ],
            ..payload()
        };
        assert_eq!(
            payload.fit(&release).unwrap().entry_hashes,
            [
                sha256_field(b"reference image"),
                sha256_field(b"live image"),
                FieldElement::ZERO,
                FieldElement::ZERO,
            ]
        );
    }

    #[test]
    fn only_optional_roles_may_be_absent() {
        let mut manifest = fixtures::payload();
        manifest.pipelines[0].type_string = "T<2>(reference#,challenge#?,live#)".into();
        manifest.pipelines[0].inputs = vec![
            input("reference", "stored_image"),
            input("challenge", "stream_frame"),
            input("live", "front_frame"),
        ];
        let release = release(&manifest);
        let with = |challenge: Option<&[u8]>| Payload {
            entries: vec![
                Some(b"reference image".to_vec()),
                challenge.map(<[u8]>::to_vec),
                Some(b"live image".to_vec()),
            ],
            ..payload()
        };
        let hashes = |challenge| with(challenge).fit(&release).unwrap().entry_hashes;
        assert_eq!(hashes(None)[1], FieldElement::ZERO);
        assert_eq!(
            hashes(Some(b"challenge image"))[1],
            sha256_field(b"challenge image")
        );
        assert_eq!(hashes(None)[2], sha256_field(b"live image"));

        let mut no_live = with(None);
        no_live.entries[2] = None;
        assert_eq!(
            no_live.fit(&release),
            Err(RequestError::OutOfBounds("entries"))
        );
    }

    #[test]
    fn rejects_payloads_that_do_not_fit_the_release() {
        let loaded = release(&fixtures::payload());
        let cases: [Case; 5] = [
            (|p| p.pipeline_id = 2, "pipeline_id"),
            (|p| p.strictness = 3, "strictness"),
            (|p| p.strictness = 0, "strictness"),
            (|p| p.entries.push(Some(vec![1])), "entries"),
            (|p| p.entries[1] = None, "entries"),
        ];
        for (change, field) in cases {
            let mut payload = payload();
            change(&mut payload);
            assert_eq!(payload.fit(&loaded), Err(RequestError::OutOfBounds(field)));
        }
        // Inputs past the type's single roles take any number of evidence frames.
        let mut manifest = fixtures::payload();
        manifest.pipelines[0]
            .inputs
            .push(input("evidence", "unlit_frame"));
        let mut payload = payload();
        payload.entries.push(Some(b"unlit frame".to_vec()));
        assert!(payload.fit(&release(&manifest)).is_ok());
    }

    #[test]
    fn verifies_the_vector_aat() {
        let claims = request(Some(aat_inputs()))
            .verify_aat(NOW)
            .unwrap()
            .unwrap();
        assert_eq!(
            claims,
            FlamingoAatClaims {
                trust_anchor_key_hash: hex_field(TRUST_ANCHOR_KEY_HASH),
                aat_flags: 0x00a3_0000_0000_0102,
            }
        );
        assert_eq!(request(None).verify_aat(NOW), Ok(None));
    }

    #[test]
    fn rejects_the_aat_outside_its_validity() {
        let request = request(Some(aat_inputs()));
        assert!(request.verify_aat(AAT_EXP - 1).is_ok());
        // Expired, then too early for the AAT's maximum lifetime.
        for now in [AAT_EXP, 0] {
            assert!(matches!(
                request.verify_aat(now),
                Err(RequestError::AatRejected(_))
            ));
        }
    }

    #[test]
    fn rejects_an_aud_above_u64() {
        let request = Request::new(
            FieldElement::from(u128::from(u64::MAX) + 1),
            42u64.into(),
            EXPIRES_AT,
            FieldElement::ZERO,
            &payload(),
            Some(aat_inputs()),
        )
        .unwrap();
        assert_eq!(
            request.verify_aat(NOW),
            Err(RequestError::OutOfBounds("aud"))
        );
    }

    #[test]
    fn rejects_an_aat_for_another_payload() {
        let mut other = payload();
        other.strictness = 1;
        assert!(matches!(
            request_for(&other, Some(aat_inputs())).verify_aat(NOW),
            Err(RequestError::AatRejected(_))
        ));
    }

    #[test]
    fn requests_round_trip() {
        let mut absent = payload();
        absent.entries[1] = None;
        for request in [
            request(None),
            request(Some(aat_inputs())),
            request_for(&absent, None),
        ] {
            assert_eq!(Request::decode(&request.encode(), LIMIT), Ok(request));
        }
    }

    #[test]
    fn rejects_requests_above_the_limit_before_parsing() {
        let encoded = request(Some(aat_inputs())).encode();
        let len = u64::try_from(encoded.len()).unwrap();
        assert!(Request::decode(&encoded, len).is_ok());
        assert_eq!(
            Request::decode(&encoded, len - 1),
            Err(RequestError::OutOfBounds("request"))
        );
        // Unparseable bytes above the limit are rejected by size, not by the CBOR decoder.
        assert_eq!(
            Request::decode(&[0xff; 64], 63),
            Err(RequestError::OutOfBounds("request"))
        );
    }

    #[test]
    fn rejects_payloads_out_of_bounds() {
        let cases: [Case; 3] = [
            (|p| p.pipeline_id = 0, "pipeline_id"),
            (|p| p.entries.clear(), "entries"),
            (
                |p| p.entries = vec![None; MAX_PIPELINE_INPUTS + 1],
                "entries",
            ),
        ];
        for (change, field) in cases {
            let mut payload = payload();
            change(&mut payload);
            assert_eq!(payload.encode(), Err(RequestError::OutOfBounds(field)));
        }
    }

    #[test]
    fn checks_expiry_against_the_verifier_time() {
        let request = request(None);
        assert_eq!(request.check_expiry(EXPIRES_AT), Ok(()));
        assert_eq!(
            request.check_expiry(EXPIRES_AT - MAX_REQUEST_LIFETIME),
            Ok(())
        );
        for now in [EXPIRES_AT + 1, EXPIRES_AT - MAX_REQUEST_LIFETIME - 1] {
            assert_eq!(
                request.check_expiry(now),
                Err(RequestError::OutOfBounds("expires_at"))
            );
        }
    }

    #[test]
    fn rejects_a_zero_nonce() {
        assert_eq!(
            Request::new(
                1u64.into(),
                FieldElement::ZERO,
                EXPIRES_AT,
                FieldElement::ZERO,
                &payload(),
                None
            ),
            Err(RequestError::OutOfBounds("nonce"))
        );
    }

    #[test]
    fn debug_omits_the_entries() {
        let debug = format!("{:?}", payload());
        assert!(!debug.contains("entries") && debug.contains("strictness: 2"));
    }

    /// Re-encodes a canonical map with its entries reversed.
    fn reversed(bytes: &[u8]) -> Vec<u8> {
        let mut value: Value = cbor::decode(bytes, "test").unwrap();
        if let Value::Map(entries) = &mut value {
            entries.reverse();
        }
        cbor::encode(&value)
    }

    /// Re-encodes a canonical map with `key` set to `value`.
    fn with(bytes: &[u8], key: &str, value: Value) -> Vec<u8> {
        let mut map: Value = cbor::decode(bytes, "test").unwrap();
        if let Value::Map(entries) = &mut map {
            match entries.iter_mut().find(|(k, _)| k.as_text() == Some(key)) {
                Some(entry) => entry.1 = value,
                None => entries.push((Value::Text(key.into()), value)),
            }
        }
        cbor::encode(&map)
    }

    #[test]
    fn rejects_non_canonical_or_foreign_encodings() {
        let encoded = request(Some(aat_inputs())).encode();
        let payload = request(None).payload;
        for bytes in [
            reversed(&encoded),
            with(&encoded, "version", Value::Integer(2.into())),
            with(&encoded, "extra", Value::Integer(1.into())),
            with(&encoded, "aud", Value::Bytes(vec![0xff; 32])),
            with(&encoded, "payload", Value::Bytes(reversed(&payload))),
        ] {
            assert!(matches!(
                Request::decode(&bytes, LIMIT),
                Err(RequestError::Malformed(_))
            ));
        }
        for bytes in [
            reversed(&payload),
            with(&payload, "pipeline_id", Value::Integer(65_536.into())),
            with(&payload, "strictness", Value::Integer(256.into())),
            with(
                &payload,
                "entries",
                Value::Array(vec![Value::Text("0".into())]),
            ),
            with(&payload, "entries", Value::Bytes(vec![1])),
            with(&payload, "hints", Value::Bytes(vec![])),
        ] {
            assert!(matches!(
                Payload::decode(&bytes),
                Err(RequestError::Malformed(_))
            ));
        }
    }
}
