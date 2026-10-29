//! The Verifier request (WIP-201 §4.4.1) with its Engine request (§4.3.1) and optional
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
    FlamingoAatClaims, MAX_COMPARED, MAX_ENTRY_META_BYTES, MAX_HINTS_BYTES, MAX_PIPELINE_INPUTS,
    MAX_REQUEST_LIFETIME, REQUEST_VERSION, release_manifest::Pipeline,
};

/// Why a request could not be encoded, decoded or accepted.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    /// The bytes are not the canonical encoding of the expected map.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// A field is outside the bounds of WIP-201 §4.4.1, or does not match the pipeline.
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
    /// The RP's single-use nonce; nonzero.
    pub nonce: FieldElement,
    /// Unix seconds after which the Verifier rejects the request.
    pub expires_at: u64,
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
        payload: &Payload,
        aat_inputs: Option<AatInputs>,
    ) -> Result<Self, RequestError> {
        let request = Self {
            aud,
            nonce,
            expires_at,
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

/// What the Engine receives, unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    /// The chosen pipeline of the release, nonzero.
    pub pipeline_id: u16,
    /// Matching strictness level defined by the release manifest.
    pub match_strictness: u8,
    /// Request-level Engine hints that never weaken `match_strictness`.
    pub hints: Vec<u8>,
    /// The images or embeddings; each one is a pipeline input, compared, or both.
    pub entries: Vec<Entry>,
    /// Distinct indices into `entries` the pipeline checks, in the order of its `inputs`.
    pub pipeline_inputs: Vec<u8>,
    /// Distinct indices into `entries`; `compare[k]` becomes `compared_entry_hash_k`.
    pub compare: Vec<u8>,
}

/// One Engine input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// An encoded image or an embedding.
    pub data: Vec<u8>,
    /// How the Engine reads `data`.
    pub meta: Vec<u8>,
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
        let hints = fields.byte_string("hints")?;
        let compare = indices(fields.take("compare")?)?;
        let entries = array(fields.take("entries")?)?
            .into_iter()
            .map(Entry::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        let pipeline_id = fields.uint("pipeline_id")?;
        let pipeline_inputs = indices(fields.take("pipeline_inputs")?)?;
        let payload = Self {
            pipeline_id,
            match_strictness: fields.uint("match_strictness")?,
            hints,
            entries,
            pipeline_inputs,
            compare,
        };
        fields.finish()?;
        if cbor::encode(&payload.to_value()) != bytes {
            return Err(RequestError::Malformed("payload"));
        }
        payload.validate()?;
        Ok(payload)
    }

    /// Checks the bounds of WIP-201 §4.3.1.
    ///
    /// # Errors
    /// Returns [`RequestError::OutOfBounds`] naming the first violated field.
    pub fn validate(&self) -> Result<(), RequestError> {
        let bound = |ok: bool, field| {
            if ok {
                Ok(())
            } else {
                Err(RequestError::OutOfBounds(field))
            }
        };
        let distinct_in_range = |list: &[u8]| {
            list.iter().enumerate().all(|(i, index)| {
                !list[..i].contains(index) && usize::from(*index) < self.entries.len()
            })
        };
        bound(self.pipeline_id != 0, "pipeline_id")?;
        bound(self.hints.len() <= MAX_HINTS_BYTES, "hints")?;
        bound(
            self.entries
                .iter()
                .all(|e| e.meta.len() <= MAX_ENTRY_META_BYTES),
            "entries[].meta",
        )?;
        bound(
            !self.pipeline_inputs.is_empty() && distinct_in_range(&self.pipeline_inputs),
            "pipeline_inputs",
        )?;
        bound(
            (2..=MAX_COMPARED).contains(&self.compare.len()) && distinct_in_range(&self.compare),
            "compare",
        )?;
        // An entry that is neither checked nor compared serves no purpose.
        let all_used = (0..self.entries.len()).all(|i| {
            u8::try_from(i)
                .is_ok_and(|i| self.pipeline_inputs.contains(&i) || self.compare.contains(&i))
        });
        bound(all_used, "entries")
    }

    /// `compare_sources` under `pipeline`: byte `k` is `i + 1` if `compare[k]` is
    /// `pipeline_inputs[i]`, else `0`, so RPs see which compared entries the pipeline checked.
    ///
    /// # Errors
    /// Returns [`RequestError::OutOfBounds`] if `pipeline_inputs` does not have the pipeline's
    /// count, or that count does not fit a byte.
    pub fn compare_sources(&self, pipeline: &Pipeline) -> Result<u32, RequestError> {
        let out_of_bounds = || RequestError::OutOfBounds("pipeline_inputs");
        if self.pipeline_inputs.len() != pipeline.inputs.len()
            || pipeline.inputs.len() > MAX_PIPELINE_INPUTS
        {
            return Err(out_of_bounds());
        }
        let mut bytes = [0u8; MAX_COMPARED];
        for (byte, index) in bytes.iter_mut().zip(&self.compare) {
            if let Some(i) = self.pipeline_inputs.iter().position(|i| i == index) {
                *byte = u8::try_from(i + 1).map_err(|_| out_of_bounds())?;
            }
        }
        Ok(u32::from_le_bytes(bytes))
    }

    /// `compared_entry_hash_k = R(SHA-256(entries[compare[k]].data))`, `0` past the last one.
    #[must_use]
    pub fn compared_entry_hashes(&self) -> [FieldElement; MAX_COMPARED] {
        let mut hashes = [FieldElement::ZERO; MAX_COMPARED];
        for (hash, &index) in hashes.iter_mut().zip(&self.compare) {
            if let Some(entry) = self.entries.get(usize::from(index)) {
                *hash = FieldElement::from_digest(&Sha256::digest(&entry.data).into());
            }
        }
        hashes
    }

    fn to_value(&self) -> Value {
        let indices =
            |list: &[u8]| Value::Array(list.iter().map(|&i| Value::Integer(i.into())).collect());
        map(vec![
            ("pipeline_id", Value::Integer(self.pipeline_id.into())),
            (
                "match_strictness",
                Value::Integer(self.match_strictness.into()),
            ),
            ("hints", Value::Bytes(self.hints.clone())),
            (
                "entries",
                Value::Array(self.entries.iter().map(Entry::to_value).collect()),
            ),
            ("pipeline_inputs", indices(&self.pipeline_inputs)),
            ("compare", indices(&self.compare)),
        ])
    }
}

impl Entry {
    fn to_value(&self) -> Value {
        map(vec![
            ("data", Value::Bytes(self.data.clone())),
            ("meta", Value::Bytes(self.meta.clone())),
        ])
    }

    fn from_value(value: Value) -> Result<Self, CborError> {
        let mut fields = Fields::of(value, "payload")?;
        let entry = Self {
            data: fields.byte_string("data")?,
            meta: fields.byte_string("meta")?,
        };
        fields.finish()?;
        Ok(entry)
    }
}

fn array(value: Value) -> Result<Vec<Value>, CborError> {
    value.into_array().map_err(|_| CborError("payload"))
}

fn indices(value: Value) -> Result<Vec<u8>, CborError> {
    array(value)?
        .into_iter()
        .map(|index| {
            index
                .as_integer()
                .and_then(|i| u8::try_from(i).ok())
                .ok_or(CborError("payload"))
        })
        .collect()
}

/// The TAKT, the AAT and the minimum build, as the Authenticator sends them (WIP-201 §4.4.1).
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
    use super::*;
    use world_id_primitives::EdDSAPrivateKey;

    // WIP-201 Appendix A1, "With an AAT".
    const PAYLOAD: &str = "a66568696e74734067636f6d706172658300010267656e747269657383a264646174615063726564656e7469616c20696d616765646d65746140a264646174614a6c69766520696d616765646d65746140a264646174614f6368616c6c656e676520696d616765646d657461406b706970656c696e655f6964016f706970656c696e655f696e707574738101706d617463685f7374726963746e65737302";
    const CDH: &str = "03ca8744a87789b5684fd3569cc3ac735de925464f2cd29e87bdfc2a45591d27";
    const TAKT: &str = "84582aa2013a000100000458202d4bdf6ee60feda0975c770bb7a23dc6e4e0ed1e35ff3c2426cded4ec030d987a05885a4041a6a4e8b7008a101a4010220012158207135fa4fd93a09dce98bbf681b4bfcf50e7c0d6354e62afb0bff2a3429617865225820ed4c1f02ddb9023ee56a557e515d6a9dc66c11f220960de594334df588776724190109781d68747470733a2f2f776f726c642e6f72672f6561742f74616b742f76313a0001116f480003000007d6010258409a97b6c24c4873234fc4e72a4a239cedec22652cc9206f87a7b9735db9d54885aa069707c532d0ae86c41add78279ac40c949459193361e166c2705d3cca4c05";
    const AAT: &str = "8443a10126a058a3a6034800000000001d6bb6041a6a4d3d8d0a5820000000000000000000000000000000000000000000000000000000000000002a190109781c68747470733a2f2f776f726c642e6f72672f6561742f6161742f76313a0001387f582003ca8744a87789b5684fd3569cc3ac735de925464f2cd29e87bdfc2a45591d273a000138805820000000000000000000000000000000000000000000000000000000000000000a58403c24fd0eb59bdcb7ca3177348f69f7ad45affbce19eb3aa85b1a51dcc3499683e84559b276e8bf5d1b6b7e28d2d45dd7ad86eb3e90c09292370f7e2c27feb09f";
    const TRUST_ANCHOR_KEY_HASH: &str =
        "14b904063236db16ecda3a3fa9aaa42b3f605706baa2fdb25afeab8df8f252d8";
    const COMPARED: [&str; 3] = [
        "21e9fe96ff18807a727830c56281c96af824005400bcb8ef0f463b34cb20c415",
        "010cff8544f0007179c076ddb49de551bd5743797bfe05cb3b26f55c696f507b",
        "2abb4a81875eb0e308f0fbfb8c0a0f57e77243e095b145ae7973e0b2771e044d",
    ];

    /// A `max_bytes` no test request reaches.
    const LIMIT: u64 = 1 << 20;

    fn hex_field(hex: &str) -> FieldElement {
        FieldElement::from_be_bytes(&hex::decode(hex).unwrap().try_into().unwrap()).unwrap()
    }

    fn entry(data: &[u8]) -> Entry {
        Entry {
            data: data.to_vec(),
            meta: vec![],
        }
    }

    fn payload() -> Payload {
        Payload {
            pipeline_id: 1,
            match_strictness: 2,
            hints: vec![],
            entries: vec![
                entry(b"credential image"),
                entry(b"live image"),
                entry(b"challenge image"),
            ],
            pipeline_inputs: vec![1],
            compare: vec![0, 1, 2],
        }
    }

    fn aat_inputs() -> AatInputs {
        AatInputs {
            trust_anchor_key: EdDSAPrivateKey::from_bytes([0x07; 32])
                .public()
                .to_compressed_bytes()
                .unwrap(),
            takt: hex::decode(TAKT).unwrap(),
            aat: hex::decode(AAT).unwrap(),
            min_build_version: 2006,
        }
    }

    const EXPIRES_AT: u64 = 1_783_446_300;
    /// The Verifier's time in the vectors.
    const NOW: u32 = 1_783_446_000;

    fn request(aat: Option<AatInputs>) -> Request {
        Request::new(
            1_928_118u64.into(),
            42u64.into(),
            EXPIRES_AT,
            &payload(),
            aat,
        )
        .unwrap()
    }

    #[test]
    fn payload_matches_the_vector() {
        let request = request(None);
        assert_eq!(hex::encode(&request.payload), PAYLOAD);
        assert_eq!(request.cdh(), hex_field(CDH));
        assert_eq!(Payload::decode(&request.payload), Ok(payload()));
    }

    #[test]
    fn compared_entry_hashes_match_the_vector() {
        let hashes = payload().compared_entry_hashes();
        for (hash, expected) in hashes.iter().zip(COMPARED) {
            assert_eq!(*hash, hex_field(expected));
        }
        assert_eq!(hashes[3], FieldElement::ZERO);
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
                aat_flags: 0x00a3_0000_07d6_0102,
            }
        );
        assert_eq!(request(None).verify_aat(NOW), Ok(None));
    }

    #[test]
    fn rejects_the_aat_outside_its_validity() {
        let request = request(Some(aat_inputs()));
        // The vector AAT's `exp`.
        let exp = 1_783_446_925;
        assert!(request.verify_aat(exp - 1).is_ok());
        // Expired, then too early for the AAT's maximum lifetime.
        for now in [exp, 0] {
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
        other.hints = vec![1];
        let request = Request::new(
            1_928_118u64.into(),
            42u64.into(),
            EXPIRES_AT,
            &other,
            Some(aat_inputs()),
        )
        .unwrap();
        assert!(matches!(
            request.verify_aat(NOW),
            Err(RequestError::AatRejected(_))
        ));
    }

    #[test]
    fn requests_round_trip() {
        for request in [request(None), request(Some(aat_inputs()))] {
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

    type Case = (fn(&mut Payload), &'static str);

    #[test]
    fn rejects_payloads_out_of_bounds() {
        let cases: [Case; 11] = [
            (|p| p.pipeline_id = 0, "pipeline_id"),
            (|p| p.hints = vec![0; MAX_HINTS_BYTES + 1], "hints"),
            (
                |p| p.entries[0].meta = vec![0; MAX_ENTRY_META_BYTES + 1],
                "entries[].meta",
            ),
            (|p| p.pipeline_inputs.clear(), "pipeline_inputs"),
            (|p| p.pipeline_inputs = vec![1, 1], "pipeline_inputs"),
            (|p| p.pipeline_inputs = vec![3], "pipeline_inputs"),
            (|p| p.compare.truncate(1), "compare"),
            (|p| p.compare = vec![0, 1, 2, 0, 1], "compare"),
            (|p| p.compare[2] = 0, "compare"),
            (|p| p.compare[0] = 3, "compare"),
            (|p| p.entries.push(entry(b"unused")), "entries"),
        ];
        for (change, field) in cases {
            let mut payload = payload();
            change(&mut payload);
            assert_eq!(payload.encode(), Err(RequestError::OutOfBounds(field)));
        }
    }

    #[test]
    fn derives_compare_sources_under_the_pipeline() {
        let pipeline = crate::release_manifest::fixtures::payload().pipelines[0].clone();
        assert_eq!(payload().compare_sources(&pipeline), Ok(256));

        let mut none_checked = payload();
        none_checked.compare = vec![0, 2];
        assert_eq!(none_checked.compare_sources(&pipeline), Ok(0));
        let mut first = payload();
        first.compare = vec![1, 0, 2];
        assert_eq!(first.compare_sources(&pipeline), Ok(1));

        let mut two_inputs = payload();
        two_inputs.pipeline_inputs.push(2);
        assert_eq!(
            two_inputs.compare_sources(&pipeline),
            Err(RequestError::OutOfBounds("pipeline_inputs"))
        );
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
                &payload(),
                None
            ),
            Err(RequestError::OutOfBounds("nonce"))
        );
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
            with(
                &payload,
                "compare",
                Value::Array(vec![Value::Text("0".into())]),
            ),
            with(&payload, "pipeline_inputs", Value::Integer(1.into())),
        ] {
            assert!(matches!(
                Payload::decode(&bytes),
                Err(RequestError::Malformed(_))
            ));
        }
    }
}
