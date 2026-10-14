//! The Verifier request (WIP-201 §3.2) and its optional Authenticator Assertion (§3.3).
//!
//! Both the request and its nested `payload` are deterministic CBOR maps. Decoding accepts
//! only the canonical encoding, so `cdh` and every party see the same bytes.

use ciborium::Value;
use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature};
use sha2::{Digest as _, Sha256};
use world_id_primitives::{
    FieldElement,
    authenticator_assertion::{AuthenticatorAssertionPrivateInputs, VerificationError, verify_aat},
};

use crate::{
    AatClaims, MAX_COMPARED, MAX_ENTRIES, MAX_ENTRY_META_BYTES, MAX_HINTS_BYTES, REQUEST_VERSION,
    cbor::{self, Fields},
    digest_to_field,
};

/// Why a request could not be encoded, decoded or accepted.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    /// The bytes are not the canonical encoding of the expected map.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// A field is outside the bounds of WIP-201 §3.2.
    #[error("{0} out of bounds")]
    OutOfBounds(&'static str),
    /// The AAT failed a WIP-106 §3.7 check.
    #[error("AAT rejected: {0}")]
    AatRejected(VerificationError),
}

/// The request the Authenticator seals to the Verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The `rpId` of the request.
    pub aud: FieldElement,
    /// The RP's single-use nonce; nonzero.
    pub nonce: FieldElement,
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
        payload: &Payload,
        aat_inputs: Option<AatInputs>,
    ) -> Result<Self, RequestError> {
        let request = Self {
            aud,
            nonce,
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
            ("aud", field(self.aud)),
            ("nonce", field(self.nonce)),
        ];
        if let Some(aat) = &self.aat_inputs {
            fields.push(("aat_inputs", aat.to_value()));
        }
        cbor::encode(&cbor::map(fields))
    }

    /// Decodes a canonical request and checks its bounds, including the payload's.
    ///
    /// # Errors
    /// Fails for any other encoding, version or shape, or a bound violation.
    pub fn decode(bytes: &[u8]) -> Result<Self, RequestError> {
        let malformed = || RequestError::Malformed("request");
        let value: Value = ciborium::from_reader(bytes).map_err(|_| malformed())?;
        let mut fields = Fields::of(value).ok_or_else(malformed)?;
        if fields.take("version").and_then(|v| cbor::uint::<u64>(&v)) != Some(REQUEST_VERSION) {
            return Err(malformed());
        }
        let request = Self {
            payload: fields
                .take("payload")
                .and_then(|v| v.into_bytes().ok())
                .ok_or_else(malformed)?,
            aud: take_field(&mut fields, "aud").ok_or_else(malformed)?,
            nonce: take_field(&mut fields, "nonce").ok_or_else(malformed)?,
            aat_inputs: fields
                .take("aat_inputs")
                .map(AatInputs::from_value)
                .transpose()?,
        };
        if !fields.is_empty() || request.encode() != bytes {
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
        digest_to_field(&Sha256::digest(&self.payload).into())
    }

    /// Verifies the AAT, if any, against this request and returns the claims it yields.
    ///
    /// # Errors
    /// Returns [`RequestError::AatRejected`] if any WIP-106 §3.7 check fails.
    pub fn verify_aat(&self) -> Result<Option<AatClaims>, RequestError> {
        self.aat_inputs
            .as_ref()
            .map(|aat| aat.verify(self.aud, self.nonce, self.cdh()))
            .transpose()
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
    /// Engine-defined pipeline, nonzero.
    pub pipeline: u16,
    /// Matching strictness level defined by the release manifest.
    pub match_strictness: u8,
    /// Request-level Engine hints that never weaken `match_strictness`.
    pub hints: Vec<u8>,
    /// Inputs to the Engine.
    pub entries: Vec<Entry>,
    /// Distinct indices into `entries`; `compare[k]` becomes `compared_entry_hash_k`.
    pub compare: Vec<u8>,
    /// The `release_hash` of the chosen release manifest.
    pub release_hash: [u8; 32],
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
        let malformed = || RequestError::Malformed("payload");
        let value: Value = ciborium::from_reader(bytes).map_err(|_| malformed())?;
        let mut fields = Fields::of(value).ok_or_else(malformed)?;
        let entries = fields
            .take("entries")
            .and_then(|v| v.into_array().ok())
            .ok_or_else(malformed)?
            .into_iter()
            .map(Entry::from_value)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(malformed)?;
        let compare = fields
            .take("compare")
            .and_then(|v| v.into_array().ok())
            .ok_or_else(malformed)?
            .iter()
            .map(cbor::uint::<u8>)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(malformed)?;
        let payload = Self {
            pipeline: fields
                .take("pipeline")
                .and_then(|v| cbor::uint(&v))
                .ok_or_else(malformed)?,
            match_strictness: fields
                .take("match_strictness")
                .and_then(|v| cbor::uint(&v))
                .ok_or_else(malformed)?,
            hints: fields
                .take("hints")
                .and_then(|v| v.into_bytes().ok())
                .ok_or_else(malformed)?,
            entries,
            compare,
            release_hash: fields
                .take("release_hash")
                .and_then(cbor::array)
                .ok_or_else(malformed)?,
        };
        if !fields.is_empty() || cbor::encode(&payload.to_value()) != bytes {
            return Err(malformed());
        }
        payload.validate()?;
        Ok(payload)
    }

    /// Checks the bounds of WIP-201 §3.2.
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
        bound(self.pipeline != 0, "pipeline")?;
        bound(self.hints.len() <= MAX_HINTS_BYTES, "hints")?;
        bound((1..=MAX_ENTRIES).contains(&self.entries.len()), "entries")?;
        bound(
            self.entries
                .iter()
                .all(|e| e.meta.len() <= MAX_ENTRY_META_BYTES),
            "entries[].meta",
        )?;
        let distinct = self
            .compare
            .iter()
            .enumerate()
            .all(|(i, index)| !self.compare[..i].contains(index));
        let in_range = self
            .compare
            .iter()
            .all(|&index| usize::from(index) < self.entries.len());
        bound(
            (2..=MAX_COMPARED).contains(&self.compare.len()) && distinct && in_range,
            "compare",
        )
    }

    /// `compared_entry_hash_k = R(SHA-256(entries[compare[k]].data))`, `0` past the last one.
    #[must_use]
    pub fn compared_entry_hashes(&self) -> [FieldElement; MAX_COMPARED] {
        let mut hashes = [FieldElement::ZERO; MAX_COMPARED];
        for (hash, &index) in hashes.iter_mut().zip(&self.compare) {
            *hash = digest_to_field(&Sha256::digest(&self.entries[usize::from(index)].data).into());
        }
        hashes
    }

    fn to_value(&self) -> Value {
        cbor::map(vec![
            ("pipeline", Value::Integer(self.pipeline.into())),
            (
                "match_strictness",
                Value::Integer(self.match_strictness.into()),
            ),
            ("hints", Value::Bytes(self.hints.clone())),
            (
                "entries",
                Value::Array(self.entries.iter().map(Entry::to_value).collect()),
            ),
            (
                "compare",
                Value::Array(
                    self.compare
                        .iter()
                        .map(|&i| Value::Integer(i.into()))
                        .collect(),
                ),
            ),
            ("release_hash", Value::Bytes(self.release_hash.to_vec())),
        ])
    }
}

impl Entry {
    fn to_value(&self) -> Value {
        cbor::map(vec![
            ("data", Value::Bytes(self.data.clone())),
            ("meta", Value::Bytes(self.meta.clone())),
        ])
    }

    fn from_value(value: Value) -> Option<Self> {
        let mut fields = Fields::of(value)?;
        let entry = Self {
            data: fields.take("data")?.into_bytes().ok()?,
            meta: fields.take("meta")?.into_bytes().ok()?,
        };
        fields.is_empty().then_some(entry)
    }
}

/// The AAT and the RP's minimum build, as the Authenticator sends them (WIP-201 §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AatInputs {
    /// Compressed Authenticator Provider key.
    pub authenticator_provider_key: [u8; 32],
    /// Expiration, in seconds since the Unix epoch.
    pub exp: u32,
    /// Packed WIP-106 security flags.
    pub sec_flags: u64,
    /// Compressed signature by `authenticator_provider_key`.
    pub sig: [u8; 64],
    /// Blinding factor of the AAT's request commitment.
    pub blind: FieldElement,
    /// Current time, in seconds since the Unix epoch; the RP checks it against its own clock.
    pub now: u32,
    /// The RP's minimum `build_version`; `0` sets no minimum.
    pub min_build_version: u32,
}

impl AatInputs {
    /// Verifies the AAT for a request with `cdh` and returns the claims a token carries.
    ///
    /// # Errors
    /// Returns [`RequestError::AatRejected`] if any WIP-106 §3.7 check fails, and
    /// [`RequestError::Malformed`] for an undecodable key or signature.
    pub fn verify(
        &self,
        aud: FieldElement,
        nonce: FieldElement,
        cdh: FieldElement,
    ) -> Result<AatClaims, RequestError> {
        let malformed = || RequestError::Malformed("aat_inputs");
        let private = AuthenticatorAssertionPrivateInputs {
            authenticator_provider_key: EdDSAPublicKey::from_compressed_bytes(
                self.authenticator_provider_key,
            )
            .map_err(|_| malformed())?,
            exp: self.exp,
            sec_flags: self.sec_flags,
            sig: EdDSASignature::from_compressed_bytes(self.sig).map_err(|_| malformed())?,
            cdh,
            blind: self.blind,
        };
        let public = private
            .public_inputs(self.now, aud, nonce, self.min_build_version)
            .map_err(RequestError::AatRejected)?;
        verify_aat(&public, &private).map_err(RequestError::AatRejected)?;
        Ok(AatClaims {
            authenticator_provider_key_hash: public.authenticator_provider_key_hash,
            aat_flags: u64::from(public.platform)
                | (u64::from(public.sec_level) << 8)
                | (u64::from(public.min_build_version) << 16)
                | (u64::from(public.sec_meta) << 48)
                | (u64::from(u8::from(public.user_presence)) << 51),
            now: public.now,
        })
    }

    fn to_value(self) -> Value {
        cbor::map(vec![
            (
                "authenticator_provider_key",
                Value::Bytes(self.authenticator_provider_key.to_vec()),
            ),
            ("exp", Value::Integer(self.exp.into())),
            ("sec_flags", Value::Integer(self.sec_flags.into())),
            ("sig", Value::Bytes(self.sig.to_vec())),
            ("blind", field(self.blind)),
            ("now", Value::Integer(self.now.into())),
            (
                "min_build_version",
                Value::Integer(self.min_build_version.into()),
            ),
        ])
    }

    fn from_value(value: Value) -> Result<Self, RequestError> {
        let malformed = || RequestError::Malformed("aat_inputs");
        let mut fields = Fields::of(value).ok_or_else(malformed)?;
        let aat = Self {
            authenticator_provider_key: fields
                .take("authenticator_provider_key")
                .and_then(cbor::array)
                .ok_or_else(malformed)?,
            exp: fields
                .take("exp")
                .and_then(|v| cbor::uint(&v))
                .ok_or_else(malformed)?,
            sec_flags: fields
                .take("sec_flags")
                .and_then(|v| cbor::uint(&v))
                .ok_or_else(malformed)?,
            sig: fields
                .take("sig")
                .and_then(cbor::array)
                .ok_or_else(malformed)?,
            blind: take_field(&mut fields, "blind").ok_or_else(malformed)?,
            now: fields
                .take("now")
                .and_then(|v| cbor::uint(&v))
                .ok_or_else(malformed)?,
            min_build_version: fields
                .take("min_build_version")
                .and_then(|v| cbor::uint(&v))
                .ok_or_else(malformed)?,
        };
        if fields.is_empty() {
            Ok(aat)
        } else {
            Err(malformed())
        }
    }
}

/// A field element as its canonical 32-byte big-endian encoding.
fn field(value: FieldElement) -> Value {
    Value::Bytes(value.to_be_bytes().to_vec())
}

/// Takes a canonical 32-byte field element.
fn take_field(fields: &mut Fields, key: &str) -> Option<FieldElement> {
    let bytes = fields.take(key).and_then(cbor::array::<32>)?;
    FieldElement::from_be_bytes(&bytes).ok()
}

#[cfg(test)]
mod tests;
