//! Untagged `COSE_Sign1` (RFC 9052) encoding of WIP-106 tokens with `coset` and `ciborium`.
//!
//! Both write deterministic CBOR for the values built here (shortest integer and length forms,
//! map entries in insertion order) but accept other encodings when reading. Decoders
//! therefore check the exact length before parsing and re-encode the result to compare it with
//! the input, so only the canonical encoding is accepted.

use ciborium::Value;
use coset::{CborSerializable, CoseSign1, CoseSign1Builder, Header};

use super::AssertionError;

/// Encodes `value` in deterministic CBOR.
pub(super) fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("writing to a Vec does not fail");
    out
}

/// An untagged `COSE_Sign1` with an empty unprotected header.
pub(super) fn sign1(protected: Header, payload: Vec<u8>, signature: Vec<u8>) -> CoseSign1 {
    CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .signature(signature)
        .build()
}

/// Encodes `sign1`; the protected header is encoded afresh, so it is deterministic CBOR too.
pub(super) fn encode_sign1(sign1: CoseSign1) -> Vec<u8> {
    sign1.to_vec().expect("writing to a Vec does not fail")
}

/// Parses an untagged `COSE_Sign1` of exactly `len` bytes with an empty unprotected header and
/// returns its protected header, parsed payload and signature. Canonical encoding is left to the
/// caller's re-encoding check.
pub(super) fn decode_sign1(
    cwt: &[u8],
    len: usize,
) -> Result<(Header, Value, Vec<u8>), AssertionError> {
    if cwt.len() != len {
        return Err(AssertionError::InvalidEncoding("length"));
    }
    let sign1 =
        CoseSign1::from_slice(cwt).map_err(|_| AssertionError::InvalidEncoding("COSE_Sign1"))?;
    if !sign1.unprotected.is_empty() {
        return Err(AssertionError::InvalidEncoding("unprotected header"));
    }
    let payload = sign1
        .payload
        .and_then(|bytes| ciborium::from_reader(bytes.as_slice()).ok())
        .ok_or(AssertionError::InvalidEncoding("payload"))?;
    Ok((sign1.protected.header, payload, sign1.signature))
}

/// Reads the entries of a CBOR map with integer keys in order.
pub(super) struct Fields {
    entries: std::vec::IntoIter<(Value, Value)>,
    part: &'static str,
}

impl Fields {
    /// Reads `value` as a map; `part` names it in errors.
    pub(super) fn of(value: Value, part: &'static str) -> Result<Self, AssertionError> {
        let entries = value
            .into_map()
            .map_err(|_| AssertionError::InvalidEncoding(part))?;
        Ok(Self {
            entries: entries.into_iter(),
            part,
        })
    }

    /// The value of the next entry, which must have `key`.
    pub(super) fn take(&mut self, key: i64) -> Result<Value, AssertionError> {
        match self.entries.next() {
            Some((k, value)) if k.as_integer() == Some(key.into()) => Ok(value),
            _ => Err(AssertionError::InvalidEncoding(self.part)),
        }
    }

    /// The next entry's value as an integer of type `T`.
    pub(super) fn uint<T: TryFrom<ciborium::value::Integer>>(
        &mut self,
        key: i64,
    ) -> Result<T, AssertionError> {
        let part = self.part;
        self.take(key)?
            .as_integer()
            .and_then(|i| T::try_from(i).ok())
            .ok_or(AssertionError::InvalidEncoding(part))
    }

    /// The next entry's value as a byte string of exactly `N` bytes.
    pub(super) fn bytes<const N: usize>(&mut self, key: i64) -> Result<[u8; N], AssertionError> {
        let part = self.part;
        self.take(key)?
            .into_bytes()
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(AssertionError::InvalidEncoding(part))
    }

    /// The next entry's value as text equal to `expected`.
    pub(super) fn text(&mut self, key: i64, expected: &str) -> Result<(), AssertionError> {
        match self.take(key)?.as_text() {
            Some(text) if text == expected => Ok(()),
            _ => Err(AssertionError::InvalidEncoding(self.part)),
        }
    }

    /// Fails unless every entry was read.
    pub(super) fn finish(mut self) -> Result<(), AssertionError> {
        match self.entries.next() {
            None => Ok(()),
            Some(_) => Err(AssertionError::InvalidEncoding(self.part)),
        }
    }
}
