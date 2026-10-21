//! Untagged `COSE_Sign1` (RFC 9052) encoding of WIP-106 tokens with `ciborium`.
//!
//! `ciborium` writes deterministic CBOR for the values built here (shortest integer and length
//! forms, map entries in insertion order) but accepts other encodings when reading. Decoders
//! therefore check the exact length before parsing and re-encode the result to compare it with
//! the input, so only the canonical encoding is accepted.

use ciborium::Value;

use super::AssertionError;

/// A CBOR integer.
pub(super) fn int(value: i64) -> Value {
    Value::Integer(value.into())
}

/// A CBOR map from integer keys.
pub(super) fn map(entries: impl IntoIterator<Item = (i64, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (int(key), value))
            .collect(),
    )
}

/// Encodes `value` in deterministic CBOR.
pub(super) fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("writing to a Vec does not fail");
    out
}

/// The COSE `Sig_structure` (RFC 9052 §4.4) with an empty `external_aad`.
pub(super) fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    encode(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]))
}

/// The parts of a `COSE_Sign1`: protected header and payload as encoded bytes, and the signature.
pub(super) struct Sign1 {
    pub(super) protected: Vec<u8>,
    pub(super) payload: Vec<u8>,
    pub(super) signature: Vec<u8>,
}

impl Sign1 {
    /// Encodes an untagged `COSE_Sign1` with an empty unprotected header.
    pub(super) fn encode(&self) -> Vec<u8> {
        encode(&Value::Array(vec![
            Value::Bytes(self.protected.clone()),
            Value::Map(Vec::new()),
            Value::Bytes(self.payload.clone()),
            Value::Bytes(self.signature.clone()),
        ]))
    }

    /// Parses an untagged `COSE_Sign1` of exactly `len` bytes with an empty unprotected header.
    /// Canonical encoding is left to the caller's re-encoding check.
    pub(super) fn decode(cwt: &[u8], len: usize) -> Result<Self, AssertionError> {
        if cwt.len() != len {
            return Err(AssertionError::InvalidEncoding("length"));
        }
        let value: Value =
            ciborium::from_reader(cwt).map_err(|_| AssertionError::InvalidEncoding("cbor"))?;
        let [protected, unprotected, payload, signature]: [Value; 4] = value
            .into_array()
            .ok()
            .and_then(|items| items.try_into().ok())
            .ok_or(AssertionError::InvalidEncoding("COSE_Sign1"))?;
        if unprotected
            .as_map()
            .is_none_or(|entries| !entries.is_empty())
        {
            return Err(AssertionError::InvalidEncoding("unprotected header"));
        }
        let bytes = |value: Value, part| {
            value
                .into_bytes()
                .map_err(|_| AssertionError::InvalidEncoding(part))
        };
        Ok(Self {
            protected: bytes(protected, "protected header")?,
            payload: bytes(payload, "payload")?,
            signature: bytes(signature, "signature")?,
        })
    }
}

/// Parses `bytes` as a CBOR value.
pub(super) fn decode(bytes: &[u8], part: &'static str) -> Result<Value, AssertionError> {
    ciborium::from_reader(bytes).map_err(|_| AssertionError::InvalidEncoding(part))
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
