//! Deterministic CBOR (RFC 8949 §4.2.1) and untagged `COSE_Sign1` (RFC 9052) for the encodings
//! WIPs specify.
//!
//! `ciborium` and `coset` write the shortest integer and length forms but accept other encodings
//! when reading. Decoders therefore read fields in canonical order, then re-encode what they read
//! and compare it with the input, so only the canonical encoding is accepted.

use std::{iter::Peekable, ops::RangeBounds};

pub use ciborium::Value;
use ciborium::value::Integer;
use coset::{CborSerializable as _, CoseSign1, CoseSign1Builder, Header};

/// Bytes that are not the expected CBOR; names the part that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid CBOR in {0}")]
pub struct CborError(pub &'static str);

/// Encodes `value`. Maps built with [`map`] are in deterministic order.
#[must_use]
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("writing to a Vec does not fail");
    out
}

/// Decodes one CBOR item. Trailing bytes and non-canonical forms are left to the caller's
/// re-encoding check.
///
/// # Errors
/// [`CborError`] naming `part` if `bytes` do not start with a CBOR item.
pub fn decode(bytes: &[u8], part: &'static str) -> Result<Value, CborError> {
    ciborium::from_reader(bytes).map_err(|_| CborError(part))
}

/// A map with its entries sorted by the bytes of their encoded keys, as deterministic CBOR
/// requires.
#[must_use]
pub fn map(entries: Vec<(Value, Value)>) -> Value {
    let mut entries: Vec<(Vec<u8>, Value, Value)> = entries
        .into_iter()
        .map(|(key, value)| (encode(&key), key, value))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Value::Map(entries.into_iter().map(|(_, k, v)| (k, v)).collect())
}

/// Reads the entries of a decoded map in canonical order.
pub struct Fields {
    entries: Peekable<std::vec::IntoIter<(Value, Value)>>,
    part: &'static str,
}

impl Fields {
    /// Reads `value` as a map; `part` names it in errors.
    ///
    /// # Errors
    /// [`CborError`] if `value` is not a map.
    pub fn of(value: Value, part: &'static str) -> Result<Self, CborError> {
        let entries = value.into_map().map_err(|_| CborError(part))?;
        Ok(Self {
            entries: entries.into_iter().peekable(),
            part,
        })
    }

    /// The value of the next entry, which must have `key`.
    ///
    /// # Errors
    /// [`CborError`] if the next entry has another key or there is none.
    pub fn take(&mut self, key: impl Into<Value>) -> Result<Value, CborError> {
        let key = key.into();
        match self.entries.next() {
            Some((k, value)) if k == key => Ok(value),
            _ => Err(CborError(self.part)),
        }
    }

    /// The value of the next entry if it has `key`.
    pub fn optional(&mut self, key: impl Into<Value>) -> Option<Value> {
        let key = key.into();
        self.entries
            .next_if(|(k, _)| *k == key)
            .map(|(_, value)| value)
    }

    /// The next entry's value as an integer of type `T`.
    ///
    /// # Errors
    /// [`CborError`] for another key, type or an integer outside `T`.
    pub fn uint<T: TryFrom<Integer>>(&mut self, key: impl Into<Value>) -> Result<T, CborError> {
        let part = self.part;
        self.take(key)?
            .as_integer()
            .and_then(|i| T::try_from(i).ok())
            .ok_or(CborError(part))
    }

    /// The next entry's value as a byte string.
    ///
    /// # Errors
    /// [`CborError`] for another key or type.
    pub fn byte_string(&mut self, key: impl Into<Value>) -> Result<Vec<u8>, CborError> {
        let part = self.part;
        self.take(key)?.into_bytes().map_err(|_| CborError(part))
    }

    /// The next entry's value as a byte string of exactly `N` bytes.
    ///
    /// # Errors
    /// [`CborError`] for another key, type or length.
    pub fn bytes<const N: usize>(&mut self, key: impl Into<Value>) -> Result<[u8; N], CborError> {
        let part = self.part;
        self.byte_string(key)?
            .try_into()
            .map_err(|_| CborError(part))
    }

    /// The next entry's value as text equal to `expected`.
    ///
    /// # Errors
    /// [`CborError`] for another key, type or text.
    pub fn text(&mut self, key: impl Into<Value>, expected: &str) -> Result<(), CborError> {
        match self.take(key)?.as_text() {
            Some(text) if text == expected => Ok(()),
            _ => Err(CborError(self.part)),
        }
    }

    /// Checks that every entry was read.
    ///
    /// # Errors
    /// [`CborError`] if entries remain.
    pub fn finish(mut self) -> Result<(), CborError> {
        match self.entries.next() {
            None => Ok(()),
            Some(_) => Err(CborError(self.part)),
        }
    }
}

/// Encodes an untagged `COSE_Sign1` with an empty unprotected header. The protected header is
/// encoded afresh, so the result is deterministic CBOR.
#[must_use]
pub fn encode_sign1(protected: Header, payload: Vec<u8>, signature: Vec<u8>) -> Vec<u8> {
    CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .signature(signature)
        .build()
        .to_vec()
        .expect("writing to a Vec does not fail")
}

/// Parses an untagged `COSE_Sign1` into its protected header, decoded payload and signature.
///
/// Its length must be in `len` and its unprotected header empty. Canonical encoding is left to
/// the caller's re-encoding check.
///
/// # Errors
/// [`CborError`] for another length or structure, a non-empty unprotected header or a missing
/// payload.
pub fn decode_sign1(
    cwt: &[u8],
    len: impl RangeBounds<usize>,
) -> Result<(Header, Value, Vec<u8>), CborError> {
    if !len.contains(&cwt.len()) {
        return Err(CborError("length"));
    }
    let sign1 = CoseSign1::from_slice(cwt).map_err(|_| CborError("COSE_Sign1"))?;
    if !sign1.unprotected.is_empty() {
        return Err(CborError("unprotected header"));
    }
    let payload = decode(
        sign1.payload.as_deref().ok_or(CborError("payload"))?,
        "payload",
    )?;
    Ok((sign1.protected.header, payload, sign1.signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_sort_by_encoded_key() {
        let value = map(vec![
            ("bb".into(), Value::from(1)),
            ("a".into(), Value::from(2)),
            ("ab".into(), Value::from(3)),
        ]);
        let keys: Vec<_> = value
            .into_map()
            .unwrap()
            .into_iter()
            .map(|(k, _)| k.into_text().unwrap())
            .collect();
        assert_eq!(keys, ["a", "ab", "bb"]);

        // Integer keys: positive before negative, then by magnitude.
        let value = map(vec![
            ((-2).into(), Value::Null),
            (1.into(), Value::Null),
            ((-1).into(), Value::Null),
        ]);
        let keys: Vec<_> = value
            .into_map()
            .unwrap()
            .into_iter()
            .map(|(k, _)| i64::try_from(k.into_integer().unwrap()).unwrap())
            .collect();
        assert_eq!(keys, [1, -1, -2]);
    }

    #[test]
    fn fields_read_in_order_and_reject_leftovers() {
        let value = map(vec![
            ("a".into(), Value::from(7)),
            ("b".into(), Value::Bytes(vec![1, 2])),
            ("c".into(), Value::Text("x".into())),
        ]);
        let mut fields = Fields::of(value.clone(), "test").unwrap();
        assert_eq!(fields.uint::<u8>("a"), Ok(7));
        assert_eq!(fields.optional("z"), None);
        assert_eq!(fields.bytes::<2>("b"), Ok([1, 2]));
        assert_eq!(fields.text("c", "x"), Ok(()));
        assert_eq!(fields.finish(), Ok(()));

        let mut fields = Fields::of(value.clone(), "test").unwrap();
        assert_eq!(fields.take("b"), Err(CborError("test")));
        let mut fields = Fields::of(value, "test").unwrap();
        fields.take("a").unwrap();
        assert_eq!(fields.finish(), Err(CborError("test")));
    }

    #[test]
    fn sign1_round_trips_and_bounds_its_length() {
        let cwt = encode_sign1(Header::default(), encode(&Value::from(1)), vec![9; 4]);
        let (_, payload, signature) = decode_sign1(&cwt, ..=cwt.len()).unwrap();
        assert_eq!(payload, Value::from(1));
        assert_eq!(signature, [9; 4]);
        assert_eq!(decode_sign1(&cwt, ..cwt.len()), Err(CborError("length")));
    }
}
