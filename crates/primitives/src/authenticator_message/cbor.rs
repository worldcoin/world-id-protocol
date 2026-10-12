//! CBOR serialization and bounded decoding.

use serde::{Serialize, de::DeserializeOwned};

const RECURSION_LIMIT: usize = 32;

/// Serializes a value as CBOR using Ciborium.
///
/// Map entries retain the order supplied by `Serialize`. Containers with unknown lengths use
/// indefinite-length encoding. Binary payloads must serialize as bytes, not integer arrays.
/// Transports enforce their own encoded size limits; this function does not validate the schema,
/// reject duplicate keys, or limit nesting.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, MessageError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

/// Decodes exactly one CBOR value using Ciborium, with a byte-size and recursion limit.
///
/// `T` determines the schema and duplicate-field behavior. Ciborium's standard value semantics
/// apply, including support for indefinite lengths and conversion of `undefined` to null.
/// The decoder uses a recursion limit of 32 and rejects any trailing bytes.
pub fn decode<T: DeserializeOwned>(bytes: &[u8], max_size: usize) -> Result<T, MessageError> {
    if bytes.len() > max_size {
        return Err(MessageError::TooLarge);
    }
    let mut remaining = bytes;
    let value = ciborium::de::from_reader_with_recursion_limit(&mut remaining, RECURSION_LIMIT)?;
    if !remaining.is_empty() {
        return Err(MessageError::TrailingData);
    }
    Ok(value)
}

/// A value failed its transport size bound, CBOR encoding rules, or payload schema.
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    /// The transport's encoded message limit was exceeded.
    #[error("CBOR value exceeds transport size limit")]
    TooLarge,
    /// More bytes remain after decoding one value.
    #[error("trailing bytes after CBOR value")]
    TrailingData,
    /// The value could not be serialized as CBOR.
    #[error("CBOR serialization failed: {0}")]
    Serialize(#[from] ciborium::ser::Error<std::io::Error>),
    /// The CBOR input or requested schema could not be decoded.
    #[error("CBOR deserialization failed: {0}")]
    Deserialize(#[from] ciborium::de::Error<std::io::Error>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value;

    #[test]
    fn rejects_trailing_data() {
        assert!(matches!(
            decode::<Value>(&[0xa0, 0], 1024),
            Err(MessageError::TrailingData)
        ));
    }

    #[test]
    fn enforces_size_and_depth_limits() {
        let encoded = encode(&"1.0").unwrap();
        assert!(matches!(
            decode::<Value>(&encoded, encoded.len() - 1),
            Err(MessageError::TooLarge)
        ));
        let mut nested = vec![0x81; RECURSION_LIMIT + 2];
        nested.push(0);
        assert!(matches!(
            decode::<Value>(&nested, 1024),
            Err(MessageError::Deserialize(
                ciborium::de::Error::RecursionLimitExceeded
            ))
        ));
    }
}
