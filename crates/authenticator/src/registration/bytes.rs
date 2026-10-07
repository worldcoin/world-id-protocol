//! Strict CBOR byte strings for registration wire fields.
use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_bytes(bytes)
}

pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    vec::deserialize(deserializer)?
        .try_into()
        .map_err(|_| D::Error::custom("incorrect byte string length"))
}

pub mod vec {
    pub use super::serialize;
    use super::*;

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        match ciborium::Value::deserialize(deserializer)? {
            ciborium::Value::Bytes(bytes) => Ok(bytes),
            _ => Err(D::Error::custom("expected CBOR byte string")),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct AddressBytes(#[serde(with = "self")] pub [u8; 20]);
