//! Strict CBOR byte strings for registration wire fields.
use serde::Serializer;
pub use world_id_primitives::serde_utils::cbor::deserialize_byte_array as deserialize;

pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_bytes(bytes)
}

pub mod vec {
    pub use super::serialize;
    pub use world_id_primitives::serde_utils::cbor::deserialize_byte_string as deserialize;
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct AddressBytes(#[serde(with = "self")] pub [u8; 20]);
