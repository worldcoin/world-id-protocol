//! Strict CBOR byte strings for registration wire fields.
use serde::Serializer;

pub mod vec {
    use super::Serializer;
    pub use world_id_primitives::serde_utils::cbor::deserialize_byte_string as deserialize;

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }
}
