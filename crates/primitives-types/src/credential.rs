use serde::{Deserialize, Serialize};

use crate::field_element::FieldElement;
use crate::public_key_bytes::PublicKeyBytes;
use crate::signature_bytes::{
    SignatureBytes, deserialize_optional_signature, serialize_optional_signature,
};

/// Version of the `Credential` object.
#[derive(Default, Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize)]
#[repr(u8)]
pub enum CredentialVersion {
    /// Version 1 of the `Credential`.
    #[default]
    V1 = 1,
}

/// Lightweight mirror of `world_id_primitives::Credential`.
///
/// All fields serialize to the same JSON/CBOR wire format as the canonical
/// type. This struct intentionally carries no crypto logic — it exists
/// solely for (de)serialization by consumers that do not need signing or
/// verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// A reference identifier for the credential.
    pub id: u64,
    /// The version of the Credential determines its structure.
    pub version: CredentialVersion,
    /// Unique issuer schema id.
    pub issuer_schema_id: u64,
    /// The blinded subject (World ID).
    pub sub: FieldElement,
    /// Timestamp of first issuance (unix seconds).
    pub genesis_issued_at: u64,
    /// Expiration timestamp (unix seconds).
    pub expires_at: u64,
    /// Claim hashes.
    pub claims: Vec<FieldElement>,
    /// The commitment to the associated data.
    pub associated_data_hash: FieldElement,
    /// The signature of the credential (signed by the issuer's key).
    #[serde(serialize_with = "serialize_optional_signature")]
    #[serde(deserialize_with = "deserialize_optional_signature")]
    #[serde(default)]
    pub signature: Option<SignatureBytes>,
    /// The public component of the issuer's key.
    pub issuer: PublicKeyBytes,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn sample_credential() -> Credential {
        Credential {
            id: 42,
            version: CredentialVersion::V1,
            issuer_schema_id: 7,
            sub: FieldElement::ONE,
            genesis_issued_at: 1_700_000_000,
            expires_at: 1_800_000_000,
            claims: vec![FieldElement::ZERO, FieldElement::ONE],
            associated_data_hash: FieldElement::ZERO,
            signature: Some(SignatureBytes::from_bytes([0xAA; 64])),
            issuer: PublicKeyBytes::from_bytes([0xBB; 32]),
        }
    }

    #[test]
    fn json_roundtrip() {
        let cred = sample_credential();
        let json = serde_json::to_string(&cred).unwrap();
        let back: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred.id, back.id);
        assert_eq!(cred.version, back.version);
        assert_eq!(cred.sub, back.sub);
        assert_eq!(cred.expires_at, back.expires_at);
        assert_eq!(cred.genesis_issued_at, back.genesis_issued_at);
        assert_eq!(cred.signature, back.signature);
        assert_eq!(cred.issuer, back.issuer);
    }

    #[test]
    fn json_roundtrip_none_signature() {
        let mut cred = sample_credential();
        cred.signature = None;
        let json = serde_json::to_string(&cred).unwrap();
        let back: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(back.signature, None);
    }

    #[test]
    fn cbor_roundtrip() {
        let cred = sample_credential();
        let mut buf = Vec::new();
        ciborium::into_writer(&cred, &mut buf).unwrap();
        let back: Credential = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(cred.id, back.id);
        assert_eq!(cred.sub, back.sub);
        assert_eq!(cred.expires_at, back.expires_at);
    }

    #[test]
    fn credential_version_json_as_string() {
        let v = CredentialVersion::V1;
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "\"V1\"");
        let back: CredentialVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn golden_file_compat() {
        let fixture = include_str!("../tests/fixtures/credential.json");
        let cred: Credential = serde_json::from_str(fixture).unwrap();

        assert_eq!(cred.id, 12345);
        assert_eq!(cred.version, CredentialVersion::V1);
        assert_eq!(cred.issuer_schema_id, 99);
        assert_eq!(cred.genesis_issued_at, 1_700_000_000);
        assert_eq!(cred.expires_at, 1_800_000_000);
        assert_eq!(
            cred.sub,
            FieldElement::from_str(
                "0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2"
            )
            .unwrap()
        );

        // Re-serialize and verify byte-identical JSON
        let reserialized = serde_json::to_string_pretty(&cred).unwrap();
        // Normalize: parse both as serde_json::Value to compare structure
        let orig_value: serde_json::Value = serde_json::from_str(fixture).unwrap();
        let re_value: serde_json::Value = serde_json::from_str(&reserialized).unwrap();
        assert_eq!(orig_value, re_value);
    }
}
