//! Issuer authentication request/response types.

use alloy::primitives::{keccak256, Address};
use alloy::sol_types::{eip712_domain, Eip712Domain, SolStruct};
use alloy::sol;
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use world_id_primitives::rp::RpId;
use world_id_primitives::{FieldElement, PrimitiveError, WorldIdProof};

use ruint::aliases::{U160, U256};

const ISSUER_AUTH_DOMAIN_NAME: &str = "WorldIDIssuerAuth";
const ISSUER_AUTH_DOMAIN_VERSION: &str = "1.0";
const ISSUER_AUTH_RP_ID_DST: &[u8] = b"world-id:issuer-auth";

sol! {
    struct IssuerAuthPayload {
        uint256 issuerSchemaId;
        uint256 action;
        uint256 nonce;
        uint256 createdAt;
        uint256 expiresAt;
    }
}

/// Issuer authentication request version.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerAuthVersion {
    /// Version 1
    V1 = 1,
}

impl serde::Serialize for IssuerAuthVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> serde::Deserialize<'de> for IssuerAuthVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = u8::deserialize(deserializer)?;
        match v {
            1 => Ok(Self::V1),
            _ => Err(serde::de::Error::custom("unsupported version")),
        }
    }
}

/// EIP-712 signature used for issuer auth requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerAuthSignature([u8; 65]);

impl IssuerAuthSignature {
    /// Create a signature from raw bytes (r || s || v).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 65]) -> Self {
        Self(bytes)
    }

    /// Returns the signature bytes (r || s || v).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 65] {
        &self.0
    }

    /// Converts the signature to a k256 (r,s) signature.
    ///
    /// # Errors
    /// Returns an error if the signature bytes are invalid.
    pub fn to_k256_signature(&self) -> Result<K256Signature, PrimitiveError> {
        K256Signature::from_slice(&self.0[..64]).map_err(|e| PrimitiveError::InvalidInput {
            attribute: "issuer_signature".to_string(),
            reason: format!("invalid signature bytes: {e}"),
        })
    }

    /// Recovers the signing address for the given prehash digest.
    ///
    /// # Errors
    /// Returns an error if the signature is invalid or recovery fails.
    pub fn recover_address(&self, digest: [u8; 32]) -> Result<Address, PrimitiveError> {
        let signature = self.to_k256_signature()?;
        let v = self.0[64];
        let normalized_v = match v {
            27 | 28 => v - 27,
            _ => v,
        };
        let recovery_id = RecoveryId::try_from(normalized_v).map_err(|e| {
            PrimitiveError::InvalidInput {
                attribute: "issuer_signature".to_string(),
                reason: format!("invalid recovery id: {e}"),
            }
        })?;
        let verifying_key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
            .map_err(|e| PrimitiveError::InvalidInput {
                attribute: "issuer_signature".to_string(),
                reason: format!("signature recovery failed: {e}"),
            })?;
        let encoded = verifying_key.to_encoded_point(false);
        let pubkey_bytes = encoded.as_bytes();
        let hash = keccak256(&pubkey_bytes[1..]);
        Ok(Address::from_slice(&hash.0[12..]))
    }
}

impl Serialize for IssuerAuthSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(self.0)))
    }
}

impl<'de> Deserialize<'de> for IssuerAuthSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.trim_start_matches("0x");
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 65 {
            return Err(serde::de::Error::custom(
                "invalid signature length: expected 65 bytes",
            ));
        }
        let mut arr = [0u8; 65];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

/// A request from an issuer asking a holder to authenticate ownership of a credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerAuthRequest {
    /// Unique identifier for this request
    pub id: String,
    /// Version of the request
    pub version: IssuerAuthVersion,
    /// Unix timestamp (seconds since epoch) when the request was created
    pub created_at: u64,
    /// Unix timestamp (seconds since epoch) when request expires
    pub expires_at: u64,
    /// Issuer schema id for the credential being authenticated.
    #[serde(with = "world_id_primitives::serde_utils::hex_u64")]
    pub issuer_schema_id: u64,
    /// The registry address used for the issuer EIP-712 domain.
    pub issuer_registry_address: Address,
    /// The issuer signer address expected to have signed this request.
    pub issuer_signer: Address,
    /// The raw representation of the action. This must be already a field element.
    pub action: FieldElement,
    /// Unique nonce for this request (serialized as hex string)
    pub nonce: FieldElement,
    /// Issuer EIP-712 signature over this request.
    pub signature: IssuerAuthSignature,
}

impl IssuerAuthRequest {
    /// Returns true if the request is expired relative to now.
    #[must_use]
    pub const fn is_expired(&self, now: u64) -> bool {
        now > self.expires_at
    }

    /// Returns true if the request was created in the future.
    #[must_use]
    pub const fn is_from_future(&self, now: u64) -> bool {
        self.created_at > now
    }

    /// Compute the EIP-712 domain for this request.
    #[must_use]
    pub fn eip712_domain(&self, chain_id: u64) -> Eip712Domain {
        eip712_domain!(
            name: ISSUER_AUTH_DOMAIN_NAME,
            version: ISSUER_AUTH_DOMAIN_VERSION,
            chain_id: chain_id,
            verifying_contract: self.issuer_registry_address,
        )
    }

    /// Compute the EIP-712 digest hash for this request.
    #[must_use]
    pub fn signing_hash(&self, chain_id: u64) -> [u8; 32] {
        let payload = IssuerAuthPayload {
            issuerSchemaId: U256::from(self.issuer_schema_id),
            action: self.action.into(),
            nonce: self.nonce.into(),
            createdAt: U256::from(self.created_at),
            expiresAt: U256::from(self.expires_at),
        };
        payload.eip712_signing_hash(&self.eip712_domain(chain_id)).0
    }

    /// Verify that the EIP-712 signature matches the expected issuer signer.
    ///
    /// # Errors
    /// Returns an error if signature recovery fails or signer does not match.
    pub fn verify_signature(&self, chain_id: u64) -> Result<(), PrimitiveError> {
        let digest = self.signing_hash(chain_id);
        let recovered = self.signature.recover_address(digest)?;
        if recovered != self.issuer_signer {
            return Err(PrimitiveError::InvalidInput {
                attribute: "issuer_signature".to_string(),
                reason: "signature does not match issuer signer".to_string(),
            });
        }
        Ok(())
    }
}

/// Authentication response returned by the authenticator to the issuer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerAuthResponse {
    /// The response id references request id
    pub id: String,
    /// Version corresponding to request version
    pub version: IssuerAuthVersion,
    /// Query proof payload
    pub proof: WorldIdProof,
    /// Blinded query point used as public input in the query proof.
    pub blinded_query: BlindedQuery,
}

/// Blinded query point (`BabyJubJub` affine) used as a public input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedQuery {
    /// X coordinate (field element)
    pub x: FieldElement,
    /// Y coordinate (field element)
    pub y: FieldElement,
}

/// Derive a deterministic RP id for issuer authentication requests.
#[must_use]
pub fn issuer_auth_rp_id(issuer_schema_id: u64) -> RpId {
    let mut input = Vec::with_capacity(ISSUER_AUTH_RP_ID_DST.len() + 8);
    input.extend_from_slice(ISSUER_AUTH_RP_ID_DST);
    input.extend_from_slice(&issuer_schema_id.to_be_bytes());
    let hash = keccak256(&input);
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&hash.0[12..]);
    RpId::new(U160::from_be_bytes(bytes))
}
