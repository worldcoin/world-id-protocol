#![allow(clippy::unreadable_literal)]

use std::{fmt, str::FromStr};

use alloy::{
    primitives::{Address, B256, U256, keccak256},
    sol_types::{Eip712Domain, SolStruct, eip712_domain},
};
use ark_ff::{BigInteger as _, PrimeField as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use taceo_oprf::types::OprfKeyId;

use crate::{
    ConstraintExpr, ConstraintNode, FieldElement, PrimitiveError, ProofRequest, ProofType,
    RequestVersion, SessionRef,
};

const RP_SIGNATURE_MSG_VERSION: u8 = 0x01;

const SESSION_SEED_OPENING_DOMAIN: &[u8] = b"World ID RP Request V2 session seed opening";

mod sol_types {
    use alloy::sol;

    sol! {
        /// EIP-712 payload signed by an EOA-backed RP for a V2 proof request.
        struct RpRequestV2 {
            uint8 requestVersion;
            uint64 rpId;
            uint160 oprfKeyId;
            uint256 nonce;
            uint64 createdAt;
            uint64 expiresAt;
            uint8 proofType;
            uint8 sessionMode;
            uint8 actionKind;
            uint256 action;
            bytes32 existingSessionSeedAuthorization;
            bytes32 detailsHash;
        }

        struct RpRequestDetailsV2 {
            bytes32 privacySalt;
            string requestId;
            bytes32 sessionRefHash;
            bytes32 requestItemsHash;
            bytes32 constraintsHash;
        }

        struct SessionRefV2 {
            uint8 kind;
            uint256 commitment;
            uint256 oprfSeed;
        }

        struct RpRequestItemV2 {
            string identifier;
            uint64 issuerSchemaId;
            uint8 signalKind;
            bytes32 signalHash;
            uint64 genesisIssuedAtMin;
            uint64 expiresAtMin;
        }

        struct RpRequestItemsV2 {
            bytes32[] items;
        }

        struct ConstraintNodeV2 {
            uint8 kind;
            string identifier;
            bytes32 expressionHash;
        }

        struct ConstraintExprV2 {
            uint8 kind;
            bytes32[] children;
        }

        struct ConstraintRootV2 {
            bool present;
            bytes32 expressionHash;
        }

        struct SessionSeedAuthorizationV2 {
            bytes32 opening;
            uint256 oprfSeed;
        }
    }
}

/// EIP-712 typed-data payload signed by an EOA-backed RP for a V2 request.
pub type RpRequestTypedDataV2 = sol_types::RpRequestV2;

/// The session behavior authorized by an RP request.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpRequestSessionMode {
    /// The request does not involve a session.
    None = 0,
    /// The request authorizes creating a fresh session.
    Create = 1,
    /// The request refers to an existing session.
    Existing = 2,
}

impl From<SessionRef> for RpRequestSessionMode {
    fn from(value: SessionRef) -> Self {
        match value {
            SessionRef::None => Self::None,
            SessionRef::Create => Self::Create,
            SessionRef::Existing(_) => Self::Existing,
        }
    }
}

/// Public, typed V2 RP authorization forwarded to OPRF nodes.
///
/// Private request details are represented only by [`Self::details_hash`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpRequestAuthorizationV2 {
    /// Request schema and authorization version.
    pub request_version: RequestVersion,
    /// Registered relying-party identifier.
    pub rp_id: RpId,
    /// OPRF key selected by the RP request.
    pub oprf_key_id: OprfKeyId,
    /// RP-provided replay nonce.
    pub nonce: FieldElement,
    /// Request creation time in Unix seconds.
    pub created_at: u64,
    /// Request expiration time in Unix seconds.
    pub expires_at: u64,
    /// High-level proof flow.
    pub proof_type: ProofType,
    /// Session behavior authorized by the request.
    pub session_mode: RpRequestSessionMode,
    /// Exact RP action for uniqueness requests; absent for session requests.
    pub action: Option<FieldElement>,
    /// Per-request commitment authorizing rederivation of an existing session seed.
    pub existing_session_seed_authorization: B256,
    /// Salted commitment to all private request semantics.
    pub details_hash: B256,
}

impl RpRequestAuthorizationV2 {
    /// Converts this authorization into its canonical EIP-712 typed-data payload.
    #[must_use]
    pub fn typed_data(&self) -> RpRequestTypedDataV2 {
        let (action_kind, action) = match self.action {
            Some(action) => (1, field_element_to_u256(action)),
            None => (0, U256::ZERO),
        };

        RpRequestTypedDataV2 {
            requestVersion: self.request_version as u8,
            rpId: self.rp_id.into_inner(),
            oprfKeyId: self.oprf_key_id.into_inner(),
            nonce: field_element_to_u256(self.nonce),
            createdAt: self.created_at,
            expiresAt: self.expires_at,
            proofType: self.proof_type as u8,
            sessionMode: self.session_mode as u8,
            actionKind: action_kind,
            action,
            existingSessionSeedAuthorization: self.existing_session_seed_authorization,
            detailsHash: self.details_hash,
        }
    }

    /// Computes the EIP-712 signing hash for this authorization.
    #[must_use]
    pub fn signing_hash(&self, chain_id: u64, rp_registry: Address) -> B256 {
        self.typed_data()
            .eip712_signing_hash(&rp_request_domain_v2(chain_id, rp_registry))
    }
}

/// Returns the EIP-712 domain for V2 RP request authorization.
#[must_use]
pub const fn rp_request_domain_v2(chain_id: u64, rp_registry: Address) -> Eip712Domain {
    eip712_domain!(
        name: "World ID RP Request",
        version: "2",
        chain_id: chain_id,
        verifying_contract: rp_registry,
    )
}

/// Computes the commitment used to authorize one exact existing-session seed.
#[must_use]
pub fn session_seed_authorization_v2(opening: B256, oprf_seed: FieldElement) -> B256 {
    sol_types::SessionSeedAuthorizationV2 {
        opening,
        oprfSeed: field_element_to_u256(oprf_seed),
    }
    .eip712_hash_struct()
}

impl ProofRequest {
    /// Builds the public V2 authorization committed to by the RP signature.
    ///
    /// # Errors
    /// Returns an error if the request is not a structurally valid V2 request.
    pub fn rp_authorization_v2(&self) -> Result<RpRequestAuthorizationV2, PrimitiveError> {
        self.validate_proof_type()?;
        if self.version != RequestVersion::V2 {
            return Err(PrimitiveError::InvalidInput {
                attribute: "version".to_string(),
                reason: "V2 authorization requires request version 2".to_string(),
            });
        }

        let existing_session_seed_authorization = match self.session_id {
            SessionRef::Existing(session_id) => {
                session_seed_authorization_v2(self.session_seed_opening_v2()?, session_id.oprf_seed)
            }
            SessionRef::None | SessionRef::Create => B256::ZERO,
        };

        Ok(RpRequestAuthorizationV2 {
            request_version: self.version,
            rp_id: self.rp_id,
            oprf_key_id: self.oprf_key_id,
            nonce: self.nonce,
            created_at: self.created_at,
            expires_at: self.expires_at,
            proof_type: self.proof_type,
            session_mode: self.session_id.into(),
            action: self.action,
            existing_session_seed_authorization,
            details_hash: self.request_details_hash_v2()?,
        })
    }

    /// Computes the EIP-712 signing hash for this V2 request.
    ///
    /// # Errors
    /// Returns an error if the request is not a structurally valid V2 request.
    pub fn eip712_signing_hash_v2(
        &self,
        chain_id: u64,
        rp_registry: Address,
    ) -> Result<B256, PrimitiveError> {
        Ok(self
            .rp_authorization_v2()?
            .signing_hash(chain_id, rp_registry))
    }

    /// Returns the selective-disclosure opening for an existing session seed.
    ///
    /// The opening is sent to OPRF nodes only when the existing seed must be rederived.
    ///
    /// # Errors
    /// Returns an error if the request is not V2 or has no request salt.
    pub fn session_seed_opening_v2(&self) -> Result<B256, PrimitiveError> {
        if self.version != RequestVersion::V2 {
            return Err(PrimitiveError::InvalidInput {
                attribute: "version".to_string(),
                reason: "session-seed openings require request version 2".to_string(),
            });
        }
        let salt = self
            .request_salt
            .ok_or_else(|| PrimitiveError::InvalidInput {
                attribute: "request_salt".to_string(),
                reason: "must be present for V2 requests".to_string(),
            })?;

        let mut input = Vec::with_capacity(SESSION_SEED_OPENING_DOMAIN.len() + salt.len());
        input.extend_from_slice(SESSION_SEED_OPENING_DOMAIN);
        input.extend_from_slice(salt.as_slice());
        Ok(keccak256(input))
    }

    fn request_details_hash_v2(&self) -> Result<B256, PrimitiveError> {
        let privacy_salt = self
            .request_salt
            .ok_or_else(|| PrimitiveError::InvalidInput {
                attribute: "request_salt".to_string(),
                reason: "must be present for V2 requests".to_string(),
            })?;

        let session_ref_hash = match self.session_id {
            SessionRef::None => sol_types::SessionRefV2 {
                kind: RpRequestSessionMode::None as u8,
                commitment: U256::ZERO,
                oprfSeed: U256::ZERO,
            },
            SessionRef::Create => sol_types::SessionRefV2 {
                kind: RpRequestSessionMode::Create as u8,
                commitment: U256::ZERO,
                oprfSeed: U256::ZERO,
            },
            SessionRef::Existing(session_id) => sol_types::SessionRefV2 {
                kind: RpRequestSessionMode::Existing as u8,
                commitment: field_element_to_u256(session_id.commitment),
                oprfSeed: field_element_to_u256(session_id.oprf_seed),
            },
        }
        .eip712_hash_struct();

        let items = self
            .requests
            .iter()
            .map(|item| {
                let (signal_kind, signal_hash) = match &item.signal {
                    Some(signal) => (1, keccak256(signal)),
                    None => (0, B256::ZERO),
                };
                sol_types::RpRequestItemV2 {
                    identifier: item.identifier.clone(),
                    issuerSchemaId: item.issuer_schema_id,
                    signalKind: signal_kind,
                    signalHash: signal_hash,
                    genesisIssuedAtMin: item.genesis_issued_at_min.unwrap_or(0),
                    expiresAtMin: item.effective_expires_at_min(self.created_at),
                }
                .eip712_hash_struct()
            })
            .collect();
        let request_items_hash = sol_types::RpRequestItemsV2 { items }.eip712_hash_struct();

        let constraints_hash = constraint_root_hash(self.constraints.as_ref());

        Ok(sol_types::RpRequestDetailsV2 {
            privacySalt: privacy_salt,
            requestId: self.id.clone(),
            sessionRefHash: session_ref_hash,
            requestItemsHash: request_items_hash,
            constraintsHash: constraints_hash,
        }
        .eip712_hash_struct())
    }
}

fn constraint_root_hash(constraints: Option<&ConstraintExpr<'_>>) -> B256 {
    sol_types::ConstraintRootV2 {
        present: constraints.is_some(),
        expressionHash: constraints.map_or(B256::ZERO, constraint_expr_hash),
    }
    .eip712_hash_struct()
}

fn constraint_expr_hash(expr: &ConstraintExpr<'_>) -> B256 {
    let (kind, nodes) = match expr {
        ConstraintExpr::All { all } => (0, all),
        ConstraintExpr::Any { any } => (1, any),
        ConstraintExpr::Enumerate { enumerate } => (2, enumerate),
    };
    let children = nodes.iter().map(constraint_node_hash).collect();
    sol_types::ConstraintExprV2 { kind, children }.eip712_hash_struct()
}

fn constraint_node_hash(node: &ConstraintNode<'_>) -> B256 {
    match node {
        ConstraintNode::Type(identifier) => sol_types::ConstraintNodeV2 {
            kind: 0,
            identifier: identifier.to_string(),
            expressionHash: B256::ZERO,
        },
        ConstraintNode::Expr(expr) => sol_types::ConstraintNodeV2 {
            kind: 1,
            identifier: String::new(),
            expressionHash: constraint_expr_hash(expr),
        },
    }
    .eip712_hash_struct()
}

fn field_element_to_u256(value: FieldElement) -> U256 {
    U256::from_be_bytes(value.to_be_bytes())
}

/// The id of a relying party.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RpId(u64);

impl RpId {
    /// Converts the RP id to an u64
    #[must_use]
    pub const fn into_inner(self) -> u64 {
        self.0
    }

    /// Creates a new `RpId` by wrapping a `u64`
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for RpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rp_{:016x}", self.0)
    }
}

impl FromStr for RpId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(id) = s.strip_prefix("rp_") {
            Ok(Self(u64::from_str_radix(id, 16).map_err(|_| {
                "Invalid RP ID format: expected hex string".to_string()
            })?))
        } else {
            Err("A valid RP ID must start with 'rp_'".to_string())
        }
    }
}

impl From<u64> for RpId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<RpId> for FieldElement {
    fn from(value: RpId) -> Self {
        Self::from(value.0)
    }
}

impl Serialize for RpId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            u64::serialize(&self.0, serializer)
        }
    }
}

impl<'de> Deserialize<'de> for RpId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_str(&s).map_err(D::Error::custom)
        } else {
            let value = u64::deserialize(deserializer)?;
            Ok(Self(value))
        }
    }
}

/// Computes the legacy V1 message signed by an RP for a [`ProofRequest`].
///
/// The message format is: `version || nonce || created_at || expires_at || action` (49 - 81 bytes total).
/// - `version`: 1 byte (currently hardcoded to `0x01`)
/// - `nonce`: 32 bytes (big-endian)
/// - `created_at`: 8 bytes (big-endian)
/// - `expires_at`: 8 bytes (big-endian)
/// - `action`: optional (see Session Proofs for more details); 32 bytes (big-endian)
///
/// # Session Proofs
/// V1 Session Proofs don't require the RP to specify an `action`, so the `action` is not included
/// in the signature. For other V1 proofs, the action must always be included, otherwise the OPRF
/// Nodes will reject the request. V2 requests use [`ProofRequest::eip712_signing_hash_v2`].
#[must_use]
pub fn compute_rp_signature_msg(
    nonce: ark_babyjubjub::Fq,
    created_at: u64,
    expires_at: u64,
    action: Option<ark_babyjubjub::Fq>,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(81);
    msg.push(RP_SIGNATURE_MSG_VERSION);
    msg.extend(nonce.into_bigint().to_bytes_be());
    msg.extend(created_at.to_be_bytes());
    msg.extend(expires_at.to_be_bytes());

    if let Some(action) = action {
        msg.extend(action.into_bigint().to_bytes_be());
    }

    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        primitives::{Signature, address},
        signers::{SignerSync as _, local::PrivateKeySigner},
    };
    use std::borrow::Cow;

    use crate::{ConstraintExpr, ConstraintNode, RequestItem, SessionId};

    fn test_v2_request() -> ProofRequest {
        ProofRequest {
            id: "request-123".to_string(),
            version: RequestVersion::V2,
            request_salt: Some(B256::repeat_byte(0x42)),
            proof_type: ProofType::Uniqueness,
            created_at: 1_700_000_000,
            expires_at: 1_700_000_900,
            rp_id: RpId::new(7),
            oprf_key_id: OprfKeyId::new(ruint::uint!(9_U160)),
            session_id: SessionRef::None,
            action: Some(FieldElement::from(11u64)),
            signature: Signature::new(U256::ZERO, U256::ZERO, false),
            nonce: FieldElement::from(13u64),
            requests: vec![
                RequestItem::new(
                    "orb".to_string(),
                    17,
                    Some(b"vote:proposal-1".to_vec()),
                    Some(19),
                    None,
                ),
                RequestItem::new("document".to_string(), 23, None, None, Some(1_700_000_100)),
            ],
            constraints: Some(ConstraintExpr::Any {
                any: vec![
                    ConstraintNode::Type(Cow::Borrowed("orb")),
                    ConstraintNode::Type(Cow::Borrowed("document")),
                ],
            }),
        }
    }

    #[test]
    fn test_rpid_display() {
        let rp_id = RpId::new(0x123456789abcdef0);
        assert_eq!(rp_id.to_string(), "rp_123456789abcdef0");

        let rp_id = RpId::new(u64::MAX);
        assert_eq!(rp_id.to_string(), "rp_ffffffffffffffff");

        let rp_id = RpId::new(0);
        assert_eq!(rp_id.to_string(), "rp_0000000000000000");
    }

    #[test]
    fn test_rpid_from_str() {
        let rp_id = "rp_123456789abcdef0".parse::<RpId>().unwrap();
        assert_eq!(rp_id.0, 0x123456789abcdef0);

        let rp_id = "rp_ffffffffffffffff".parse::<RpId>().unwrap();
        assert_eq!(rp_id.0, u64::MAX);

        let rp_id = "rp_0000000000000000".parse::<RpId>().unwrap();
        assert_eq!(rp_id.0, 0);

        let rp_id = "rp_123456789ABCDEF0".parse::<RpId>().unwrap();
        assert_eq!(rp_id.0, 0x123456789abcdef0);
    }

    #[test]
    fn test_rpid_from_str_errors() {
        assert!("123456789abcdef0".parse::<RpId>().is_err());
        assert!("rp_invalid".parse::<RpId>().is_err());
        assert!("rp_".parse::<RpId>().is_err());
    }

    #[test]
    fn test_rpid_roundtrip() {
        let original = RpId::new(0x123456789abcdef0);
        let s = original.to_string();
        let parsed = s.parse::<RpId>().unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_rpid_json_serialization() {
        let rp_id = RpId::new(0x123456789abcdef0);
        let json = serde_json::to_string(&rp_id).unwrap();
        assert_eq!(json, "\"rp_123456789abcdef0\"");

        let deserialized: RpId = serde_json::from_str(&json).unwrap();
        assert_eq!(rp_id, deserialized);
    }

    #[test]
    fn test_rpid_binary_serialization() {
        let rp_id = RpId::new(0x123456789abcdef0);

        let mut buffer = Vec::new();
        ciborium::into_writer(&rp_id, &mut buffer).unwrap();

        let decoded: RpId = ciborium::from_reader(&buffer[..]).unwrap();

        assert_eq!(rp_id, decoded);
    }

    #[test]
    fn test_compute_rp_signature_msg_fixed_length() {
        // Test with small values that would have leading zeros in variable-length encoding
        // to ensure we always get fixed 32-byte field elements
        let nonce = ark_babyjubjub::Fq::from(1u64);
        let created_at = 1000u64;
        let expires_at = 2000u64;

        let msg = compute_rp_signature_msg(nonce, created_at, expires_at, None);

        // Message must always be exactly 49 bytes if no action is used
        // 1 (version) + 32 (nonce) + 8 (created_at) + 8 (expires_at)
        assert_eq!(
            msg.len(),
            49,
            "RP signature message must be exactly 49 bytes"
        );
        assert_eq!(
            msg[0], RP_SIGNATURE_MSG_VERSION,
            "RP signature message version must be 0x01"
        );
    }

    #[test]
    fn test_compute_rp_signature_msg_with_action() {
        // Test with small values that would have leading zeros in variable-length encoding
        // to ensure we always get fixed 32-byte field elements
        let nonce = ark_babyjubjub::Fq::from(1u64);
        let created_at = 1000u64;
        let expires_at = 2000u64;
        let action = ark_babyjubjub::Fq::from(2u64);

        let msg = compute_rp_signature_msg(nonce, created_at, expires_at, Some(action));

        // Message must be exactly 81 bytes when an action is provided:
        // 1 (version) + 32 (nonce) + 8 (created_at) + 8 (expires_at) + 32 (action)
        assert_eq!(
            msg.len(),
            81,
            "RP signature message must be exactly 81 bytes"
        );
        assert_eq!(
            msg[0], RP_SIGNATURE_MSG_VERSION,
            "RP signature message version must be 0x01"
        );
    }

    #[test]
    fn v2_eip712_golden_vector() {
        let request = test_v2_request();
        let rp_registry = address!("1111111111111111111111111111111111111111");
        let digest = request.eip712_signing_hash_v2(480, rp_registry).unwrap();
        let signer = PrivateKeySigner::from_str(
            "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let signature = signer.sign_hash_sync(&digest).unwrap();

        assert_eq!(
            hex::encode(digest),
            "6186351c03c9588d002b7489ff55c567d50b2cecadca2729573fcc2bd750866b"
        );
        assert_eq!(
            signature.to_string(),
            "0x75e63e6e1874aa4575298bf818cae4be901c4995b9f6719eced33669bdcb128c2fc6734f386b4ded49e54887238840b3722182fa1adf30ee8b4253fdf05406371b"
        );
        assert_eq!(
            signature.recover_address_from_prehash(&digest).unwrap(),
            signer.address()
        );
    }

    #[test]
    fn v2_public_semantic_mutations_change_signing_hash() {
        let request = test_v2_request();
        let rp_registry = address!("1111111111111111111111111111111111111111");
        let authorization = request.rp_authorization_v2().unwrap();
        let original = authorization.signing_hash(480, rp_registry);

        let mutations = [
            RpRequestAuthorizationV2 {
                request_version: RequestVersion::V1,
                ..authorization
            },
            RpRequestAuthorizationV2 {
                rp_id: RpId::new(8),
                ..authorization
            },
            RpRequestAuthorizationV2 {
                oprf_key_id: OprfKeyId::new(ruint::uint!(10_U160)),
                ..authorization
            },
            RpRequestAuthorizationV2 {
                nonce: FieldElement::from(14_u64),
                ..authorization
            },
            RpRequestAuthorizationV2 {
                created_at: authorization.created_at + 1,
                ..authorization
            },
            RpRequestAuthorizationV2 {
                expires_at: authorization.expires_at + 1,
                ..authorization
            },
            RpRequestAuthorizationV2 {
                proof_type: ProofType::Session,
                ..authorization
            },
            RpRequestAuthorizationV2 {
                session_mode: RpRequestSessionMode::Create,
                ..authorization
            },
            RpRequestAuthorizationV2 {
                action: Some(FieldElement::from(12_u64)),
                ..authorization
            },
            RpRequestAuthorizationV2 {
                existing_session_seed_authorization: B256::repeat_byte(0x44),
                ..authorization
            },
            RpRequestAuthorizationV2 {
                details_hash: B256::repeat_byte(0x45),
                ..authorization
            },
        ];

        for mutation in mutations {
            assert_ne!(mutation.signing_hash(480, rp_registry), original);
        }
        assert_ne!(authorization.signing_hash(481, rp_registry), original);
        assert_ne!(
            authorization.signing_hash(480, address!("2222222222222222222222222222222222222222")),
            original
        );
    }

    #[test]
    fn v2_private_semantic_mutations_change_details_hash() {
        let request = test_v2_request();
        let original = request.rp_authorization_v2().unwrap().details_hash;

        let mut changed = request.clone();
        changed.id.push_str("-changed");
        assert_ne!(
            changed.rp_authorization_v2().unwrap().details_hash,
            original
        );

        let mut changed = request.clone();
        changed.requests.swap(0, 1);
        assert_ne!(
            changed.rp_authorization_v2().unwrap().details_hash,
            original
        );

        let mut changed = request.clone();
        changed.requests[0].identifier.push_str("-changed");
        assert_ne!(
            changed.rp_authorization_v2().unwrap().details_hash,
            original
        );

        let mut changed = request.clone();
        changed.requests[0].issuer_schema_id += 1;
        assert_ne!(
            changed.rp_authorization_v2().unwrap().details_hash,
            original
        );

        let mut changed = request.clone();
        changed.requests[0].signal.as_mut().unwrap().push(0);
        assert_ne!(
            changed.rp_authorization_v2().unwrap().details_hash,
            original
        );

        let mut changed = request.clone();
        changed.requests[0].genesis_issued_at_min = Some(20);
        assert_ne!(
            changed.rp_authorization_v2().unwrap().details_hash,
            original
        );

        let mut changed = request.clone();
        changed.requests[0].expires_at_min = Some(request.created_at + 1);
        assert_ne!(
            changed.rp_authorization_v2().unwrap().details_hash,
            original
        );

        let mut changed = request.clone();
        if let Some(ConstraintExpr::Any { any }) = changed.constraints.as_mut() {
            any.swap(0, 1);
        }
        assert_ne!(
            changed.rp_authorization_v2().unwrap().details_hash,
            original
        );

        let mut changed = request;
        changed.request_salt = Some(B256::repeat_byte(0x43));
        assert_ne!(
            changed.rp_authorization_v2().unwrap().details_hash,
            original
        );
    }

    #[test]
    fn v2_effective_timestamp_defaults_are_canonical() {
        let mut implicit = test_v2_request();
        implicit.requests[0].genesis_issued_at_min = None;
        implicit.requests[0].expires_at_min = None;

        let mut explicit = implicit.clone();
        explicit.requests[0].genesis_issued_at_min = Some(0);
        explicit.requests[0].expires_at_min = Some(explicit.created_at);

        assert_eq!(
            implicit.rp_authorization_v2().unwrap().details_hash,
            explicit.rp_authorization_v2().unwrap().details_hash
        );
    }

    #[test]
    fn v2_existing_session_commits_to_both_fields() {
        let mut seed_bytes = [0u8; 32];
        seed_bytes[0] = 1;
        seed_bytes[31] = 5;
        let session_id = SessionId::new(
            FieldElement::from(29u64),
            FieldElement::from_be_bytes(&seed_bytes).unwrap(),
        )
        .unwrap();

        let mut request = test_v2_request();
        request.proof_type = ProofType::Session;
        request.session_id = SessionRef::Existing(session_id);
        request.action = None;
        let authorization = request.rp_authorization_v2().unwrap();

        let mut changed_commitment = request.clone();
        changed_commitment.session_id = SessionRef::Existing(
            SessionId::new(FieldElement::from(30u64), session_id.oprf_seed).unwrap(),
        );
        assert_ne!(
            changed_commitment
                .rp_authorization_v2()
                .unwrap()
                .details_hash,
            authorization.details_hash
        );

        let mut other_seed_bytes = seed_bytes;
        other_seed_bytes[31] = 6;
        let mut changed_seed = request;
        changed_seed.session_id = SessionRef::Existing(
            SessionId::new(
                session_id.commitment,
                FieldElement::from_be_bytes(&other_seed_bytes).unwrap(),
            )
            .unwrap(),
        );
        let changed_authorization = changed_seed.rp_authorization_v2().unwrap();
        assert_ne!(
            changed_authorization.details_hash,
            authorization.details_hash
        );
        assert_ne!(
            changed_authorization.existing_session_seed_authorization,
            authorization.existing_session_seed_authorization
        );
    }
}
