#![allow(clippy::unreadable_literal)]

use std::{fmt, str::FromStr};

use alloy::{
    primitives::{Address, B256, U256, keccak256},
    sol_types::{Eip712Domain, SolStruct, eip712_domain},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use taceo_oprf::types::OprfKeyId;

use crate::{
    ConstraintExpr, ConstraintNode, FieldElement, PrimitiveError, ProofRequest, ProofType,
    RequestVersion, SessionRef,
};

const SESSION_SEED_OPENING_DOMAIN: &[u8] = b"World ID RP Request session seed opening";

mod sol_types {
    use alloy::sol;

    sol! {
        /// EIP-712 payload signed by an EOA-backed RP for a proof request.
        struct RpRequest {
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

        struct RpRequestDetails {
            bytes32 privacySalt;
            string requestId;
            bytes32 sessionRefHash;
            bytes32 requestItemsHash;
            bytes32 constraintsHash;
        }

        struct SessionRefDetails {
            uint8 kind;
            uint256 commitment;
            uint256 oprfSeed;
        }

        struct RpRequestItem {
            string identifier;
            uint64 issuerSchemaId;
            uint8 signalKind;
            bytes32 signalHash;
            uint64 genesisIssuedAtMin;
            uint64 expiresAtMin;
        }

        struct RpRequestItems {
            bytes32[] items;
        }

        struct ConstraintNodeDetails {
            uint8 kind;
            string identifier;
            bytes32 expressionHash;
        }

        struct ConstraintExprDetails {
            uint8 kind;
            bytes32[] children;
        }

        struct ConstraintRootDetails {
            bool present;
            bytes32 expressionHash;
        }

        struct SessionSeedAuthorization {
            bytes32 opening;
            uint256 oprfSeed;
        }
    }
}

/// EIP-712 typed-data payload signed by an EOA-backed RP request.
pub type RpRequestTypedData = sol_types::RpRequest;

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

/// Public, typed RP authorization forwarded to OPRF nodes.
///
/// Private request details are represented only by [`Self::details_hash`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpRequestAuthorization {
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

impl RpRequestAuthorization {
    /// Converts this authorization into its canonical EIP-712 typed-data payload.
    #[must_use]
    pub fn typed_data(&self) -> RpRequestTypedData {
        let (action_kind, action) = match self.action {
            Some(action) => (1, field_element_to_u256(action)),
            None => (0, U256::ZERO),
        };

        RpRequestTypedData {
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
            .eip712_signing_hash(&rp_request_domain(chain_id, rp_registry))
    }
}

/// Returns the EIP-712 domain for RP request authorization.
#[must_use]
pub const fn rp_request_domain(chain_id: u64, rp_registry: Address) -> Eip712Domain {
    eip712_domain!(
        name: "World ID RP Request",
        version: "1",
        chain_id: chain_id,
        verifying_contract: rp_registry,
    )
}

/// Computes the commitment used to authorize one exact existing-session seed.
#[must_use]
pub fn session_seed_authorization(opening: B256, oprf_seed: FieldElement) -> B256 {
    sol_types::SessionSeedAuthorization {
        opening,
        oprfSeed: field_element_to_u256(oprf_seed),
    }
    .eip712_hash_struct()
}

impl ProofRequest {
    /// Builds the public authorization committed to by the RP signature.
    ///
    /// # Errors
    /// Returns an error if the request is not structurally valid.
    pub fn rp_authorization(&self) -> Result<RpRequestAuthorization, PrimitiveError> {
        self.validate_proof_type()?;

        let existing_session_seed_authorization = match self.session_id {
            SessionRef::Existing(session_id) => {
                session_seed_authorization(self.session_seed_opening()?, session_id.oprf_seed)
            }
            SessionRef::None | SessionRef::Create => B256::ZERO,
        };

        Ok(RpRequestAuthorization {
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
            details_hash: self.request_details_hash(),
        })
    }

    /// Computes the EIP-712 signing hash for this request.
    ///
    /// # Errors
    /// Returns an error if the request is not structurally valid.
    pub fn eip712_signing_hash(
        &self,
        chain_id: u64,
        rp_registry: Address,
    ) -> Result<B256, PrimitiveError> {
        Ok(self.rp_authorization()?.signing_hash(chain_id, rp_registry))
    }

    /// Returns the selective-disclosure opening for an existing session seed.
    ///
    /// The opening is sent to OPRF nodes only when the existing seed must be rederived.
    ///
    /// # Errors
    /// Returns an error if the request salt is zero.
    pub fn session_seed_opening(&self) -> Result<B256, PrimitiveError> {
        if self.request_salt == B256::ZERO {
            return Err(PrimitiveError::InvalidInput {
                attribute: "request_salt".to_string(),
                reason: "must be non-zero".to_string(),
            });
        }

        let mut input =
            Vec::with_capacity(SESSION_SEED_OPENING_DOMAIN.len() + self.request_salt.len());
        input.extend_from_slice(SESSION_SEED_OPENING_DOMAIN);
        input.extend_from_slice(self.request_salt.as_slice());
        Ok(keccak256(input))
    }

    fn request_details_hash(&self) -> B256 {
        let session_ref_hash = match self.session_id {
            SessionRef::None => sol_types::SessionRefDetails {
                kind: RpRequestSessionMode::None as u8,
                commitment: U256::ZERO,
                oprfSeed: U256::ZERO,
            },
            SessionRef::Create => sol_types::SessionRefDetails {
                kind: RpRequestSessionMode::Create as u8,
                commitment: U256::ZERO,
                oprfSeed: U256::ZERO,
            },
            SessionRef::Existing(session_id) => sol_types::SessionRefDetails {
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
                sol_types::RpRequestItem {
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
        let request_items_hash = sol_types::RpRequestItems { items }.eip712_hash_struct();

        let constraints_hash = constraint_root_hash(self.constraints.as_ref());

        sol_types::RpRequestDetails {
            privacySalt: self.request_salt,
            requestId: self.id.clone(),
            sessionRefHash: session_ref_hash,
            requestItemsHash: request_items_hash,
            constraintsHash: constraints_hash,
        }
        .eip712_hash_struct()
    }
}

fn constraint_root_hash(constraints: Option<&ConstraintExpr<'_>>) -> B256 {
    sol_types::ConstraintRootDetails {
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
    sol_types::ConstraintExprDetails { kind, children }.eip712_hash_struct()
}

fn constraint_node_hash(node: &ConstraintNode<'_>) -> B256 {
    match node {
        ConstraintNode::Type(identifier) => sol_types::ConstraintNodeDetails {
            kind: 0,
            identifier: identifier.to_string(),
            expressionHash: B256::ZERO,
        },
        ConstraintNode::Expr(expr) => sol_types::ConstraintNodeDetails {
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        primitives::{Signature, address},
        signers::{SignerSync as _, local::PrivateKeySigner},
    };
    use std::borrow::Cow;

    use crate::{ConstraintExpr, ConstraintNode, RequestItem, SessionId};

    fn test_request() -> ProofRequest {
        ProofRequest {
            id: "request-123".to_string(),
            version: RequestVersion::V1,
            request_salt: B256::repeat_byte(0x42),
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
    fn eip712_golden_vector() {
        let request = test_request();
        let rp_registry = address!("1111111111111111111111111111111111111111");
        let digest = request.eip712_signing_hash(480, rp_registry).unwrap();
        let signer = PrivateKeySigner::from_str(
            "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let signature = signer.sign_hash_sync(&digest).unwrap();

        assert_eq!(
            hex::encode(digest),
            "ca749586327d7fe36d165c63e886d01c5d57723e89e4c146f0dc0e342dcd8e92"
        );
        assert_eq!(
            signature.to_string(),
            "0x24319295fcaebf1d02ac63e392cbc6f05428e59e85e6ccf1879374cfbb07f17b3f87daf15ad02f857d4c84a0ad4b9eaf36337a2970ab62f5e2ae635b17e91a101c"
        );
        assert_eq!(
            signature.recover_address_from_prehash(&digest).unwrap(),
            signer.address()
        );
    }

    #[test]
    fn public_semantic_mutations_change_signing_hash() {
        let request = test_request();
        let rp_registry = address!("1111111111111111111111111111111111111111");
        let authorization = request.rp_authorization().unwrap();
        let original = authorization.signing_hash(480, rp_registry);

        let mutations = [
            RpRequestAuthorization {
                rp_id: RpId::new(8),
                ..authorization
            },
            RpRequestAuthorization {
                oprf_key_id: OprfKeyId::new(ruint::uint!(10_U160)),
                ..authorization
            },
            RpRequestAuthorization {
                nonce: FieldElement::from(14_u64),
                ..authorization
            },
            RpRequestAuthorization {
                created_at: authorization.created_at + 1,
                ..authorization
            },
            RpRequestAuthorization {
                expires_at: authorization.expires_at + 1,
                ..authorization
            },
            RpRequestAuthorization {
                proof_type: ProofType::Session,
                ..authorization
            },
            RpRequestAuthorization {
                session_mode: RpRequestSessionMode::Create,
                ..authorization
            },
            RpRequestAuthorization {
                action: Some(FieldElement::from(12_u64)),
                ..authorization
            },
            RpRequestAuthorization {
                existing_session_seed_authorization: B256::repeat_byte(0x44),
                ..authorization
            },
            RpRequestAuthorization {
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
    fn private_semantic_mutations_change_details_hash() {
        let request = test_request();
        let original = request.rp_authorization().unwrap().details_hash;

        let mut changed = request.clone();
        changed.id.push_str("-changed");
        assert_ne!(changed.rp_authorization().unwrap().details_hash, original);

        let mut changed = request.clone();
        changed.requests.swap(0, 1);
        assert_ne!(changed.rp_authorization().unwrap().details_hash, original);

        let mut changed = request.clone();
        changed.requests[0].identifier.push_str("-changed");
        assert_ne!(changed.rp_authorization().unwrap().details_hash, original);

        let mut changed = request.clone();
        changed.requests[0].issuer_schema_id += 1;
        assert_ne!(changed.rp_authorization().unwrap().details_hash, original);

        let mut changed = request.clone();
        changed.requests[0].signal.as_mut().unwrap().push(0);
        assert_ne!(changed.rp_authorization().unwrap().details_hash, original);

        let mut changed = request.clone();
        changed.requests[0].genesis_issued_at_min = Some(20);
        assert_ne!(changed.rp_authorization().unwrap().details_hash, original);

        let mut changed = request.clone();
        changed.requests[0].expires_at_min = Some(request.created_at + 1);
        assert_ne!(changed.rp_authorization().unwrap().details_hash, original);

        let mut changed = request.clone();
        if let Some(ConstraintExpr::Any { any }) = changed.constraints.as_mut() {
            any.swap(0, 1);
        }
        assert_ne!(changed.rp_authorization().unwrap().details_hash, original);

        let mut changed = request;
        changed.request_salt = B256::repeat_byte(0x43);
        assert_ne!(changed.rp_authorization().unwrap().details_hash, original);
    }

    #[test]
    fn effective_timestamp_defaults_are_canonical() {
        let mut implicit = test_request();
        implicit.requests[0].genesis_issued_at_min = None;
        implicit.requests[0].expires_at_min = None;

        let mut explicit = implicit.clone();
        explicit.requests[0].genesis_issued_at_min = Some(0);
        explicit.requests[0].expires_at_min = Some(explicit.created_at);

        assert_eq!(
            implicit.rp_authorization().unwrap().details_hash,
            explicit.rp_authorization().unwrap().details_hash
        );
    }

    #[test]
    fn existing_session_commits_to_both_fields() {
        let mut seed_bytes = [0u8; 32];
        seed_bytes[0] = 1;
        seed_bytes[31] = 5;
        let session_id = SessionId::new(
            FieldElement::from(29u64),
            FieldElement::from_be_bytes(&seed_bytes).unwrap(),
        )
        .unwrap();

        let mut request = test_request();
        request.proof_type = ProofType::Session;
        request.session_id = SessionRef::Existing(session_id);
        request.action = None;
        let authorization = request.rp_authorization().unwrap();

        let mut changed_commitment = request.clone();
        changed_commitment.session_id = SessionRef::Existing(
            SessionId::new(FieldElement::from(30u64), session_id.oprf_seed).unwrap(),
        );
        assert_ne!(
            changed_commitment.rp_authorization().unwrap().details_hash,
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
        let changed_authorization = changed_seed.rp_authorization().unwrap();
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
