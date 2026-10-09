//! The response to a `worldid_auth_v1_register` request (WIP-109 §3.6.2 and §3.6.3).

use serde::{Deserialize, Serialize};
use world_id_primitives::{
    MAX_AUTHENTICATOR_KEYS, TREE_DEPTH,
    authenticator_message::{ErrorObject, Response},
};

use super::request::AuthenticatorName;

/// The registration response as sent over the bridge.
pub type RegisterResponseMessage = Response<RegistrationResult, RegistrationErrorData>;

/// The result of a successful registration: where the new authenticator was inserted, and the
/// credentials it needs to generate proofs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationResult {
    /// The index of the account the authenticator was registered on, from 1 to 2^30 − 1.
    #[serde(serialize_with = "leaf_index::serialize")]
    pub leaf_index: u64,
    /// The slot the authenticator was inserted at, below [`MAX_AUTHENTICATOR_KEYS`].
    #[serde(serialize_with = "pubkey_id::serialize")]
    pub pubkey_id: u32,
    /// Names of the account's other authenticators known to the Approving Authenticator.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authenticators: Vec<KnownAuthenticator>,
    /// The account's credential vault, unless the user or Approving Authenticator policy
    /// excluded it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault: Option<Vault>,
}

/// The name of one of the account's other authenticators.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownAuthenticator {
    /// The slot of the authenticator, below [`MAX_AUTHENTICATOR_KEYS`].
    #[serde(with = "pubkey_id")]
    pub pubkey_id: u32,
    /// The name the Approving Authenticator knows it by.
    pub name: AuthenticatorName,
}

/// A credential vault export.
///
/// The vault holds the account's credentials and the associated data from their issuers, which
/// may include biometric data. Its bytes are zeroized on drop.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vault {
    /// The format of `data`.
    pub format: VaultFormat,
    /// The vault bytes, a CBOR byte string on the wire.
    #[serde(with = "super::bytes::vec")]
    pub data: Vec<u8>,
}

impl Drop for Vault {
    /// The vault may hold biometric data, so its bytes are wiped when dropped.
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.data);
    }
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("format", &self.format)
            .field("len", &self.data.len())
            .finish_non_exhaustive()
    }
}

/// The format of a [`Vault`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultFormat {
    /// The output of WalletKit's `export_vault_for_backup`, to be imported with
    /// `merge_vault_from_backup`.
    #[serde(rename = "walletkit_plaintext_v1")]
    WalletkitPlaintextV1,
}

/// The machine-readable reason a registration failed, carried directly in `error.code`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationErrorReason {
    /// A field is missing or malformed, or a key or address is invalid.
    InvalidParams,
    /// The Approving Authenticator does not accept the requested name.
    InvalidName,
    /// The Approving Authenticator could not complete the request for another reason.
    InternalError,
    /// The user declined.
    UserRejected,
    /// The Approving Authenticator is not an Admin Authenticator of the account.
    NotAuthorized,
    /// The key or address is already registered, but not as requested.
    AuthenticatorConflict,
    /// The account has no free authenticator slot.
    MaxAuthenticatorsReached,
    /// The `InsertAuthenticator` operation definitively failed.
    OperationFailed,
    /// The operation was submitted, but its outcome could not be determined in time.
    OutcomeUnknown,
}

impl RegistrationErrorReason {
    /// Returns the stable message error code for this reason.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidParams => "invalid_params",
            Self::InvalidName => "invalid_name",
            Self::InternalError => "internal_error",
            Self::UserRejected => "user_rejected",
            Self::NotAuthorized => "not_authorized",
            Self::AuthenticatorConflict => "authenticator_conflict",
            Self::MaxAuthenticatorsReached => "max_authenticators_reached",
            Self::OperationFailed => "operation_failed",
            Self::OutcomeUnknown => "outcome_unknown",
        }
    }

    /// Recognizes a registration error code, preserving unknown codes at the envelope layer.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "invalid_params" => Some(Self::InvalidParams),
            "invalid_name" => Some(Self::InvalidName),
            "internal_error" => Some(Self::InternalError),
            "user_rejected" => Some(Self::UserRejected),
            "not_authorized" => Some(Self::NotAuthorized),
            "authenticator_conflict" => Some(Self::AuthenticatorConflict),
            "max_authenticators_reached" => Some(Self::MaxAuthenticatorsReached),
            "operation_failed" => Some(Self::OperationFailed),
            "outcome_unknown" => Some(Self::OutcomeUnknown),
            _ => None,
        }
    }

    /// Builds the message error object for this reason, with an optional implementation-specific
    /// `detail`.
    #[must_use]
    pub fn into_error(self, detail: Option<String>) -> ErrorObject<RegistrationErrorData> {
        ErrorObject {
            code: self.code().into(),
            message: self.message().to_string(),
            data: detail.map(|detail| RegistrationErrorData {
                detail: Some(detail),
            }),
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::InvalidParams => "Invalid params",
            Self::InvalidName => "Name not accepted",
            Self::InternalError => "Internal error",
            Self::UserRejected => "User rejected the registration",
            Self::NotAuthorized => "Not an Admin Authenticator of the account",
            Self::AuthenticatorConflict => "Authenticator already registered differently",
            Self::MaxAuthenticatorsReached => "No free authenticator slot",
            Self::OperationFailed => "InsertAuthenticator operation failed",
            Self::OutcomeUnknown => "InsertAuthenticator outcome unknown",
        }
    }
}

/// The `data` member of a registration error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RegistrationErrorData {
    /// Optional implementation-specific detail, e.g. a gateway error code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRegistrationErrorData {
    #[serde(default, deserialize_with = "super::deserialize_present")]
    detail: Option<String>,
}

impl<'de> Deserialize<'de> for RegistrationErrorData {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire: WireRegistrationErrorData = super::deserialize_payload(deserializer)?;
        Ok(Self {
            detail: wire.detail,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRegistrationResult {
    #[serde(deserialize_with = "leaf_index::deserialize")]
    leaf_index: u64,
    #[serde(deserialize_with = "pubkey_id::deserialize")]
    pubkey_id: u32,
    #[serde(default)]
    authenticators: Vec<KnownAuthenticator>,
    #[serde(default, deserialize_with = "super::deserialize_present")]
    vault: Option<Vault>,
}

impl<'de> Deserialize<'de> for RegistrationResult {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire: WireRegistrationResult = super::deserialize_payload(deserializer)?;
        Ok(Self {
            leaf_index: wire.leaf_index,
            pubkey_id: wire.pubkey_id,
            authenticators: wire.authenticators,
            vault: wire.vault,
        })
    }
}

/// Account indices run from 1 to 2^30 − 1; index 0 is reserved (WIP-100 §3.8, §5.1).
mod leaf_index {
    use serde::{Deserializer, Serializer, de::Error as _, ser::Error as _};

    use super::{TREE_DEPTH, deserialize_unsigned};

    const fn is_valid(index: u64) -> bool {
        index != 0 && index < 1 << TREE_DEPTH
    }

    pub(super) fn serialize<S: Serializer>(index: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        if !is_valid(*index) {
            return Err(S::Error::custom("leaf index out of range"));
        }
        serializer.serialize_u64(*index)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let index = deserialize_unsigned(deserializer)?;
        if !is_valid(index) {
            return Err(D::Error::custom("leaf index out of range"));
        }
        Ok(index)
    }
}

/// Authenticator slots are below `NUM_KEYS` (WIP-100 §3.8).
mod pubkey_id {
    use serde::{Deserializer, Serializer, de::Error as _, ser::Error as _};

    use super::{MAX_AUTHENTICATOR_KEYS, deserialize_unsigned};

    fn is_valid(slot: u32) -> bool {
        usize::try_from(slot).is_ok_and(|slot| slot < MAX_AUTHENTICATOR_KEYS)
    }

    pub(super) fn serialize<S: Serializer>(slot: &u32, serializer: S) -> Result<S::Ok, S::Error> {
        if !is_valid(*slot) {
            return Err(S::Error::custom("pubkey_id out of range"));
        }
        serializer.serialize_u32(*slot)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
        let slot = deserialize_unsigned(deserializer)?;
        if !is_valid(slot) {
            return Err(D::Error::custom("pubkey_id out of range"));
        }
        Ok(slot)
    }
}

fn deserialize_unsigned<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: TryFrom<u64>,
{
    use serde::de::Error as _;
    let ciborium::Value::Integer(integer) = ciborium::Value::deserialize(deserializer)? else {
        return Err(D::Error::custom("expected CBOR unsigned integer"));
    };
    let value =
        u64::try_from(integer).map_err(|_| D::Error::custom("expected unsigned integer"))?;
    T::try_from(value).map_err(|_| D::Error::custom("unsigned integer exceeds field width"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use world_id_primitives::authenticator_message::{Id, Version, decode, encode};

    #[test]
    fn success_uses_unsigned_indexes_and_raw_vault_bytes() {
        let response = RegisterResponseMessage {
            version: Version::V1,
            id: Some(Id::String("request".into())),
            outcome: Ok(RegistrationResult {
                leaf_index: 42,
                pubkey_id: 1,
                authenticators: vec![KnownAuthenticator {
                    pubkey_id: 0,
                    name: "phone".to_string().try_into().unwrap(),
                }],
                vault: Some(Vault {
                    format: VaultFormat::WalletkitPlaintextV1,
                    data: b"SQLite".to_vec(),
                }),
            }),
        };
        let encoded = encode(&response).unwrap();
        assert_eq!(
            decode::<RegisterResponseMessage>(&encoded, 4096).unwrap(),
            response
        );
        let value: ciborium::Value = ciborium::from_reader(encoded.as_slice()).unwrap();
        let result = value
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("result"))
            .unwrap()
            .1
            .as_map()
            .unwrap();
        assert!(
            result
                .iter()
                .find(|(k, _)| k.as_text() == Some("leaf_index"))
                .unwrap()
                .1
                .is_integer()
        );
        let vault = &result
            .iter()
            .find(|(k, _)| k.as_text() == Some("vault"))
            .unwrap()
            .1;
        assert!(
            vault
                .as_map()
                .unwrap()
                .iter()
                .find(|(k, _)| k.as_text() == Some("data"))
                .unwrap()
                .1
                .is_bytes()
        );
    }

    #[test]
    fn errors_use_direct_codes_and_preserve_optional_detail() {
        let error = RegistrationErrorReason::OperationFailed
            .into_error(Some("transaction_reverted".into()));
        assert_eq!(error.code, "operation_failed");
        assert_eq!(
            error.data.unwrap().detail.as_deref(),
            Some("transaction_reverted")
        );
        assert!(
            RegistrationErrorReason::UserRejected
                .into_error(None)
                .data
                .is_none()
        );
        assert_eq!(
            RegistrationErrorReason::from_code("user_rejected"),
            Some(RegistrationErrorReason::UserRejected)
        );
        assert_eq!(RegistrationErrorReason::from_code("future_error"), None);
    }

    #[test]
    fn error_data_must_be_an_untagged_map_without_unknown_fields() {
        use ciborium::Value;
        let data = Value::Map(vec![("detail".into(), "transaction_reverted".into())]);
        assert_eq!(
            data.deserialized::<RegistrationErrorData>().unwrap(),
            RegistrationErrorData {
                detail: Some("transaction_reverted".into())
            }
        );
        for invalid in [
            Value::Tag(0, Box::new(data)),
            Value::Map(vec![("detail".into(), Value::Tag(0, Box::new("x".into())))]),
            Value::Map(vec![("other".into(), "x".into())]),
            Value::Map(vec![("detail".into(), Value::Null)]),
            Value::Null,
        ] {
            assert!(
                invalid.deserialized::<RegistrationErrorData>().is_err(),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn result_rejects_tagged_maps_and_nested_text() {
        use ciborium::Value;
        let result = Value::Map(vec![
            ("leaf_index".into(), 42.into()),
            ("pubkey_id".into(), 1.into()),
        ]);
        assert!(
            Value::Tag(0, Box::new(result))
                .deserialized::<RegistrationResult>()
                .is_err()
        );
        let result = Value::Map(vec![
            ("leaf_index".into(), 42.into()),
            ("pubkey_id".into(), 1.into()),
            (
                "authenticators".into(),
                Value::Array(vec![Value::Map(vec![
                    ("pubkey_id".into(), 0.into()),
                    ("name".into(), Value::Tag(0, Box::new("phone".into()))),
                ])]),
            ),
        ]);
        assert!(result.deserialized::<RegistrationResult>().is_err());
    }

    #[test]
    fn indexes_are_bounded_to_the_protocol_ranges() {
        use ciborium::Value;
        let result = |leaf_index: u64, pubkey_id: u64, known: u64| {
            Value::Map(vec![
                ("leaf_index".into(), leaf_index.into()),
                ("pubkey_id".into(), pubkey_id.into()),
                (
                    "authenticators".into(),
                    Value::Array(vec![Value::Map(vec![
                        ("pubkey_id".into(), known.into()),
                        ("name".into(), "phone".into()),
                    ])]),
                ),
            ])
            .deserialized::<RegistrationResult>()
        };
        let max_leaf = (1 << 30) - 1;
        assert!(result(1, 0, 6).is_ok());
        assert!(result(max_leaf, 6, 0).is_ok());
        for (leaf_index, pubkey_id, known) in [(0, 1, 0), (1 << 30, 1, 0), (42, 7, 0), (42, 1, 7)] {
            assert!(
                result(leaf_index, pubkey_id, known).is_err(),
                "{leaf_index} {pubkey_id} {known}"
            );
        }

        let valid = RegistrationResult {
            leaf_index: 42,
            pubkey_id: 1,
            authenticators: Vec::new(),
            vault: None,
        };
        let encode_result = |result: &RegistrationResult| {
            let mut out = Vec::new();
            ciborium::into_writer(result, &mut out)
        };
        assert!(encode_result(&valid).is_ok());
        for invalid in [
            RegistrationResult {
                leaf_index: 0,
                ..valid.clone()
            },
            RegistrationResult {
                pubkey_id: 7,
                ..valid.clone()
            },
            RegistrationResult {
                authenticators: vec![KnownAuthenticator {
                    pubkey_id: 7,
                    name: "phone".to_string().try_into().unwrap(),
                }],
                ..valid.clone()
            },
        ] {
            assert!(encode_result(&invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn indexes_reject_tags_floats_and_overflow() {
        use ciborium::Value;
        for invalid in [
            Value::Tag(2, Box::new(Value::Bytes(vec![42]))),
            Value::Tag(0, Box::new(Value::Integer(42.into()))),
            Value::Float(42.0),
            Value::Integer((-1).into()),
            Value::Integer((u64::from(u32::MAX) + 1).into()),
        ] {
            let result = Value::Map(vec![
                ("leaf_index".into(), 42.into()),
                ("pubkey_id".into(), invalid),
            ]);
            assert!(result.deserialized::<RegistrationResult>().is_err());
        }
    }

    #[test]
    fn rejects_hex_indexes_and_text_vault() {
        for value in [
            ciborium::Value::Map(vec![
                ("leaf_index".into(), "0x2a".into()),
                ("pubkey_id".into(), 1.into()),
            ]),
            ciborium::Value::Map(vec![
                ("leaf_index".into(), (-1).into()),
                ("pubkey_id".into(), 1.into()),
            ]),
            ciborium::Value::Map(vec![
                ("leaf_index".into(), 42.into()),
                ("pubkey_id".into(), 1.into()),
                (
                    "vault".into(),
                    ciborium::Value::Map(vec![
                        ("format".into(), "walletkit_plaintext_v1".into()),
                        ("data".into(), "U1FMaXRl".into()),
                    ]),
                ),
            ]),
        ] {
            assert!(value.deserialized::<RegistrationResult>().is_err());
        }
    }
}
