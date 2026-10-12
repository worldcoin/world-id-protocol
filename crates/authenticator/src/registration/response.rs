//! The response to a `worldid_auth_v1_register` request (WIP-109 §3.6.2 and §3.6.3).

use std::fmt;

use serde::{Deserialize, Serialize};
use world_id_primitives::{
    MAX_AUTHENTICATOR_KEYS, TREE_DEPTH,
    authenticator_message::{self, ErrorObject, MessageError, Response, Value},
    serde_utils::deserialize_present,
};
use zeroize::Zeroizing;

use super::{MAX_RESPONSE_SIZE, reject_tags};

/// The largest [`Vault::data`] a registration response carries: 3.5 MiB, so that the encrypted
/// response fits the message-bridge's 5 MiB body limit (WIP-109 §3.6.2).
pub const MAX_VAULT_SIZE: usize = 3_670_016;

/// The format of a [`Vault`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultFormat {
    /// The output of WalletKit's `export_vault_for_backup`, to be imported with
    /// `merge_vault_from_backup`.
    #[serde(rename = "walletkit_plaintext_v1")]
    WalletkitPlaintextV1,
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
    /// The vault bytes, a CBOR byte string of at most [`MAX_VAULT_SIZE`] bytes on the wire.
    #[serde(with = "vault_data")]
    pub data: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("format", &self.format)
            .field("len", &self.data.len())
            .finish_non_exhaustive()
    }
}

/// The name of one of the account's other authenticators.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownAuthenticator {
    /// The slot of the authenticator, below [`MAX_AUTHENTICATOR_KEYS`].
    #[serde(with = "pubkey_id")]
    pub pubkey_id: u32,
    /// The name the Approving Authenticator knows it by. Untrusted text with no length limit of
    /// its own (WIP-109 §3.6.2); the message size limit bounds it.
    pub name: String,
}

/// The result of a successful registration: where the new authenticator was inserted, and the
/// credentials it needs to generate proofs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationResult {
    /// The index of the account the authenticator was registered on, from 1 to 2^30 − 1.
    #[serde(with = "leaf_index")]
    pub leaf_index: u64,
    /// The slot the authenticator was inserted at, below [`MAX_AUTHENTICATOR_KEYS`].
    #[serde(with = "pubkey_id")]
    pub pubkey_id: u32,
    /// Names of the account's other authenticators known to the Approving Authenticator.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authenticators: Vec<KnownAuthenticator>,
    /// The account's credential vault, unless the user or Approving Authenticator policy
    /// excluded it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub vault: Option<Vault>,
}

/// The `data` member of a registration error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationErrorData {
    /// Optional implementation-specific detail, e.g. a gateway error code.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub detail: Option<String>,
}

/// The machine-readable reason a registration failed, carried as its [`code`](Self::code) in
/// `error.code`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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

    /// Returns the reason with the error code `code`, or `None` for a code that WIP-109 does not
    /// define. An unknown code stays available in the [`ErrorObject`].
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

/// The registration response as sent over the bridge.
///
/// Decode it with [`decode_response`], which also rejects the CBOR tags that deserializing the
/// message directly would skip.
pub type RegisterResponseMessage = Response<RegistrationResult, RegistrationErrorData>;

/// Decodes a registration response from the plaintext of
/// [`TransportKey::decrypt_response`](super::TransportKey::decrypt_response).
///
/// The plaintext must hold a single WIP-105 response of at most 3.5 MiB plus 4 KiB (WIP-109
/// §3.5). Its `result` must be a [`RegistrationResult`] and its `error.data`, when present, a
/// [`RegistrationErrorData`], neither with CBOR tags at any depth. Matching the `id` against the
/// request is up to the caller.
///
/// # Errors
///
/// Returns a [`MessageError`] if the plaintext is too large, is not a single CBOR value, or does
/// not match the response schema.
pub fn decode_response(plaintext: &[u8]) -> Result<RegisterResponseMessage, MessageError> {
    let response = authenticator_message::decode(plaintext, MAX_RESPONSE_SIZE)?;
    // Typed decoding skips CBOR tags, so the payload is decoded once more as a `Value` to find
    // them.
    let mut raw: Response<Value, Value> =
        authenticator_message::decode(plaintext, MAX_RESPONSE_SIZE)?;
    let tag_check = match &raw.outcome {
        Ok(result) => reject_tags(result),
        Err(error) => error.data.as_ref().map_or(Ok(()), reject_tags),
    };
    if let Ok(result) = &mut raw.outcome {
        wipe_byte_strings(result);
    }
    tag_check.map(|()| response)
}

/// Wipes every byte string in `value`, which may hold a copy of the vault.
fn wipe_byte_strings(value: &mut Value) {
    match value {
        Value::Bytes(bytes) => zeroize::Zeroize::zeroize(bytes),
        Value::Tag(_, value) => wipe_byte_strings(value),
        Value::Array(values) => values.iter_mut().for_each(wipe_byte_strings),
        Value::Map(entries) => entries.iter_mut().for_each(|(key, value)| {
            wipe_byte_strings(key);
            wipe_byte_strings(value);
        }),
        _ => {}
    }
}

/// Account indices run from 1 to 2^30 − 1; index 0 is reserved (WIP-100 §3.8, §5.1).
mod leaf_index {
    use serde::{Deserializer, Serializer, de::Error as _, ser::Error as _};

    use world_id_primitives::serde_utils::cbor::deserialize_unsigned;

    use super::TREE_DEPTH;

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

/// Authenticator slots are below the registry's `getMaxAuthenticators()` (WIP-109 §3.6.2). Decoding
/// checks [`MAX_AUTHENTICATOR_KEYS`], the most slots an account's key set holds; the Requesting
/// Authenticator checks the actual slot against the registry.
mod pubkey_id {
    use serde::{Deserializer, Serializer, de::Error as _, ser::Error as _};

    use world_id_primitives::serde_utils::cbor::deserialize_unsigned;

    use super::MAX_AUTHENTICATOR_KEYS;

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

/// The vault bytes as a CBOR byte string of at most [`MAX_VAULT_SIZE`] bytes (WIP-109 §3.6.2).
mod vault_data {
    use serde::{Deserializer, Serializer, de::Error as _, ser::Error as _};
    use world_id_primitives::serde_utils::cbor;
    use zeroize::Zeroizing;

    use super::MAX_VAULT_SIZE;

    const TOO_LARGE: &str = "vault data exceeds 3.5 MiB";

    pub(super) fn serialize<S: Serializer>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        if data.len() > MAX_VAULT_SIZE {
            return Err(S::Error::custom(TOO_LARGE));
        }
        serializer.serialize_bytes(data)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Zeroizing<Vec<u8>>, D::Error> {
        let data = Zeroizing::new(cbor::deserialize_byte_string(deserializer)?);
        if data.len() > MAX_VAULT_SIZE {
            return Err(D::Error::custom(TOO_LARGE));
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use world_id_primitives::authenticator_message::{Id, Version, encode};

    use super::*;

    /// Decodes the result of a response whose CBOR `result` is `result`.
    fn decode_result(result: Value) -> Result<RegistrationResult, MessageError> {
        let response = Response::<Value, Value>::builder()
            .id("request".to_string())
            .outcome(Ok(result))
            .build();
        let decoded = decode_response(&encode(&response).unwrap())?;
        Ok(decoded.outcome.expect("a successful response"))
    }

    /// Decodes the error data of an error response whose CBOR `error.data` is `data`.
    fn decode_error_data(data: Value) -> Result<Option<RegistrationErrorData>, MessageError> {
        let error = ErrorObject::builder()
            .code("operation_failed")
            .message("InsertAuthenticator operation failed")
            .data(data)
            .build();
        let response = Response::<Value, Value>::builder()
            .id("request".to_string())
            .outcome(Err(error))
            .build();
        let decoded = decode_response(&encode(&response).unwrap())?;
        Ok(decoded.outcome.expect_err("an error response").data)
    }

    /// A CBOR `result` with the given indexes and no other fields.
    fn result_with_indexes(leaf_index: Value, pubkey_id: Value) -> Value {
        Value::Map(vec![
            ("leaf_index".into(), leaf_index),
            ("pubkey_id".into(), pubkey_id),
        ])
    }

    /// A CBOR `result` with a valid `leaf_index` and `pubkey_id` and `field` set to `value`.
    fn result_with(field: &str, value: Value) -> Value {
        let Value::Map(mut entries) = result_with_indexes(42.into(), 1.into()) else {
            unreachable!("the result is a map")
        };
        entries.push((field.into(), value));
        Value::Map(entries)
    }

    #[test]
    fn result_uses_unsigned_indexes_and_raw_vault_bytes() {
        let result = RegistrationResult {
            leaf_index: 42,
            pubkey_id: 1,
            authenticators: vec![KnownAuthenticator {
                pubkey_id: 0,
                name: "phone".to_string(),
            }],
            vault: Some(Vault {
                format: VaultFormat::WalletkitPlaintextV1,
                data: b"SQLite".to_vec().into(),
            }),
        };
        let wire = Value::Map(vec![
            ("leaf_index".into(), 42.into()),
            ("pubkey_id".into(), 1.into()),
            (
                "authenticators".into(),
                Value::Array(vec![Value::Map(vec![
                    ("pubkey_id".into(), 0.into()),
                    ("name".into(), "phone".into()),
                ])]),
            ),
            (
                "vault".into(),
                Value::Map(vec![
                    ("format".into(), "walletkit_plaintext_v1".into()),
                    ("data".into(), Value::Bytes(b"SQLite".to_vec())),
                ]),
            ),
        ]);
        assert_eq!(Value::serialized(&result).unwrap(), wire);
        assert_eq!(decode_result(wire).unwrap(), result);

        let response = RegisterResponseMessage {
            version: Version::V1,
            id: Some(Id::String("request".into())),
            outcome: Ok(result),
        };
        assert_eq!(
            decode_response(&encode(&response).unwrap()).unwrap(),
            response
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
        let data = Value::Map(vec![("detail".into(), "transaction_reverted".into())]);
        assert_eq!(
            decode_error_data(data.clone()).unwrap(),
            Some(RegistrationErrorData {
                detail: Some("transaction_reverted".into())
            })
        );
        for invalid in [
            Value::Tag(0, Box::new(data)),
            Value::Map(vec![("detail".into(), Value::Tag(0, Box::new("x".into())))]),
            Value::Map(vec![("other".into(), "x".into())]),
            Value::Map(vec![("detail".into(), Value::Null)]),
            Value::Null,
        ] {
            assert!(decode_error_data(invalid.clone()).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn indexes_are_bounded_to_the_protocol_ranges() {
        let max_leaf_index = (1 << 30) - 1;
        let with_known = |leaf_index: u64, pubkey_id: u64, known: u64| {
            let Value::Map(mut entries) = result_with_indexes(leaf_index.into(), pubkey_id.into())
            else {
                unreachable!("the result is a map")
            };
            entries.push((
                "authenticators".into(),
                Value::Array(vec![Value::Map(vec![
                    ("pubkey_id".into(), known.into()),
                    ("name".into(), "phone".into()),
                ])]),
            ));
            Value::Map(entries)
        };
        assert!(decode_result(with_known(1, 0, 6)).is_ok());
        assert!(decode_result(with_known(max_leaf_index, 6, 0)).is_ok());
        for (leaf_index, pubkey_id, known) in [(0, 1, 0), (1 << 30, 1, 0), (42, 7, 0), (42, 1, 7)] {
            assert!(
                decode_result(with_known(leaf_index, pubkey_id, known)).is_err(),
                "{leaf_index} {pubkey_id} {known}"
            );
        }

        let valid = RegistrationResult {
            leaf_index: 42,
            pubkey_id: 1,
            authenticators: Vec::new(),
            vault: None,
        };
        assert!(Value::serialized(&valid).is_ok());
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
                    name: "phone".to_string(),
                }],
                ..valid.clone()
            },
        ] {
            assert!(Value::serialized(&invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn known_authenticator_names_have_no_length_limit() {
        let name = "n".repeat(200);
        let result = decode_result(result_with(
            "authenticators",
            Value::Array(vec![Value::Map(vec![
                ("pubkey_id".into(), 0.into()),
                ("name".into(), name.clone().into()),
            ])]),
        ))
        .unwrap();
        assert_eq!(result.authenticators[0].name, name);
    }

    #[test]
    fn result_rejects_other_cbor_types_and_tags() {
        let vault = |data: Value| {
            Value::Map(vec![
                ("format".into(), "walletkit_plaintext_v1".into()),
                ("data".into(), data),
            ])
        };
        for invalid in [
            Value::Tag(0, result_with_indexes(42.into(), 1.into()).into()),
            result_with_indexes("0x2a".into(), 1.into()),
            result_with_indexes((-1).into(), 1.into()),
            result_with_indexes(42.into(), Value::Float(1.0)),
            result_with_indexes(42.into(), Value::Tag(0, Box::new(1.into()))),
            result_with_indexes(Value::Tag(2, Box::new(Value::Bytes(vec![42]))), 1.into()),
            result_with_indexes(42.into(), (u64::from(u32::MAX) + 1).into()),
            result_with(
                "authenticators",
                Value::Array(vec![Value::Map(vec![
                    ("pubkey_id".into(), 0.into()),
                    ("name".into(), Value::Tag(0, Box::new("phone".into()))),
                ])]),
            ),
            result_with("authenticators", Value::Null),
            result_with("vault", Value::Null),
            result_with("vault", vault("U1FMaXRl".into())),
            result_with("unknown", true.into()),
        ] {
            assert!(decode_result(invalid.clone()).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn vault_data_is_limited_to_3_5_mib() {
        let result = |size| RegistrationResult {
            leaf_index: 42,
            pubkey_id: 1,
            authenticators: Vec::new(),
            vault: Some(Vault {
                format: VaultFormat::WalletkitPlaintextV1,
                data: vec![0; size].into(),
            }),
        };
        let wire = |size| {
            result_with(
                "vault",
                Value::Map(vec![
                    ("format".into(), "walletkit_plaintext_v1".into()),
                    ("data".into(), Value::Bytes(vec![0; size])),
                ]),
            )
        };
        assert_eq!(
            decode_result(wire(MAX_VAULT_SIZE)).unwrap(),
            result(MAX_VAULT_SIZE)
        );
        assert!(decode_result(wire(MAX_VAULT_SIZE + 1)).is_err());
        assert!(Value::serialized(&result(MAX_VAULT_SIZE)).is_ok());
        assert!(Value::serialized(&result(MAX_VAULT_SIZE + 1)).is_err());
    }
}
