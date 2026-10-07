//! The response to a `worldid_auth_v1_register` request (WIP-109 §3.6.2 and §3.6.3).

use serde::{Deserialize, Serialize};
use world_id_primitives::authenticator_message::{ErrorObject, Response};

use super::request::AuthenticatorName;

/// The registration response as sent over the bridge.
pub type RegisterResponseMessage = Response<RegistrationResult, RegistrationErrorData>;

/// The result of a successful registration: where the new authenticator was inserted, and the
/// credentials it needs to generate proofs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationResult {
    /// The index of the account the authenticator was registered on.
    pub leaf_index: u64,
    /// The slot the authenticator was inserted at.
    pub pubkey_id: u32,
    /// Names of the account's other authenticators known to the Approving Authenticator.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authenticators: Vec<KnownAuthenticator>,
    /// The account's credential vault, unless the user or Approving Authenticator policy
    /// excluded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<Vault>,
}

/// The name of one of the account's other authenticators.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownAuthenticator {
    /// The slot of the authenticator.
    pub pubkey_id: u32,
    /// The name the Approving Authenticator knows it by.
    pub name: AuthenticatorName,
}

/// A credential vault export.
///
/// The vault holds the account's credentials and the associated data from their issuers, which
/// may include biometric data.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vault {
    /// The format of `data`.
    pub format: VaultFormat,
    /// The vault bytes, a CBOR byte string on the wire.
    #[serde(with = "super::bytes::vec")]
    pub data: Vec<u8>,
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
}

/// The `data` member of a registration error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationErrorData {
    /// Optional implementation-specific detail, e.g. a gateway error code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use world_id_primitives::authenticator_message::{Id, decode, encode};

    #[test]
    fn success_uses_unsigned_indexes_and_raw_vault_bytes() {
        let response = RegisterResponseMessage {
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
