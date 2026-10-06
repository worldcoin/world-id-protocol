//! The response to a `worldid_auth_v1_register` request (WIP-109 §3.6.2 and §3.6.3).

use serde::{Deserialize, Serialize};
use world_id_primitives::{
    authenticator_message::{ErrorObject, Response},
    serde_utils::{strict_hex_u32, strict_hex_u64},
};

use super::request::AuthenticatorName;

/// The registration response as sent over the bridge.
pub type RegisterResponseMessage = Response<RegistrationResult, RegistrationErrorData>;

/// The result of a successful registration: where the new authenticator was inserted, and the
/// credentials it needs to generate proofs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationResult {
    /// The index of the account the authenticator was registered on.
    #[serde(with = "strict_hex_u64")]
    pub leaf_index: u64,
    /// The slot the authenticator was inserted at.
    #[serde(with = "strict_hex_u32")]
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
    #[serde(with = "strict_hex_u32")]
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
    /// The vault bytes, standard padded base64 on the wire.
    #[serde(with = "base64_standard")]
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

mod base64_standard {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        STANDARD
            .decode(String::deserialize(deserializer)?)
            .map_err(D::Error::custom)
    }
}

/// The machine-readable reason a registration failed, carried in `error.data.reason`.
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
    /// Returns the JSON-RPC error code for this reason.
    #[must_use]
    pub const fn code(self) -> i64 {
        match self {
            Self::InvalidParams | Self::InvalidName => -32602,
            Self::InternalError => -32603,
            Self::UserRejected => 1000,
            Self::NotAuthorized => 1001,
            Self::AuthenticatorConflict => 1002,
            Self::MaxAuthenticatorsReached => 1003,
            Self::OperationFailed => 1004,
            Self::OutcomeUnknown => 1005,
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

    /// Builds the JSON-RPC error object for this reason, with an optional implementation-specific
    /// `detail`.
    #[must_use]
    pub fn into_error(self, detail: Option<String>) -> ErrorObject<RegistrationErrorData> {
        ErrorObject {
            code: self.code(),
            message: self.message().to_string(),
            data: Some(RegistrationErrorData {
                reason: self,
                detail,
            }),
        }
    }
}

/// The `data` member of a registration error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationErrorData {
    /// Why the registration failed.
    pub reason: RegistrationErrorReason,
    /// Optional implementation-specific detail, e.g. a gateway error code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use world_id_primitives::authenticator_message::Id;

    use super::*;

    #[test]
    fn success_matches_the_spec_example() {
        let json = json!({
            "jsonrpc": "2.0",
            "id": "90f2",
            "result": {
                "leaf_index": "0x2a",
                "pubkey_id": "0x1",
                "authenticators": [{ "pubkey_id": "0x0", "name": "iPhone" }],
                "vault": { "format": "walletkit_plaintext_v1", "data": "U1FMaXRl" }
            }
        });
        let response: RegisterResponseMessage = serde_json::from_value(json.clone()).unwrap();
        let result = response.outcome.as_ref().unwrap();
        assert_eq!(result.leaf_index, 42);
        assert_eq!(result.pubkey_id, 1);
        assert_eq!(result.authenticators[0].name.as_str(), "iPhone");
        assert_eq!(result.vault.as_ref().unwrap().data, b"SQLite");
        assert_eq!(serde_json::to_value(&response).unwrap(), json);
    }

    #[test]
    fn minimal_success_omits_optional_members() {
        let response = RegisterResponseMessage {
            id: Id::String("x".into()),
            outcome: Ok(RegistrationResult {
                leaf_index: 1,
                pubkey_id: 0,
                authenticators: Vec::new(),
                vault: None,
            }),
        };
        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            json!({"jsonrpc": "2.0", "id": "x", "result": {"leaf_index": "0x1", "pubkey_id": "0x0"}})
        );
    }

    #[test]
    fn errors_carry_reason_and_code() {
        let response = RegisterResponseMessage {
            id: Id::String("x".into()),
            outcome: Err(RegistrationErrorReason::OperationFailed
                .into_error(Some("transaction_reverted".into()))),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["error"]["code"], 1004);
        assert_eq!(json["error"]["data"]["reason"], "operation_failed");
        assert_eq!(json["error"]["data"]["detail"], "transaction_reverted");
        assert_eq!(
            serde_json::from_value::<RegisterResponseMessage>(json).unwrap(),
            response
        );
    }

    #[test]
    fn result_parsing_is_strict() {
        for result in [
            json!({"leaf_index": "42", "pubkey_id": "0x1"}),
            json!({"leaf_index": "0x2a", "pubkey_id": "0x1", "extra": 1}),
            json!({"leaf_index": "0x2a", "pubkey_id": "0x1", "vault": {"format": "other", "data": ""}}),
            json!({"leaf_index": "0x2a", "pubkey_id": "0x1", "vault": {"format": "walletkit_plaintext_v1", "data": "%%%"}}),
        ] {
            assert!(
                serde_json::from_value::<RegistrationResult>(result.clone()).is_err(),
                "{result}"
            );
        }
    }
}
