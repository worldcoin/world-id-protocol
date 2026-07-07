//! ABI-aware decoding of on-chain revert data returned by the WorldID
//! registries (V1 and V2).
//!
//! The gateway's RPC layer receives revert data as ABI-encoded custom errors
//! (a 4-byte selector followed by the ABI-encoded arguments). Without
//! decoding, this surfaces to API callers as an opaque hex blob buried in a
//! JSON-RPC error message. This module extracts that revert data from an
//! alloy transport / contract error, looks up the selector against the V1/V2
//! registry ABIs, and maps it to:
//!
//!   * a [`GatewayErrorCode`] for programmatic handling by callers, and
//!   * a stable human-readable message safe to include in the API response.
//!
//! Callers can also decode raw revert bytes directly via
//! [`DecodedRegistryError::decode`], which is convenient for testing.
//!
//! When decoding fails (unknown selector, malformed data, non-revert error,
//! etc.) callers should fall back to the legacy string-matching path in
//! [`crate::error::parse_contract_error`].

use alloy::{
    sol_types::SolError,
    transports::{RpcError, TransportErrorKind},
};
use world_id_primitives::api_types::GatewayErrorCode;
use world_id_registries::world_id::{
    WorldIdRegistry::WorldIdRegistryErrors, WorldIdRegistryV2::WorldIdRegistryV2Errors,
};

/// A revert whose 4-byte selector was recognised as belonging to one of the
/// registry ABIs.
///
/// The V2 ABI is a strict superset of V1 for the errors the gateway cares
/// about, so lookup is tried V2 → V1 to prefer the richer V2-only variants
/// (e.g. `RecoveryAgentUpdateWindowExpired`) when a shared selector matches
/// both.
///
/// We deliberately don't ABI-decode the *arguments* of the error. Doing so
/// would require constructing every concrete `sol!`-generated error type,
/// which is (a) fragile against ABI additions and (b) unnecessary — the
/// variant name alone is enough to produce a helpful message and error code,
/// and the raw hex is still logged internally for debugging.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DecodedRegistryError {
    variant_name: &'static str,
    source: RegistrySource,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RegistrySource {
    V1,
    V2,
}

impl DecodedRegistryError {
    /// Decode raw revert data (4-byte selector followed by the ABI-encoded
    /// error arguments) into one of the known registry error variants.
    ///
    /// Returns `None` if the data is empty, shorter than a selector, or the
    /// selector is unknown to both registry ABIs.
    #[must_use]
    pub fn decode(data: &[u8]) -> Option<Self> {
        let selector: [u8; 4] = data.get(..4)?.try_into().ok()?;
        Self::from_selector(selector)
    }

    /// Decode a bare 4-byte selector against the known registry ABIs.
    #[must_use]
    pub fn from_selector(selector: [u8; 4]) -> Option<Self> {
        if let Some(name) = WorldIdRegistryV2Errors::name_by_selector(selector) {
            return Some(Self {
                variant_name: name,
                source: RegistrySource::V2,
            });
        }
        if let Some(name) = WorldIdRegistryErrors::name_by_selector(selector) {
            return Some(Self {
                variant_name: name,
                source: RegistrySource::V1,
            });
        }
        None
    }

    /// Extract revert data from an alloy transport error (typically returned
    /// by `provider.call(...)`), and decode it. Returns `None` if the error
    /// does not carry revert data.
    #[must_use]
    pub fn from_transport_error(err: &RpcError<TransportErrorKind>) -> Option<Self> {
        let data = err.as_error_resp().and_then(|e| e.as_revert_data())?;
        Self::decode(&data)
    }

    /// Extract revert data from an alloy contract error (typically returned
    /// by generated `sol!` contract bindings), and decode it.
    #[must_use]
    pub fn from_contract_error(err: &alloy::contract::Error) -> Option<Self> {
        let data = err.as_revert_data()?;
        Self::decode(&data)
    }

    /// The Solidity error variant name (e.g. `"AuthenticatorAlreadyExists"`).
    ///
    /// This is intentionally the raw contract name rather than an English
    /// sentence — it is stable across releases, greppable in logs, and
    /// mirrors the on-chain source. See [`Self::human_message`] for a
    /// user-friendlier variant.
    #[must_use]
    pub const fn variant_name(&self) -> &'static str {
        self.variant_name
    }

    /// A stable, human-readable description of the revert. Prefixed with
    /// `WorldID:` for parity with reverts thrown by the contracts themselves.
    #[must_use]
    pub fn human_message(&self) -> String {
        format!("WorldID: {}", describe(self.variant_name))
    }

    /// Map the decoded error to a [`GatewayErrorCode`]. Errors that don't
    /// have a dedicated code fall through to [`GatewayErrorCode::BadRequest`]
    /// — callers should still surface the [`Self::human_message`] so the
    /// caller sees *what* went wrong, just without a machine-readable code.
    #[must_use]
    pub const fn to_error_code(&self) -> GatewayErrorCode {
        match self.variant_name.as_bytes() {
            b"AuthenticatorAddressAlreadyInUse" | b"AuthenticatorAlreadyExists" => {
                GatewayErrorCode::AuthenticatorAlreadyExists
            }
            b"AuthenticatorDoesNotExist" => GatewayErrorCode::AuthenticatorDoesNotExist,
            b"AuthenticatorDoesNotBelongToAccount" => {
                GatewayErrorCode::AuthenticatorDoesNotBelongToAccount
            }
            b"MismatchedSignatureNonce" => GatewayErrorCode::MismatchedSignatureNonce,
            b"PubkeyIdInUse" => GatewayErrorCode::PubkeyIdInUse,
            b"PubkeyIdOutOfBounds" | b"PubkeyIdOverflow" => GatewayErrorCode::PubkeyIdOutOfBounds,
            b"MethodUnsupported" => GatewayErrorCode::MethodNotAvailable,
            _ => GatewayErrorCode::BadRequest,
        }
    }

    #[cfg(test)]
    pub(crate) const fn is_v2(&self) -> bool {
        matches!(self.source, RegistrySource::V2)
    }
}

/// Map a raw Solidity error name to a short, human-readable description.
/// Unknown names fall through to the raw name — that's still strictly better
/// than surfacing the hex selector to callers.
fn describe(name: &str) -> &str {
    match name {
        // Ownership / lookup
        "AccountDoesNotExist" => "account does not exist for the given leaf index",
        "AuthenticatorAddressAlreadyInUse" => {
            "authenticator address is already in use by another account"
        }
        "AuthenticatorAlreadyExists" => "authenticator already exists on this account",
        "AuthenticatorClassMismatch" => "authenticator class does not match",
        "AuthenticatorDoesNotBelongToAccount" => {
            "authenticator does not belong to the specified account"
        }
        "AuthenticatorDoesNotExist" => "authenticator does not exist on this account",
        "OwnerMaxAuthenticatorsOutOfBounds" => {
            "account already has the maximum number of authenticators"
        }

        // Signature / nonce
        "ECDSAInvalidSignature" => "invalid ECDSA signature",
        "ECDSAInvalidSignatureLength" => "invalid ECDSA signature length",
        "ECDSAInvalidSignatureS" => "invalid ECDSA signature `s` value",
        "InvalidSignature" => "invalid signature",
        "MismatchedAuthenticatorSigner" => {
            "signature was not produced by an authenticator on this account"
        }
        "MismatchedSignatureNonce" => "signature nonce does not match the on-chain value",
        "ZeroRecoveredSignatureAddress" => "signature recovered to the zero address",

        // Pubkey slots
        "PubkeyIdDoesNotExist" => "pubkey id does not exist on this account",
        "PubkeyIdInUse" => "pubkey id slot is already in use",
        "PubkeyIdOutOfBounds" => "pubkey id is out of bounds",
        "PubkeyIdOverflow" => "pubkey id overflow",
        "MismatchedPubkeyId" => "pubkey id does not match the on-chain value",

        // Leaf / merkle
        "LeafIndexOutOfRange" => "leaf index is out of range",
        "MismatchedLeafIndex" => "leaf index does not match the on-chain value",
        "UnknownRoot" => "root is not known to the registry",
        "WrongDefaultZeroIndex" => "wrong default-zero merkle index",

        // Recovery
        "MismatchedRecoveryCounter" => "recovery counter does not match the on-chain value",
        "NoActiveRecoveryAgentUpdate" => "no active recovery agent update to revert",
        "NoPendingRecoveryAgentUpdate" => "no pending recovery agent update to execute",
        "RecoveryAddressNotSet" => "recovery address is not set for this account",
        "RecoveryAgentUpdateStillActive" => {
            "recovery agent update is still active — cannot start a new one yet"
        }
        "RecoveryAgentUpdateStillInCooldown" => "recovery agent update is still in cooldown",
        "RecoveryAgentUpdateWindowExpired" => "recovery agent update window has expired",
        "RecoveryCounterOverflow" => "recovery counter overflow",
        "RecoveryNotEnabled" => "recovery is not enabled for this account",
        "ReusedAuthenticatorAddress" => "authenticator address was reused",

        // Registry lifecycle / misc.
        "AlreadyInitialized" => "registry is already initialized",
        "BitmapOverflow" => "authenticator bitmap overflow",
        "DepthNotSupported" => "merkle depth not supported",
        "EmptyAddressArray" => "authenticator address array is empty",
        "ImplementationNotInitialized" => "registry implementation is not initialized",
        "InsufficientFunds" => "insufficient funds",
        "InvalidInitialization" => "invalid initialization",
        "MethodUnsupported" => "method is not supported on this registry version",
        "MismatchingArrayLengths" => "mismatched array lengths",
        "NotInitializing" => "registry is not currently initializing",
        "UnmanageableNotAllowed" => "unmanageable account operation is not allowed",
        "ZeroAddress" => "unexpected zero address argument",

        // OpenZeppelin proxy / access-control passthroughs
        "AddressEmptyCode" => "target address has no contract code",
        "ERC1967InvalidImplementation" => "invalid ERC-1967 implementation address",
        "ERC1967NonPayable" => "ERC-1967 proxy is non-payable",
        "FailedCall" => "call to registry failed",
        "OwnableInvalidOwner" => "invalid owner",
        "OwnableUnauthorizedAccount" => "unauthorized account",
        "SafeERC20FailedOperation" => "ERC-20 operation failed",
        "UUPSUnauthorizedCallContext" => "UUPS call context is unauthorized",
        "UUPSUnsupportedProxiableUUID" => "UUPS proxiable UUID is not supported",

        other => other,
    }
}

/// Return the 4-byte selector of a known [`SolError`] as a lowercase
/// `0x`-prefixed hex string. Used by the legacy string-matching fallback in
/// [`crate::error::parse_contract_error`].
pub(crate) fn selector_hex<E: SolError>() -> String {
    format!("0x{}", hex::encode(E::SELECTOR))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::sol_types::SolError;
    use world_id_registries::world_id::WorldIdRegistry::{
        AuthenticatorAddressAlreadyInUse, MismatchedSignatureNonce, PubkeyIdOutOfBounds,
    };
    use world_id_registries::world_id::WorldIdRegistryV2::{
        RecoveryAgentUpdateStillInCooldown, RecoveryAgentUpdateWindowExpired,
    };

    fn selector_of<E: SolError>() -> [u8; 4] {
        E::SELECTOR
    }

    #[test]
    fn decodes_v1_authenticator_already_in_use() {
        let decoded =
            DecodedRegistryError::from_selector(selector_of::<AuthenticatorAddressAlreadyInUse>())
                .expect("selector known");
        assert_eq!(decoded.variant_name(), "AuthenticatorAddressAlreadyInUse");
        assert!(matches!(
            decoded.to_error_code(),
            GatewayErrorCode::AuthenticatorAlreadyExists
        ));
        assert!(
            decoded.human_message().contains("already in use"),
            "unexpected message: {}",
            decoded.human_message()
        );
    }

    #[test]
    fn decodes_v2_only_variant() {
        // `RecoveryAgentUpdateWindowExpired` only exists in the V2 ABI.
        let decoded =
            DecodedRegistryError::from_selector(selector_of::<RecoveryAgentUpdateWindowExpired>())
                .expect("selector known");
        assert_eq!(decoded.variant_name(), "RecoveryAgentUpdateWindowExpired");
        assert!(decoded.is_v2());
        assert!(decoded.human_message().contains("window has expired"));
    }

    #[test]
    fn decodes_shared_variant_prefers_v2() {
        // `RecoveryAgentUpdateStillInCooldown` exists in both V1 and V2.
        let decoded = DecodedRegistryError::from_selector(selector_of::<
            RecoveryAgentUpdateStillInCooldown,
        >())
        .expect("selector known");
        assert!(decoded.is_v2());
        assert_eq!(decoded.variant_name(), "RecoveryAgentUpdateStillInCooldown");
    }

    #[test]
    fn decodes_pubkey_id_out_of_bounds() {
        let decoded = DecodedRegistryError::from_selector(selector_of::<PubkeyIdOutOfBounds>())
            .expect("selector known");
        assert_eq!(decoded.variant_name(), "PubkeyIdOutOfBounds");
        assert!(matches!(
            decoded.to_error_code(),
            GatewayErrorCode::PubkeyIdOutOfBounds
        ));
    }

    #[test]
    fn decodes_mismatched_signature_nonce() {
        let decoded =
            DecodedRegistryError::from_selector(selector_of::<MismatchedSignatureNonce>())
                .expect("selector known");
        assert_eq!(decoded.variant_name(), "MismatchedSignatureNonce");
        assert!(matches!(
            decoded.to_error_code(),
            GatewayErrorCode::MismatchedSignatureNonce
        ));
    }

    #[test]
    fn decodes_bytes_using_selector_prefix() {
        // 4-byte selector followed by dummy arg bytes — we only look at the
        // first 4 bytes, so garbage after is fine.
        let sel = selector_of::<MismatchedSignatureNonce>();
        let mut data = Vec::from(sel);
        data.extend_from_slice(&[0xaau8; 32]);
        let decoded = DecodedRegistryError::decode(&data).expect("selector known");
        assert_eq!(decoded.variant_name(), "MismatchedSignatureNonce");
    }

    #[test]
    fn returns_none_for_short_data() {
        assert!(DecodedRegistryError::decode(&[]).is_none());
        assert!(DecodedRegistryError::decode(&[0x11]).is_none());
        assert!(DecodedRegistryError::decode(&[0x11, 0x22, 0x33]).is_none());
    }

    #[test]
    fn returns_none_for_unknown_selector() {
        // Unknown 4-byte selector.
        let data = [0xde, 0xad, 0xbe, 0xef];
        assert!(DecodedRegistryError::decode(&data).is_none());
    }

    #[test]
    fn selector_hex_prefixes_with_0x() {
        let s = selector_hex::<PubkeyIdOutOfBounds>();
        assert!(s.starts_with("0x"));
        assert_eq!(s.len(), 2 + 8);
    }
}
