//! ABI-aware decoding of on-chain revert data returned by the WorldID
//! registry.
//!
//! The gateway's RPC layer receives revert data as ABI-encoded custom errors
//! (a 4-byte selector followed by the ABI-encoded arguments). Without
//! decoding, this surfaces to API callers as an opaque hex blob buried in a
//! JSON-RPC error message. This module extracts that revert data from an
//! alloy transport / contract error, decodes it against the registry ABI, and
//! maps it to:
//!
//!   * a [`GatewayErrorCode`] for programmatic handling by callers, and
//!   * a stable human-readable message safe to include in the API response.
//!
//! Callers can also decode raw revert bytes directly via
//! [`DecodedRegistryError::decode`], which is convenient for testing.
//!
//! Unknown selectors, malformed data, and non-revert errors are left
//! undecoded so callers can preserve the original error message.

use alloy::{
    sol_types::SolInterface,
    transports::{RpcError, TransportErrorKind},
};
use world_id_primitives::api_types::GatewayErrorCode;
use world_id_registries::world_id::WorldIdRegistryV2::WorldIdRegistryV2Errors as RegistryError;

/// A registry custom error decoded from ABI-encoded revert data.
#[derive(Clone)]
pub struct DecodedRegistryError {
    error: RegistryError,
}

impl DecodedRegistryError {
    /// Decode raw revert data (4-byte selector followed by ABI-encoded error
    /// arguments) into a generated registry error variant.
    ///
    /// Returns `None` if the selector is unknown or the argument payload is
    /// malformed.
    #[must_use]
    pub fn decode(data: &[u8]) -> Option<Self> {
        RegistryError::abi_decode_validate(data)
            .ok()
            .map(|error| Self { error })
    }

    /// Extract revert data from an alloy transport error (typically returned
    /// by `provider.call(...)`), and decode it. Returns `None` if the error
    /// does not carry valid registry revert data.
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
    #[must_use]
    pub fn variant_name(&self) -> &'static str {
        RegistryError::name_by_selector(self.error.selector())
            .expect("decoded registry error must have a known selector")
    }

    /// A stable, human-readable description of the revert. Prefixed with
    /// `WorldID:` for parity with reverts thrown by the contracts themselves.
    #[must_use]
    pub fn human_message(&self) -> String {
        format!("WorldID: {}", describe(&self.error))
    }

    /// Map the decoded error to a [`GatewayErrorCode`]. Errors that don't
    /// have a dedicated code fall through to [`GatewayErrorCode::BadRequest`].
    #[must_use]
    pub fn to_error_code(&self) -> GatewayErrorCode {
        match &self.error {
            RegistryError::AuthenticatorAddressAlreadyInUse(_)
            | RegistryError::AuthenticatorAlreadyExists(_) => {
                GatewayErrorCode::AuthenticatorAlreadyExists
            }
            RegistryError::AuthenticatorDoesNotExist(_) => {
                GatewayErrorCode::AuthenticatorDoesNotExist
            }
            RegistryError::AuthenticatorDoesNotBelongToAccount(_) => {
                GatewayErrorCode::AuthenticatorDoesNotBelongToAccount
            }
            RegistryError::MismatchedSignatureNonce(_) => {
                GatewayErrorCode::MismatchedSignatureNonce
            }
            RegistryError::PubkeyIdInUse(_) => GatewayErrorCode::PubkeyIdInUse,
            RegistryError::PubkeyIdOutOfBounds(_) | RegistryError::PubkeyIdOverflow(_) => {
                GatewayErrorCode::PubkeyIdOutOfBounds
            }
            RegistryError::MethodUnsupported(_) => GatewayErrorCode::MethodNotAvailable,
            _ => GatewayErrorCode::BadRequest,
        }
    }
}

/// Map a generated registry error variant to a short, human-readable
/// description. This match is deliberately exhaustive so ABI additions must
/// be handled explicitly.
fn describe(error: &RegistryError) -> &'static str {
    match error {
        // Ownership / lookup
        RegistryError::AccountDoesNotExist(_) => "account does not exist for the given leaf index",
        RegistryError::AuthenticatorAddressAlreadyInUse(_) => {
            "authenticator address is already in use by another account"
        }
        RegistryError::AuthenticatorAlreadyExists(_) => {
            "authenticator already exists on this account"
        }
        RegistryError::AuthenticatorClassMismatch(_) => "authenticator class does not match",
        RegistryError::AuthenticatorDoesNotBelongToAccount(_) => {
            "authenticator does not belong to the specified account"
        }
        RegistryError::AuthenticatorDoesNotExist(_) => {
            "authenticator does not exist on this account"
        }
        RegistryError::OwnerMaxAuthenticatorsOutOfBounds(_) => {
            "account already has the maximum number of authenticators"
        }

        // Signature / nonce
        RegistryError::ECDSAInvalidSignature(_) => "invalid ECDSA signature",
        RegistryError::ECDSAInvalidSignatureLength(_) => "invalid ECDSA signature length",
        RegistryError::ECDSAInvalidSignatureS(_) => "invalid ECDSA signature `s` value",
        RegistryError::InvalidSignature(_) => "invalid signature",
        RegistryError::MismatchedAuthenticatorSigner(_) => {
            "signature was not produced by an authenticator on this account"
        }
        RegistryError::MismatchedSignatureNonce(_) => {
            "signature nonce does not match the on-chain value"
        }
        RegistryError::ZeroRecoveredSignatureAddress(_) => {
            "signature recovered to the zero address"
        }

        // Pubkey slots
        RegistryError::PubkeyIdDoesNotExist(_) => "pubkey id does not exist on this account",
        RegistryError::PubkeyIdInUse(_) => "pubkey id slot is already in use",
        RegistryError::PubkeyIdOutOfBounds(_) => "pubkey id is out of bounds",
        RegistryError::PubkeyIdOverflow(_) => "pubkey id overflow",
        RegistryError::MismatchedPubkeyId(_) => "pubkey id does not match the on-chain value",

        // Leaf / merkle
        RegistryError::LeafIndexOutOfRange(_) => "leaf index is out of range",
        RegistryError::MismatchedLeafIndex(_) => "leaf index does not match the on-chain value",
        RegistryError::UnknownRoot(_) => "root is not known to the registry",
        RegistryError::WrongDefaultZeroIndex(_) => "wrong default-zero merkle index",

        // Recovery
        RegistryError::MismatchedRecoveryCounter(_) => {
            "recovery counter does not match the on-chain value"
        }
        RegistryError::NoActiveRecoveryAgentUpdate(_) => {
            "no active recovery agent update to revert"
        }
        RegistryError::NoPendingRecoveryAgentUpdate(_) => {
            "no pending recovery agent update to execute"
        }
        RegistryError::RecoveryAddressNotSet(_) => "recovery address is not set for this account",
        RegistryError::RecoveryAgentUpdateStillActive(_) => {
            "recovery agent update is still active — cannot start a new one yet"
        }
        RegistryError::RecoveryAgentUpdateStillInCooldown(_) => {
            "recovery agent update is still in cooldown"
        }
        RegistryError::RecoveryAgentUpdateWindowExpired(_) => {
            "recovery agent update window has expired"
        }
        RegistryError::RecoveryCounterOverflow(_) => "recovery counter overflow",
        RegistryError::RecoveryNotEnabled(_) => "recovery is not enabled for this account",
        RegistryError::ReusedAuthenticatorAddress(_) => "authenticator address was reused",

        // Registry lifecycle / misc.
        RegistryError::AlreadyInitialized(_) => "registry is already initialized",
        RegistryError::BitmapOverflow(_) => "authenticator bitmap overflow",
        RegistryError::DepthNotSupported(_) => "merkle depth not supported",
        RegistryError::EmptyAddressArray(_) => "authenticator address array is empty",
        RegistryError::ImplementationNotInitialized(_) => {
            "registry implementation is not initialized"
        }
        RegistryError::InsufficientFunds(_) => "insufficient funds",
        RegistryError::InvalidInitialization(_) => "invalid initialization",
        RegistryError::MethodUnsupported(_) => "method is not supported on this registry version",
        RegistryError::MismatchingArrayLengths(_) => "mismatched array lengths",
        RegistryError::NotInitializing(_) => "registry is not currently initializing",
        RegistryError::UnmanageableNotAllowed(_) => "unmanageable account operation is not allowed",
        RegistryError::ZeroAddress(_) => "unexpected zero address argument",

        // OpenZeppelin proxy / access-control passthroughs
        RegistryError::AddressEmptyCode(_) => "target address has no contract code",
        RegistryError::ERC1967InvalidImplementation(_) => "invalid ERC-1967 implementation address",
        RegistryError::ERC1967NonPayable(_) => "ERC-1967 proxy is non-payable",
        RegistryError::FailedCall(_) => "call to registry failed",
        RegistryError::OwnableInvalidOwner(_) => "invalid owner",
        RegistryError::OwnableUnauthorizedAccount(_) => "unauthorized account",
        RegistryError::SafeERC20FailedOperation(_) => "ERC-20 operation failed",
        RegistryError::UUPSUnauthorizedCallContext(_) => "UUPS call context is unauthorized",
        RegistryError::UUPSUnsupportedProxiableUUID(_) => "UUPS proxiable UUID is not supported",
    }
}

#[cfg(test)]
mod tests {
    use std::mem::discriminant;

    use alloy::{
        primitives::{Address, U256},
        sol_types::SolError,
    };
    use test_case::test_case;
    use world_id_registries::world_id::WorldIdRegistryV2::{
        AuthenticatorAddressAlreadyInUse, MismatchedSignatureNonce, PubkeyIdOutOfBounds,
        RecoveryAgentUpdateWindowExpired,
    };

    use super::*;

    #[test_case(
        AuthenticatorAddressAlreadyInUse { authenticatorAddress: Address::ZERO }.abi_encode(),
        "AuthenticatorAddressAlreadyInUse",
        GatewayErrorCode::AuthenticatorAlreadyExists,
        "WorldID: authenticator address is already in use by another account";
        "authenticator already in use"
    )]
    #[test_case(
        RecoveryAgentUpdateWindowExpired {
            leafIndex: 1,
            invalidAfter: U256::from(2),
        }.abi_encode(),
        "RecoveryAgentUpdateWindowExpired",
        GatewayErrorCode::BadRequest,
        "WorldID: recovery agent update window has expired";
        "V2 recovery window expired"
    )]
    #[test_case(
        PubkeyIdOutOfBounds.abi_encode(),
        "PubkeyIdOutOfBounds",
        GatewayErrorCode::PubkeyIdOutOfBounds,
        "WorldID: pubkey id is out of bounds";
        "pubkey id out of bounds"
    )]
    #[test_case(
        MismatchedSignatureNonce {
            leafIndex: 1,
            expectedNonce: U256::from(2),
            actualNonce: U256::from(3),
        }.abi_encode(),
        "MismatchedSignatureNonce",
        GatewayErrorCode::MismatchedSignatureNonce,
        "WorldID: signature nonce does not match the on-chain value";
        "mismatched signature nonce"
    )]
    fn decodes_known_error(
        data: Vec<u8>,
        expected_variant: &str,
        expected_code: GatewayErrorCode,
        expected_message: &str,
    ) {
        let decoded = DecodedRegistryError::decode(&data).expect("error should decode");
        assert_eq!(decoded.variant_name(), expected_variant);
        assert_eq!(
            discriminant(&decoded.to_error_code()),
            discriminant(&expected_code)
        );
        assert_eq!(decoded.human_message(), expected_message);
    }

    fn truncated_signature_nonce_error() -> Vec<u8> {
        let mut data = MismatchedSignatureNonce {
            leafIndex: 1,
            expectedNonce: U256::from(2),
            actualNonce: U256::from(3),
        }
        .abi_encode();
        data.truncate(4 + 32);
        data
    }

    #[test_case(Vec::new(); "empty")]
    #[test_case(vec![0x11]; "shorter than selector")]
    #[test_case(vec![0x11, 0x22, 0x33]; "three-byte selector")]
    #[test_case(vec![0xde, 0xad, 0xbe, 0xef]; "unknown selector")]
    #[test_case(truncated_signature_nonce_error(); "truncated arguments")]
    fn rejects_invalid_error(data: Vec<u8>) {
        assert!(DecodedRegistryError::decode(&data).is_none());
    }
}
