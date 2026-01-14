use crate::{types::MAX_AUTHENTICATORS, ErrorResponse as ApiError};
use world_id_core::types::{
    CreateAccountRequest, InsertAuthenticatorRequest, RecoverAccountRequest,
    RemoveAuthenticatorRequest, UpdateAuthenticatorRequest,
};

/// Standard ECDSA signature length.
const ECDSA_SIGNATURE_LEN: usize = 65;

/// Basic ECDSA signature validation.
///
/// Note that it does **NOT** compute a signature verification algorithm.
fn validate_ecdsa_signature(signature: &[u8]) -> Result<(), ApiError> {
    if signature.len() != ECDSA_SIGNATURE_LEN {
        return Err(ApiError::bad_request(
            // 65 is the standard ECDSA signature length (r, s, v).
            "ECDSA signature must be exactly 65 bytes long".to_string(),
        ));
    }
    if signature.iter().all(|&byte| byte == 0) {
        return Err(ApiError::bad_request(
            "ECDSA signature cannot be all zeros".to_string(),
        ));
    }
    Ok(())
}

/// Trait that performs input validation on specific requests to the gateway.
pub(crate) trait ValidateRequest {
    /// Perform input validation on the specific request.
    fn validate(&self) -> Result<(), ApiError>;
}

impl ValidateRequest for CreateAccountRequest {
    fn validate(&self) -> Result<(), ApiError> {
        if self.authenticator_addresses.len() > MAX_AUTHENTICATORS as usize {
            return Err(ApiError::bad_request(format!(
                "authenticators cannot be more than {MAX_AUTHENTICATORS}"
            )));
        }
        if self.authenticator_addresses.is_empty() {
            return Err(ApiError::bad_request(
                "authenticators cannot be empty".to_string(),
            ));
        }
        if self.authenticator_addresses.len() != self.authenticator_pubkeys.len() {
            return Err(ApiError::bad_request(
                "authenticators addresses must be equal to authenticators pubkeys".to_string(),
            ));
        }
        if self.authenticator_addresses.iter().any(|a| a.is_zero()) {
            return Err(ApiError::bad_request(
                "authenticator address cannot be zero".to_string(),
            ));
        }
        Ok(())
    }
}

impl ValidateRequest for InsertAuthenticatorRequest {
    fn validate(&self) -> Result<(), ApiError> {
        if self.new_authenticator_address.is_zero() {
            return Err(ApiError::bad_request(
                "new_authenticator_address cannot be zero".to_string(),
            ));
        }
        if self.pubkey_id >= MAX_AUTHENTICATORS {
            return Err(ApiError::bad_request(format!(
                "pubkey_id must be less than {MAX_AUTHENTICATORS}"
            )));
        }
        if self.leaf_index.is_zero() {
            return Err(ApiError::bad_request(
                "leaf_index cannot be zero".to_string(),
            ));
        }
        if self.old_offchain_signer_commitment.is_zero()
            || self.new_offchain_signer_commitment.is_zero()
        {
            return Err(ApiError::bad_request(
                "offchain signer commitment cannot be zero".to_string(),
            ));
        }
        validate_ecdsa_signature(&self.signature)?;
        Ok(())
    }
}

impl ValidateRequest for UpdateAuthenticatorRequest {
    fn validate(&self) -> Result<(), ApiError> {
        if self.leaf_index.is_zero() {
            return Err(ApiError::bad_request(
                "leaf_index cannot be zero".to_string(),
            ));
        }
        if self.pubkey_id >= MAX_AUTHENTICATORS {
            return Err(ApiError::bad_request(format!(
                "pubkey_id must be less than {MAX_AUTHENTICATORS}"
            )));
        }
        if self.new_authenticator_address.is_zero() {
            return Err(ApiError::bad_request(
                "new_authenticator_address cannot be zero".to_string(),
            ));
        }
        if self.old_offchain_signer_commitment.is_zero()
            || self.new_offchain_signer_commitment.is_zero()
        {
            return Err(ApiError::bad_request(
                "offchain signer commitment cannot be zero".to_string(),
            ));
        }
        validate_ecdsa_signature(&self.signature)?;
        Ok(())
    }
}

impl ValidateRequest for RemoveAuthenticatorRequest {
    fn validate(&self) -> Result<(), ApiError> {
        let pubkey_id = self.pubkey_id.unwrap_or(0);

        if self.leaf_index.is_zero() {
            return Err(ApiError::bad_request(
                "leaf_index cannot be zero".to_string(),
            ));
        }
        if pubkey_id >= MAX_AUTHENTICATORS {
            return Err(ApiError::bad_request(format!(
                "pubkey_id must be less than {MAX_AUTHENTICATORS}"
            )));
        }
        if self.authenticator_address.is_zero() {
            return Err(ApiError::bad_request(
                "authenticator_address cannot be zero".to_string(),
            ));
        }
        if self.old_offchain_signer_commitment.is_zero()
            || self.new_offchain_signer_commitment.is_zero()
        {
            return Err(ApiError::bad_request(
                "offchain signer commitment cannot be zero".to_string(),
            ));
        }
        validate_ecdsa_signature(&self.signature)?;
        Ok(())
    }
}

impl ValidateRequest for RecoverAccountRequest {
    fn validate(&self) -> Result<(), ApiError> {
        if self.leaf_index.is_zero() {
            return Err(ApiError::bad_request(
                "leaf_index cannot be zero".to_string(),
            ));
        }
        if self.new_authenticator_address.is_zero() {
            return Err(ApiError::bad_request(
                "new_authenticator_address cannot be zero".to_string(),
            ));
        }
        if self.old_offchain_signer_commitment.is_zero()
            || self.new_offchain_signer_commitment.is_zero()
        {
            return Err(ApiError::bad_request(
                "offchain signer commitment cannot be zero".to_string(),
            ));
        }
        validate_ecdsa_signature(&self.signature)?;
        Ok(())
    }
}
