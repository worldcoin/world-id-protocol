use tokio::sync::OnceCell;

use crate::error::GatewayErrorResponse;
use alloy::{
    primitives::{Address, Bytes, Signature, U256},
    providers::Provider,
    sol_types::{Eip712Domain, SolStruct, eip712_domain},
};
use world_id_core::{
    api_types::{
        CreateAccountRequest, InsertAuthenticatorRequest, RecoverAccountRequest,
        RemoveAuthenticatorRequest, UpdateAuthenticatorRequest,
    },
    world_id_registry::{
        InsertAuthenticatorTypedData, RecoverAccountTypedData, RemoveAuthenticatorTypedData,
        UpdateAuthenticatorTypedData,
    },
};

use crate::{request::Registry, types::MAX_AUTHENTICATORS};

/// Global OnceCell to store the chain ID.
pub static CHAIN_ID: OnceCell<u64> = OnceCell::const_new();

/// Standard ECDSA signature length.
const ECDSA_SIGNATURE_LEN: usize = 65;

/// Returns the EIP-712 domain for the WorldIdRegistry contract.
fn eip712_domain(chain_id: u64, verifying_contract: Address) -> Eip712Domain {
    eip712_domain!(
        name: "WorldIDRegistry",
        version: "1.0",
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    )
}

/// Trait for validating gateway requests before processing.
///
/// Validation consists of two phases:
/// 1. **Pre-flight**: Synchronous checks including field validation and signature verification
/// 2. **Simulation**: Async contract call to verify the transaction would succeed
pub(crate) trait RequestValidation: Sized + Sync {
    /// Synchronous pre-flight validation including signature verification.
    ///
    /// Checks basic constraints like field lengths, zero values, and verifies
    /// ECDSA signatures using EIP-712 typed data.
    fn pre_flight(
        &self,
        chain_id: u64,
        verifying_contract: Address,
    ) -> Result<(), GatewayErrorResponse>;

    /// Get the encoded calldata for this request.
    ///
    /// This produces the ABI-encoded calldata that can be used for both
    /// simulation and actual transaction submission.
    fn calldata(&self, registry: &Registry) -> Bytes;

    /// Simulate the request against the contract.
    ///
    /// Calls the contract with `.call()` to check if the transaction would revert
    /// without actually spending gas.
    fn simulate(
        &self,
        registry: &Registry,
    ) -> impl Future<Output = Result<(), GatewayErrorResponse>> + Send;

    /// Full validation: pre-flight checks (including signature verification), then contract simulation.
    fn validate(
        &self,
        registry: &Registry,
    ) -> impl Future<Output = Result<(), GatewayErrorResponse>> + Send {
        async move {
            let chain_id = *CHAIN_ID
                .get_or_try_init(|| async {
                    registry
                        .provider()
                        .get_chain_id()
                        .await
                        .map_err(|_| GatewayErrorResponse::internal_server_error())
                })
                .await?;
            let verifying_contract = *registry.address();

            self.pre_flight(chain_id, verifying_contract)?;
            self.simulate(registry).await
        }
    }
}

/// Basic ECDSA signature format validation.
fn validate_ecdsa_signature_format(signature: &[u8]) -> Result<(), GatewayErrorResponse> {
    if signature.len() != ECDSA_SIGNATURE_LEN {
        return Err(GatewayErrorResponse::bad_request_message(
            "ECDSA signature must be exactly 65 bytes long".to_string(),
        ));
    }
    if signature.iter().all(|&byte| byte == 0) {
        return Err(GatewayErrorResponse::bad_request_message(
            "ECDSA signature cannot be all zeros".to_string(),
        ));
    }
    Ok(())
}

/// Parse a 65-byte signature into an alloy Signature.
fn parse_signature(signature: &[u8]) -> Result<Signature, GatewayErrorResponse> {
    validate_ecdsa_signature_format(signature)?;

    // Signature format: r (32 bytes) || s (32 bytes) || v (1 byte)
    let r = U256::from_be_slice(&signature[0..32]);
    let s = U256::from_be_slice(&signature[32..64]);
    let v = signature[64];

    // v should be 27 or 28 (or 0/1 for some implementations)
    let y_parity = match v {
        0 | 27 => false,
        1 | 28 => true,
        _ => {
            return Err(GatewayErrorResponse::bad_request_message(format!(
                "invalid signature recovery id: {v}"
            )));
        }
    };

    Ok(Signature::new(r, s, y_parity))
}

/// Recover the signer address from an EIP-712 typed data hash and signature.
fn recover_signer<T: SolStruct>(
    typed_data: &T,
    signature: &[u8],
    chain_id: u64,
    verifying_contract: Address,
) -> Result<Address, GatewayErrorResponse> {
    let sig = parse_signature(signature)?;
    let domain = eip712_domain(chain_id, verifying_contract);
    let digest = typed_data.eip712_signing_hash(&domain);

    sig.recover_address_from_prehash(&digest).map_err(|e| {
        GatewayErrorResponse::bad_request_message(format!("signature recovery failed: {e}"))
    })
}

// =============================================================================
// CreateAccountRequest
// =============================================================================

impl RequestValidation for CreateAccountRequest {
    fn pre_flight(
        &self,
        _chain_id: u64,
        _verifying_contract: Address,
    ) -> Result<(), GatewayErrorResponse> {
        // CreateAccountRequest has no signature to verify
        if self.authenticator_addresses.len() > MAX_AUTHENTICATORS as usize {
            return Err(GatewayErrorResponse::bad_request_message(format!(
                "authenticators cannot be more than {MAX_AUTHENTICATORS}"
            )));
        }
        if self.authenticator_addresses.is_empty() {
            return Err(GatewayErrorResponse::bad_request_message(
                "authenticators cannot be empty".to_string(),
            ));
        }
        if self.authenticator_addresses.len() != self.authenticator_pubkeys.len() {
            return Err(GatewayErrorResponse::bad_request_message(
                "authenticators addresses must be equal to authenticators pubkeys".to_string(),
            ));
        }
        if self.authenticator_addresses.iter().any(|a| a.is_zero()) {
            return Err(GatewayErrorResponse::bad_request_message(
                "authenticator address cannot be zero".to_string(),
            ));
        }
        if self.offchain_signer_commitment.is_zero() {
            return Err(GatewayErrorResponse::bad_request_message(
                "offchain signer commitment cannot be zero".to_string(),
            ));
        }
        Ok(())
    }

    fn calldata(&self, registry: &Registry) -> Bytes {
        registry
            .createAccount(
                self.recovery_address.unwrap_or_default(),
                self.authenticator_addresses.clone(),
                self.authenticator_pubkeys.clone(),
                self.offchain_signer_commitment,
            )
            .calldata()
            .clone()
    }

    async fn simulate(&self, registry: &Registry) -> Result<(), GatewayErrorResponse> {
        registry
            .createAccount(
                self.recovery_address.unwrap_or_default(),
                self.authenticator_addresses.clone(),
                self.authenticator_pubkeys.clone(),
                self.offchain_signer_commitment,
            )
            .call()
            .await
            .map_err(GatewayErrorResponse::from_simulation_error)?;
        Ok(())
    }
}

// =============================================================================
// InsertAuthenticatorRequest
// =============================================================================

impl RequestValidation for InsertAuthenticatorRequest {
    fn pre_flight(
        &self,
        chain_id: u64,
        verifying_contract: Address,
    ) -> Result<(), GatewayErrorResponse> {
        if self.new_authenticator_address.is_zero() {
            return Err(GatewayErrorResponse::bad_request_message(
                "new_authenticator_address cannot be zero".to_string(),
            ));
        }
        if self.pubkey_id >= MAX_AUTHENTICATORS {
            return Err(GatewayErrorResponse::bad_request_message(format!(
                "pubkey_id must be less than {MAX_AUTHENTICATORS}"
            )));
        }
        if self.leaf_index == 0 {
            return Err(GatewayErrorResponse::bad_request_message(
                "leaf_index cannot be zero".to_string(),
            ));
        }
        if self.old_offchain_signer_commitment.is_zero()
            || self.new_offchain_signer_commitment.is_zero()
        {
            return Err(GatewayErrorResponse::bad_request_message(
                "offchain signer commitment cannot be zero".to_string(),
            ));
        }

        // Verify ECDSA signature
        let typed_data = InsertAuthenticatorTypedData {
            leafIndex: self.leaf_index,
            newAuthenticatorAddress: self.new_authenticator_address,
            pubkeyId: self.pubkey_id,
            newAuthenticatorPubkey: self.new_authenticator_pubkey,
            newOffchainSignerCommitment: self.new_offchain_signer_commitment,
            nonce: self.nonce,
        };
        let _signer = recover_signer(&typed_data, &self.signature, chain_id, verifying_contract)?;

        Ok(())
    }

    fn calldata(&self, registry: &Registry) -> Bytes {
        registry
            .insertAuthenticator(
                self.leaf_index,
                self.new_authenticator_address,
                self.pubkey_id,
                self.new_authenticator_pubkey,
                self.old_offchain_signer_commitment,
                self.new_offchain_signer_commitment,
                Bytes::from(self.signature.clone()),
                self.sibling_nodes.clone(),
                self.nonce,
            )
            .calldata()
            .clone()
    }

    async fn simulate(&self, registry: &Registry) -> Result<(), GatewayErrorResponse> {
        registry
            .insertAuthenticator(
                self.leaf_index,
                self.new_authenticator_address,
                self.pubkey_id,
                self.new_authenticator_pubkey,
                self.old_offchain_signer_commitment,
                self.new_offchain_signer_commitment,
                Bytes::from(self.signature.clone()),
                self.sibling_nodes.clone(),
                self.nonce,
            )
            .call()
            .await
            .map_err(GatewayErrorResponse::from_simulation_error)?;
        Ok(())
    }
}

// =============================================================================
// UpdateAuthenticatorRequest
// =============================================================================

impl RequestValidation for UpdateAuthenticatorRequest {
    fn pre_flight(
        &self,
        chain_id: u64,
        verifying_contract: Address,
    ) -> Result<(), GatewayErrorResponse> {
        if self.leaf_index == 0 {
            return Err(GatewayErrorResponse::bad_request_message(
                "leaf_index cannot be zero".to_string(),
            ));
        }
        if self.pubkey_id >= MAX_AUTHENTICATORS {
            return Err(GatewayErrorResponse::bad_request_message(format!(
                "pubkey_id must be less than {MAX_AUTHENTICATORS}"
            )));
        }
        if self.new_authenticator_address.is_zero() {
            return Err(GatewayErrorResponse::bad_request_message(
                "new_authenticator_address cannot be zero".to_string(),
            ));
        }
        if self.old_offchain_signer_commitment.is_zero()
            || self.new_offchain_signer_commitment.is_zero()
        {
            return Err(GatewayErrorResponse::bad_request_message(
                "offchain signer commitment cannot be zero".to_string(),
            ));
        }

        // Verify ECDSA signature is from the authenticator being replaced
        let typed_data = UpdateAuthenticatorTypedData {
            leafIndex: self.leaf_index,
            oldAuthenticatorAddress: self.old_authenticator_address,
            newAuthenticatorAddress: self.new_authenticator_address,
            pubkeyId: self.pubkey_id,
            newAuthenticatorPubkey: self.new_authenticator_pubkey,
            newOffchainSignerCommitment: self.new_offchain_signer_commitment,
            nonce: self.nonce,
        };
        let signer = recover_signer(&typed_data, &self.signature, chain_id, verifying_contract)?;
        if signer != self.old_authenticator_address {
            return Err(GatewayErrorResponse::bad_request_message(
                "signature must be from the authenticator being replaced".to_string(),
            ));
        }

        Ok(())
    }

    fn calldata(&self, registry: &Registry) -> Bytes {
        registry
            .updateAuthenticator(
                self.leaf_index,
                self.old_authenticator_address,
                self.new_authenticator_address,
                self.pubkey_id,
                self.new_authenticator_pubkey,
                self.old_offchain_signer_commitment,
                self.new_offchain_signer_commitment,
                Bytes::from(self.signature.clone()),
                self.sibling_nodes.clone(),
                self.nonce,
            )
            .calldata()
            .clone()
    }

    async fn simulate(&self, registry: &Registry) -> Result<(), GatewayErrorResponse> {
        registry
            .updateAuthenticator(
                self.leaf_index,
                self.old_authenticator_address,
                self.new_authenticator_address,
                self.pubkey_id,
                self.new_authenticator_pubkey,
                self.old_offchain_signer_commitment,
                self.new_offchain_signer_commitment,
                Bytes::from(self.signature.clone()),
                self.sibling_nodes.clone(),
                self.nonce,
            )
            .call()
            .await
            .map_err(GatewayErrorResponse::from_simulation_error)?;

        Ok(())
    }
}

// =============================================================================
// RemoveAuthenticatorRequest
// =============================================================================

impl RequestValidation for RemoveAuthenticatorRequest {
    fn pre_flight(
        &self,
        chain_id: u64,
        verifying_contract: Address,
    ) -> Result<(), GatewayErrorResponse> {
        let pubkey_id = self.pubkey_id.unwrap_or(0);
        let authenticator_pubkey = self.authenticator_pubkey.unwrap_or(U256::ZERO);

        if self.leaf_index == 0 {
            return Err(GatewayErrorResponse::bad_request_message(
                "leaf_index cannot be zero".to_string(),
            ));
        }
        if pubkey_id >= MAX_AUTHENTICATORS {
            return Err(GatewayErrorResponse::bad_request_message(format!(
                "pubkey_id must be less than {MAX_AUTHENTICATORS}"
            )));
        }
        if self.authenticator_address.is_zero() {
            return Err(GatewayErrorResponse::bad_request_message(
                "authenticator_address cannot be zero".to_string(),
            ));
        }
        if self.old_offchain_signer_commitment.is_zero()
            || self.new_offchain_signer_commitment.is_zero()
        {
            return Err(GatewayErrorResponse::bad_request_message(
                "offchain signer commitment cannot be zero".to_string(),
            ));
        }

        // Verify ECDSA signature format and recoverability
        // Note: Any authenticator on the account can authorize removal, not just the one being removed.
        // Full authorization is verified by the contract during simulation.
        let typed_data = RemoveAuthenticatorTypedData {
            leafIndex: self.leaf_index,
            authenticatorAddress: self.authenticator_address,
            pubkeyId: pubkey_id,
            authenticatorPubkey: authenticator_pubkey,
            newOffchainSignerCommitment: self.new_offchain_signer_commitment,
            nonce: self.nonce,
        };
        let _signer = recover_signer(&typed_data, &self.signature, chain_id, verifying_contract)?;

        Ok(())
    }

    fn calldata(&self, registry: &Registry) -> Bytes {
        let pubkey_id = self.pubkey_id.unwrap_or(0);
        let authenticator_pubkey = self.authenticator_pubkey.unwrap_or(U256::ZERO);

        registry
            .removeAuthenticator(
                self.leaf_index,
                self.authenticator_address,
                pubkey_id,
                authenticator_pubkey,
                self.old_offchain_signer_commitment,
                self.new_offchain_signer_commitment,
                Bytes::from(self.signature.clone()),
                self.sibling_nodes.clone(),
                self.nonce,
            )
            .calldata()
            .clone()
    }

    async fn simulate(&self, registry: &Registry) -> Result<(), GatewayErrorResponse> {
        let pubkey_id = self.pubkey_id.unwrap_or(0);
        let authenticator_pubkey = self.authenticator_pubkey.unwrap_or(U256::ZERO);

        registry
            .removeAuthenticator(
                self.leaf_index,
                self.authenticator_address,
                pubkey_id,
                authenticator_pubkey,
                self.old_offchain_signer_commitment,
                self.new_offchain_signer_commitment,
                Bytes::from(self.signature.clone()),
                self.sibling_nodes.clone(),
                self.nonce,
            )
            .call()
            .await
            .map(|_| ())
            .map_err(GatewayErrorResponse::from_simulation_error)
    }
}

// =============================================================================
// RecoverAccountRequest
// =============================================================================

impl RequestValidation for RecoverAccountRequest {
    fn pre_flight(
        &self,
        chain_id: u64,
        verifying_contract: Address,
    ) -> Result<(), GatewayErrorResponse> {
        let new_pubkey = self.new_authenticator_pubkey.unwrap_or(U256::ZERO);

        if self.leaf_index == 0 {
            return Err(GatewayErrorResponse::bad_request_message(
                "leaf_index cannot be zero".to_string(),
            ));
        }
        if self.new_authenticator_address.is_zero() {
            return Err(GatewayErrorResponse::bad_request_message(
                "new_authenticator_address cannot be zero".to_string(),
            ));
        }
        if self.old_offchain_signer_commitment.is_zero()
            || self.new_offchain_signer_commitment.is_zero()
        {
            return Err(GatewayErrorResponse::bad_request_message(
                "offchain signer commitment cannot be zero".to_string(),
            ));
        }

        // Verify ECDSA signature
        let typed_data = RecoverAccountTypedData {
            leafIndex: self.leaf_index,
            newAuthenticatorAddress: self.new_authenticator_address,
            newAuthenticatorPubkey: new_pubkey,
            newOffchainSignerCommitment: self.new_offchain_signer_commitment,
            nonce: self.nonce,
        };
        let _signer = recover_signer(&typed_data, &self.signature, chain_id, verifying_contract)?;

        Ok(())
    }

    fn calldata(&self, registry: &Registry) -> Bytes {
        let new_pubkey = self.new_authenticator_pubkey.unwrap_or(U256::ZERO);

        registry
            .recoverAccount(
                self.leaf_index,
                self.new_authenticator_address,
                new_pubkey,
                self.old_offchain_signer_commitment,
                self.new_offchain_signer_commitment,
                Bytes::from(self.signature.clone()),
                self.sibling_nodes.clone(),
                self.nonce,
            )
            .calldata()
            .clone()
    }

    async fn simulate(&self, registry: &Registry) -> Result<(), GatewayErrorResponse> {
        let new_pubkey = self.new_authenticator_pubkey.unwrap_or(U256::ZERO);

        registry
            .recoverAccount(
                self.leaf_index,
                self.new_authenticator_address,
                new_pubkey,
                self.old_offchain_signer_commitment,
                self.new_offchain_signer_commitment,
                Bytes::from(self.signature.clone()),
                self.sibling_nodes.clone(),
                self.nonce,
            )
            .call()
            .await
            .map_err(GatewayErrorResponse::from_simulation_error)?;

        Ok(())
    }
}
