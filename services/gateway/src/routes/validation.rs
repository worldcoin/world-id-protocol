use tokio::sync::OnceCell;

use crate::error::GatewayErrorResponse;
use alloy::{
    primitives::{Address, Bytes, Signature, TxKind, U256},
    providers::Provider,
    rpc::types::{BlockId, TransactionRequest},
    sol_types::{Eip712Domain, SolStruct, eip712_domain},
};
use world_id_core::{
    api_types::{
        CancelRecoveryAgentUpdateRequest, CreateAccountRequest, ExecuteRecoveryAgentUpdateRequest,
        InsertAuthenticatorRequest, RecoverAccountRequest, RemoveAuthenticatorRequest,
        UpdateAuthenticatorRequest, UpdateRecoveryAgentRequest,
    },
    world_id_registry::{
        CancelRecoveryAgentUpdateTypedData, InitiateRecoveryAgentUpdateTypedData,
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

    /// Full validation: pre-flight checks (including signature verification), contract simulation,
    /// and returns the already-encoded calldata for submission.
    fn validate_and_calldata(
        &self,
        registry: &Registry,
    ) -> impl Future<Output = Result<Bytes, GatewayErrorResponse>> + Send {
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
            let calldata = self.calldata(registry);
            simulate_calldata(registry, &calldata).await?;
            Ok(calldata)
        }
    }
}

async fn simulate_calldata(
    registry: &Registry,
    calldata: &Bytes,
) -> Result<(), GatewayErrorResponse> {
    let tx = TransactionRequest {
        to: Some(TxKind::Call(*registry.address())),
        input: calldata.clone().into(),
        ..Default::default()
    };

    registry
        .provider()
        .call(tx)
        .block(BlockId::default())
        .await
        .map(|_| ())
        .map_err(GatewayErrorResponse::from_simulation_error)
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
                self.nonce,
            )
            .calldata()
            .clone()
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
                self.nonce,
            )
            .calldata()
            .clone()
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
                self.nonce,
            )
            .calldata()
            .clone()
    }
}

// =============================================================================
// UpdateRecoveryAgentRequest (initiateRecoveryAgentUpdate)
// =============================================================================
impl RequestValidation for UpdateRecoveryAgentRequest {
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
        if self.new_recovery_agent.is_zero() {
            return Err(GatewayErrorResponse::bad_request_message(
                "new_recovery_agent cannot be the zero address".to_string(),
            ));
        }

        // Verify EIP-712 signature format and recoverability.
        //
        // The EIP-712 typehash used here matches the contract's
        // `INITIATE_RECOVERY_AGENT_UPDATE_TYPEHASH` (uint64 leafIndex):
        //   "InitiateRecoveryAgentUpdate(uint64 leafIndex,address newRecoveryAgent,uint256 nonce)"
        //
        // Authorization (i.e. whether the signer owns the leaf) is fully enforced
        // by the contract during on-chain execution. The gateway only needs to
        // confirm the signature is structurally valid and recoverable — the same
        // pattern used by InsertAuthenticatorRequest and RemoveAuthenticatorRequest.
        let typed_data = InitiateRecoveryAgentUpdateTypedData {
            leafIndex: self.leaf_index,
            newRecoveryAgent: self.new_recovery_agent,
            nonce: self.nonce,
        };
        let _signer = recover_signer(&typed_data, &self.signature, chain_id, verifying_contract)?;

        Ok(())
    }

    fn calldata(&self, registry: &Registry) -> Bytes {
        registry
            .initiateRecoveryAgentUpdate(
                self.leaf_index,
                self.new_recovery_agent,
                Bytes::from(self.signature.clone()),
                self.nonce,
            )
            .calldata()
            .clone()
    }
}

// =============================================================================
// CancelRecoveryAgentUpdateRequest (cancelRecoveryAgentUpdate)
// =============================================================================
impl RequestValidation for CancelRecoveryAgentUpdateRequest {
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

        // Verify EIP-712 signature format and recoverability.
        //
        // The EIP-712 typehash used here matches the contract's
        // `CANCEL_RECOVERY_AGENT_UPDATE_TYPEHASH` (uint64 leafIndex):
        //   "CancelRecoveryAgentUpdate(uint64 leafIndex,uint256 nonce)"
        //
        // Authorization is enforced by the contract; the gateway checks only
        // that the signature is structurally valid and recoverable.
        let typed_data = CancelRecoveryAgentUpdateTypedData {
            leafIndex: self.leaf_index,
            nonce: self.nonce,
        };
        let _signer = recover_signer(&typed_data, &self.signature, chain_id, verifying_contract)?;

        Ok(())
    }

    fn calldata(&self, registry: &Registry) -> Bytes {
        registry
            .cancelRecoveryAgentUpdate(
                self.leaf_index,
                Bytes::from(self.signature.clone()),
                self.nonce,
            )
            .calldata()
            .clone()
    }
}

// =============================================================================
// ExecuteRecoveryAgentUpdateRequest (executeRecoveryAgentUpdate)
// =============================================================================
impl RequestValidation for ExecuteRecoveryAgentUpdateRequest {
    fn pre_flight(
        &self,
        _chain_id: u64,
        _verifying_contract: Address,
    ) -> Result<(), GatewayErrorResponse> {
        // executeRecoveryAgentUpdate is permissionless — no signature to verify.
        // The contract enforces cooldown; simulate_calldata will surface
        // RecoveryAgentUpdateStillInCooldown or NoPendingRecoveryAgentUpdate if
        // called too early or without a pending update.
        if self.leaf_index == 0 {
            return Err(GatewayErrorResponse::bad_request_message(
                "leaf_index cannot be zero".to_string(),
            ));
        }
        Ok(())
    }

    fn calldata(&self, registry: &Registry) -> Bytes {
        registry
            .executeRecoveryAgentUpdate(self.leaf_index)
            .calldata()
            .clone()
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
                self.nonce,
            )
            .calldata()
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        primitives::{Address, U256, address},
        signers::local::PrivateKeySigner,
    };
    use world_id_core::{
        api_types::{
            CancelRecoveryAgentUpdateRequest, ExecuteRecoveryAgentUpdateRequest,
            UpdateRecoveryAgentRequest,
        },
        world_id_registry::{
            domain as registry_domain, sign_cancel_recovery_agent_update,
            sign_initiate_recovery_agent_update,
        },
    };

    const CHAIN_ID: u64 = 1;
    const CONTRACT: Address = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    fn make_domain() -> alloy::sol_types::Eip712Domain {
        registry_domain(CHAIN_ID, CONTRACT)
    }

    // ------------------------------------------------------------------
    // UpdateRecoveryAgentRequest (initiateRecoveryAgentUpdate) pre_flight
    // ------------------------------------------------------------------

    #[test]
    fn initiate_preflight_rejects_zero_leaf_index() {
        let signer = PrivateKeySigner::random();
        let domain = make_domain();
        let non_zero_agent: Address = address!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let sig = sign_initiate_recovery_agent_update(
            &signer,
            0,
            non_zero_agent,
            U256::ZERO,
            &domain,
        )
        .unwrap();

        let req = UpdateRecoveryAgentRequest {
            leaf_index: 0,
            new_recovery_agent: non_zero_agent,
            signature: sig.as_bytes().to_vec(),
            nonce: U256::ZERO,
        };
        assert!(req.pre_flight(CHAIN_ID, CONTRACT).is_err());
    }

    #[test]
    fn initiate_preflight_rejects_zero_recovery_agent() {
        let signer = PrivateKeySigner::random();
        let domain = make_domain();
        let sig = sign_initiate_recovery_agent_update(
            &signer,
            1,
            Address::ZERO,
            U256::ZERO,
            &domain,
        )
        .unwrap();

        let req = UpdateRecoveryAgentRequest {
            leaf_index: 1,
            new_recovery_agent: Address::ZERO,
            signature: sig.as_bytes().to_vec(),
            nonce: U256::ZERO,
        };
        assert!(req.pre_flight(CHAIN_ID, CONTRACT).is_err());
    }

    #[test]
    fn initiate_preflight_accepts_valid_signature() {
        let signer = PrivateKeySigner::random();
        let domain = make_domain();
        let leaf_index = 1u64;
        let new_recovery_agent: Address = address!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let nonce = U256::from(5u64);

        let sig =
            sign_initiate_recovery_agent_update(&signer, leaf_index, new_recovery_agent, nonce, &domain)
                .unwrap();

        let req = UpdateRecoveryAgentRequest {
            leaf_index,
            new_recovery_agent,
            signature: sig.as_bytes().to_vec(),
            nonce,
        };
        assert!(req.pre_flight(CHAIN_ID, CONTRACT).is_ok());
    }

    #[test]
    fn initiate_preflight_rejects_bad_signature() {
        let req = UpdateRecoveryAgentRequest {
            leaf_index: 1,
            new_recovery_agent: address!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            signature: vec![0u8; 65],
            nonce: U256::ZERO,
        };
        // all-zero signature is explicitly rejected by validate_ecdsa_signature_format
        assert!(req.pre_flight(CHAIN_ID, CONTRACT).is_err());
    }

    // ------------------------------------------------------------------
    // CancelRecoveryAgentUpdateRequest pre_flight
    // ------------------------------------------------------------------

    #[test]
    fn cancel_preflight_rejects_zero_leaf_index() {
        let signer = PrivateKeySigner::random();
        let domain = make_domain();
        let sig =
            sign_cancel_recovery_agent_update(&signer, 0, U256::ZERO, &domain).unwrap();

        let req = CancelRecoveryAgentUpdateRequest {
            leaf_index: 0,
            signature: sig.as_bytes().to_vec(),
            nonce: U256::ZERO,
        };
        assert!(req.pre_flight(CHAIN_ID, CONTRACT).is_err());
    }

    #[test]
    fn cancel_preflight_accepts_valid_signature() {
        let signer = PrivateKeySigner::random();
        let domain = make_domain();
        let leaf_index = 7u64;
        let nonce = U256::from(2u64);

        let sig = sign_cancel_recovery_agent_update(&signer, leaf_index, nonce, &domain).unwrap();

        let req = CancelRecoveryAgentUpdateRequest {
            leaf_index,
            signature: sig.as_bytes().to_vec(),
            nonce,
        };
        assert!(req.pre_flight(CHAIN_ID, CONTRACT).is_ok());
    }

    #[test]
    fn cancel_preflight_rejects_wrong_length_signature() {
        let req = CancelRecoveryAgentUpdateRequest {
            leaf_index: 1,
            signature: vec![0u8; 32], // wrong length
            nonce: U256::ZERO,
        };
        assert!(req.pre_flight(CHAIN_ID, CONTRACT).is_err());
    }

    // ------------------------------------------------------------------
    // ExecuteRecoveryAgentUpdateRequest pre_flight
    // ------------------------------------------------------------------

    #[test]
    fn execute_preflight_rejects_zero_leaf_index() {
        let req = ExecuteRecoveryAgentUpdateRequest { leaf_index: 0 };
        assert!(req.pre_flight(CHAIN_ID, CONTRACT).is_err());
    }

    #[test]
    fn execute_preflight_accepts_nonzero_leaf_index() {
        let req = ExecuteRecoveryAgentUpdateRequest { leaf_index: 1 };
        // pre_flight itself passes; simulate_calldata (eth_call) would catch
        // premature calls but we don't exercise that in a pure unit test.
        assert!(req.pre_flight(CHAIN_ID, CONTRACT).is_ok());
    }
}
