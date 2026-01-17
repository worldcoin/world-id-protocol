//! Issuer-side verification helpers for issuer authentication proofs.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use alloy::primitives::Address;
use ark_bn254::Bn254;
use ark_groth16::PreparedVerifyingKey;
use circom_types::groth16::VerificationKey;
use eddsa_babyjubjub::EdDSAPublicKey;
use std::sync::Mutex;
use world_id_primitives::{FieldElement, TREE_DEPTH};

use crate::requests::{issuer_auth_rp_id, IssuerAuthRequest, IssuerAuthResponse};

/// Errors that can occur when verifying issuer authentication proofs.
#[derive(Debug, thiserror::Error)]
pub enum IssuerAuthVerificationError {
    /// Request/response version mismatch.
    #[error("request and response versions do not match")]
    VersionMismatch,
    /// Request/response id mismatch.
    #[error("request and response ids do not match")]
    RequestIdMismatch,
    /// Request expired.
    #[error("issuer auth request has expired")]
    RequestExpired,
    /// Request created in the future.
    #[error("issuer auth request is from the future")]
    RequestFromFuture,
    /// Signature mismatch or invalid.
    #[error("issuer auth request signature is invalid")]
    InvalidSignature,
    /// Issuer schema id mismatch.
    #[error("issuer schema id does not match expected value")]
    IssuerSchemaMismatch,
    /// Issuer signer address mismatch.
    #[error("issuer signer does not match expected value")]
    IssuerSignerMismatch,
    /// Replay detected.
    #[error("issuer auth request signature has been used already")]
    ReplayDetected,
    /// Merkle root invalid.
    #[error("merkle root is invalid")]
    InvalidMerkleRoot,
    /// Proof verification failed.
    #[error("issuer auth proof verification failed")]
    InvalidProof,
    /// Internal error.
    #[error("{0}")]
    Internal(String),
}

/// Context required to verify issuer authentication proofs.
#[derive(Clone, Copy)]
pub struct IssuerAuthVerificationContext<'a> {
    /// Expected issuer schema id for the credential.
    pub expected_schema_id: u64,
    /// Expected signer address for the issuer request.
    pub expected_signer: Address,
    /// Issuer public key for the credential.
    pub issuer_pubkey: &'a EdDSAPublicKey,
    /// Chain id for the EIP-712 domain.
    pub chain_id: u64,
}

/// Replay protection for issuer auth requests.
#[derive(Clone)]
pub struct IssuerAuthReplayProtection {
    signatures: Arc<Mutex<HashMap<Vec<u8>, Duration>>>,
}

impl IssuerAuthReplayProtection {
    /// Initialize replay protection with automatic cleanup.
    ///
    /// # Panics
    /// Panics if called outside of a Tokio runtime.
    #[must_use]
    pub fn new(max_signature_age: Duration, cleanup_interval: Duration) -> Self {
        let signatures = Arc::new(Mutex::new(HashMap::new()));
        let guard = signatures.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                let current_time = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0));
                guard
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .retain(|_, ts| current_time.saturating_sub(*ts) < max_signature_age);
            }
        });
        Self { signatures }
    }

    /// Checks and inserts a signature timestamp, returning an error on replay.
    ///
    /// # Errors
    /// Returns `ReplayDetected` if the signature was already used.
    pub fn check_and_insert(
        &self,
        signature: &[u8],
        timestamp: Duration,
    ) -> Result<(), IssuerAuthVerificationError> {
        let mut guard = self
            .signatures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.contains_key(signature) {
            return Err(IssuerAuthVerificationError::ReplayDetected);
        }
        guard.insert(signature.to_vec(), timestamp);
        drop(guard);
        Ok(())
    }
}

/// Verifier for issuer auth proofs.
pub struct IssuerAuthVerifier {
    vk: Arc<PreparedVerifyingKey<Bn254>>,
    replay_protection: IssuerAuthReplayProtection,
}

impl IssuerAuthVerifier {
    /// Create a verifier from a query proof verification key.
    #[must_use]
    pub fn new(
        vk: VerificationKey<Bn254>,
        replay_protection: IssuerAuthReplayProtection,
    ) -> Self {
        let ark_vk: ark_groth16::VerifyingKey<Bn254> = vk.into();
        Self {
            vk: Arc::new(ark_groth16::prepare_verifying_key(&ark_vk)),
            replay_protection,
        }
    }

    /// Verify a response using an explicit root validity check.
    ///
    /// # Errors
    /// Returns `IssuerAuthVerificationError` if any signature, replay, root, or proof checks fail.
    pub fn verify_with_root(
        &self,
        request: &IssuerAuthRequest,
        response: &IssuerAuthResponse,
        context: IssuerAuthVerificationContext<'_>,
        root_is_valid: bool,
    ) -> Result<(), IssuerAuthVerificationError> {
        if request.id != response.id {
            return Err(IssuerAuthVerificationError::RequestIdMismatch);
        }
        if request.version != response.version {
            return Err(IssuerAuthVerificationError::VersionMismatch);
        }
        if request.issuer_schema_id != context.expected_schema_id {
            return Err(IssuerAuthVerificationError::IssuerSchemaMismatch);
        }
        if request.issuer_signer != context.expected_signer {
            return Err(IssuerAuthVerificationError::IssuerSignerMismatch);
        }

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| IssuerAuthVerificationError::Internal(e.to_string()))?
            .as_secs();
        if request.is_from_future(now) {
            return Err(IssuerAuthVerificationError::RequestFromFuture);
        }
        if request.is_expired(now) {
            return Err(IssuerAuthVerificationError::RequestExpired);
        }

        request
            .verify_signature(context.chain_id)
            .map_err(|_| IssuerAuthVerificationError::InvalidSignature)?;

        self.replay_protection.check_and_insert(
            request.signature.as_bytes(),
            Duration::from_secs(request.created_at),
        )?;

        if !root_is_valid {
            return Err(IssuerAuthVerificationError::InvalidMerkleRoot);
        }

        let rp_id = issuer_auth_rp_id(request.issuer_schema_id);
        let rp_id_field: FieldElement = rp_id.into();

        let public = [
            *response.blinded_query.x,
            *response.blinded_query.y,
            *FieldElement::from(request.issuer_schema_id),
            context.issuer_pubkey.pk.x,
            context.issuer_pubkey.pk.y,
            *FieldElement::from(request.created_at),
            *response.proof.merkle_root,
            ark_babyjubjub::Fq::from(TREE_DEPTH as u64),
            *rp_id_field,
            *request.action,
            *request.nonce,
        ];

        let valid = ark_groth16::Groth16::<Bn254>::verify_proof(
            &self.vk,
            &response.proof.zkp,
            &public,
        )
        .map_err(|e| IssuerAuthVerificationError::Internal(e.to_string()))?;

        if !valid {
            return Err(IssuerAuthVerificationError::InvalidProof);
        }

        Ok(())
    }

    /// Verify a response using `WorldIDRegistry.isValidRoot` if a registry instance is provided.
    ///
    /// # Errors
    /// Returns `IssuerAuthVerificationError` if root lookup or proof validation fails.
    #[cfg(feature = "authenticator")]
    pub async fn verify_with_registry(
        &self,
        request: &IssuerAuthRequest,
        response: &IssuerAuthResponse,
        context: IssuerAuthVerificationContext<'_>,
        registry: &crate::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance<
            alloy::providers::DynProvider,
        >,
    ) -> Result<(), IssuerAuthVerificationError> {
        let root_is_valid = registry
            .isValidRoot(response.proof.merkle_root.into())
            .call()
            .await
            .map_err(|e| IssuerAuthVerificationError::Internal(e.to_string()))?;
        self.verify_with_root(
            request,
            response,
            context,
            root_is_valid,
        )
    }
}
