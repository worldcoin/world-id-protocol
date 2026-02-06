//! This module implements the authentication process for World ID.
//!
//! During the user's session initialization, the MPC nodes uses this authentication service to determine whether a user is eligible to compute a nullifier.
//!
//! Additionally, it defines two sub-modules necessary for the authentication process.
//!
//! - [`credential_blinding_factor`] – implements authentication for OPRF credential blinding factor generation.
//! - [`merkle_watcher`] – watches the blockchain for merkle-root update events.
//! - [`nullifier`] – implements authentication for OPRF nullifier generation.
//! - [`rp_registry_watcher`] – keeps track of registered RPs
//! - [`schema_issuer_registry_watcher`] – keeps track of registered Credential Schema Issuers
//! - [`signature_history`] – keeps track of nonce + time_stamp signatures to detect replays

use std::sync::Arc;

use ark_bn254::Bn254;
use axum::{http::StatusCode, response::IntoResponse};
use circom_types::groth16::VerificationKey;
use taceo_oprf::types::OprfKeyId;
use world_id_primitives::TREE_DEPTH;

use crate::auth::merkle_watcher::{MerkleWatcher, MerkleWatcherError};

/// The embedded Groth16 verification key for OPRF query proofs.
const QUERY_VERIFICATION_KEY: &str = include_str!("../../../circom/OPRFQuery.vk.json");

pub(crate) mod credential_blinding_factor;
pub(crate) mod merkle_watcher;
pub(crate) mod nullifier;
pub(crate) mod rp_registry_watcher;
pub(crate) mod schema_issuer_registry_watcher;
pub(crate) mod signature_history;

/// Common errors returned by the [`NullifierOprfRequestAuthenticator`] and [`CredentialBlindingFactorOprfRequestAuthenticator`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum OprfRequestAuthError {
    /// The client Groth16 proof did not verify.
    #[error("client proof did not verify")]
    InvalidProof,
    /// The provided merkle root is not valid
    #[error("invalid merkle root")]
    InvalidMerkleRoot,
    /// An error returned from the merkle watcher service during merkle look-up.
    #[error(transparent)]
    MerkleWatcherError(#[from] MerkleWatcherError),
}

impl IntoResponse for OprfRequestAuthError {
    fn into_response(self) -> axum::response::Response {
        match self {
            OprfRequestAuthError::InvalidProof => {
                (StatusCode::BAD_REQUEST, "invalid proof").into_response()
            }
            OprfRequestAuthError::MerkleWatcherError(err) => {
                tracing::error!("merkle watcher error: {err}");
                (StatusCode::SERVICE_UNAVAILABLE.into_response()).into_response()
            }
            OprfRequestAuthError::InvalidMerkleRoot => {
                (StatusCode::BAD_REQUEST, "invalid merkle root").into_response()
            }
        }
    }
}

/// Common authentication for [`NullifierOprfRequestAuthenticator`] and [`CredentialBlindingFactorOprfRequestAuthenticator`].
pub(crate) struct OprfRequestAuthenticator {
    merkle_watcher: MerkleWatcher,
    vk: Arc<ark_groth16::PreparedVerifyingKey<Bn254>>,
}

impl OprfRequestAuthenticator {
    pub(crate) fn init(merkle_watcher: MerkleWatcher) -> Self {
        let vk: VerificationKey<Bn254> =
            serde_json::from_str(QUERY_VERIFICATION_KEY).expect("can deserialize embedded vk");
        Self {
            merkle_watcher,
            vk: Arc::new(ark_groth16::prepare_verifying_key(&vk.into())),
        }
    }

    pub(crate) async fn verify(
        &self,
        proof: &ark_groth16::Proof<Bn254>,
        blinded_query: ark_babyjubjub::EdwardsAffine,
        merkle_root: ark_babyjubjub::Fq,
        oprf_key_id: OprfKeyId,
        action: ark_babyjubjub::Fq,
        nonce: ark_babyjubjub::Fq,
    ) -> Result<(), OprfRequestAuthError> {
        tracing::debug!("checking if merkle root is valid...");
        let valid = self
            .merkle_watcher
            .is_root_valid(merkle_root.into())
            .await?;
        if !valid {
            tracing::debug!("merkle root INVALID");
            return Err(OprfRequestAuthError::InvalidMerkleRoot)?;
        }

        tracing::debug!("verifying user proof...");
        let public = [
            blinded_query.x,
            blinded_query.y,
            merkle_root,
            ark_babyjubjub::Fq::from(TREE_DEPTH as u64),
            oprf_key_id.into(),
            action,
            nonce,
        ];
        let valid = ark_groth16::Groth16::<Bn254>::verify_proof(&self.vk, proof, &public)
            .expect("We expect that we loaded the correct key");
        if valid {
            tracing::debug!("proof valid");
            Ok(())
        } else {
            tracing::debug!("proof INVALID");
            Err(OprfRequestAuthError::InvalidProof)
        }
    }
}
