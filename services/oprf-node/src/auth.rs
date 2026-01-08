//! This module implements the authentication process for World ID.
//!
//! During the user's session initialization, the MPC nodes uses this authentication service to determine whether a user is eligible to compute a nullifier.
//!
//! Additionally, it defines two sub-modules necessary for the authentication process.
//!
//! - [`merkle_watcher`] – watches the blockchain for merkle-root update events.
//! - [`signature_history`] – keeps track of nonce + time_stamp signatures to detect replays

use crate::auth::{
    merkle_watcher::{MerkleWatcher, MerkleWatcherError},
    signature_history::{DuplicateSignatureError, SignatureHistory},
};
use ark_bn254::Bn254;
use async_trait::async_trait;
use axum::{http::StatusCode, response::IntoResponse};
use circom_types::groth16::VerificationKey;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use taceo_oprf_service::OprfRequestAuthenticator;
use taceo_oprf_types::api::v1::OprfRequest;
use uuid::Uuid;
use world_id_primitives::{oprf::OprfRequestAuthV1, TREE_DEPTH};

/// The embedded Groth16 verification key for OPRF query proofs.
const QUERY_VERIFICATION_KEY: &str = include_str!("../../../circom/OPRFQuery.vk.json");

pub(crate) mod merkle_watcher;
pub(crate) mod signature_history;

/// Errors returned by the [`WorldOprfReqAuthenticator`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum OprfRequestAuthError {
    /// The client Groth16 proof did not verify.
    #[error("client proof did not verify")]
    InvalidProof,
    /// An error returned from the merkle watcher service during merkle look-up.
    #[error(transparent)]
    MerkleWatcherError(#[from] MerkleWatcherError),
    /// The current time stamp difference between client and service is larger than allowed.
    #[error("the time stamp difference is too large")]
    TimeStampDifference,
    /// A nonce signature was uses more than once
    #[error(transparent)]
    DuplicateSignatureError(#[from] DuplicateSignatureError),
    /// The provided merkle root is not valid
    #[error("invalid merkle root")]
    InvalidMerkleRoot,
    /// Internal server error
    #[error(transparent)]
    InternalServerError(#[from] eyre::Report),
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
            OprfRequestAuthError::TimeStampDifference => (
                StatusCode::BAD_REQUEST,
                "the time stamp difference is too large",
            )
                .into_response(),
            OprfRequestAuthError::DuplicateSignatureError(err) => {
                (StatusCode::BAD_REQUEST, err.to_string()).into_response()
            }
            OprfRequestAuthError::InvalidMerkleRoot => {
                (StatusCode::BAD_REQUEST, "invalid merkle root").into_response()
            }
            OprfRequestAuthError::InternalServerError(err) => {
                let error_id = Uuid::new_v4();
                tracing::error!("{error_id} - {err:?}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("An internal server error has occurred. Error ID={error_id}"),
                )
                    .into_response()
            }
        }
    }
}

pub(crate) struct WorldOprfRequestAuthenticator {
    merkle_watcher: MerkleWatcher,
    signature_history: SignatureHistory,
    vk: Arc<ark_groth16::PreparedVerifyingKey<Bn254>>,
    current_time_stamp_max_difference: Duration,
}

impl WorldOprfRequestAuthenticator {
    pub(crate) fn init(
        merkle_watcher: MerkleWatcher,
        current_time_stamp_max_difference: Duration,
        signature_history_cleanup_interval: Duration,
    ) -> Self {
        let vk: VerificationKey<Bn254> =
            serde_json::from_str(QUERY_VERIFICATION_KEY).expect("can deserialize embedded vk");
        Self {
            signature_history: SignatureHistory::init(
                current_time_stamp_max_difference * 2,
                signature_history_cleanup_interval,
            ),
            merkle_watcher,
            vk: Arc::new(ark_groth16::prepare_verifying_key(&vk.into())),
            current_time_stamp_max_difference,
        }
    }
}

#[async_trait]
impl OprfRequestAuthenticator for WorldOprfRequestAuthenticator {
    type RequestAuth = OprfRequestAuthV1;
    type RequestAuthError = OprfRequestAuthError;

    async fn verify(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<(), Self::RequestAuthError> {
        // check the time stamp against system time +/- difference
        let req_time_stamp = Duration::from_secs(request.auth.current_time_stamp);
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time is after unix epoch");
        if current_time.abs_diff(req_time_stamp) > self.current_time_stamp_max_difference {
            return Err(OprfRequestAuthError::TimeStampDifference);
        }

        // TODO check the RP nonce signature

        // add signature to history to check if the nonces where only used once
        self.signature_history
            .add_signature(request.auth.signature.to_vec(), req_time_stamp)?;

        // check if the merkle root is valid
        let valid = self
            .merkle_watcher
            .is_root_valid(request.auth.merkle_root.into())
            .await?;
        if !valid {
            return Err(OprfRequestAuthError::InvalidMerkleRoot)?;
        }

        // verify the user proof
        let public = [
            request.blinded_query.x,
            request.blinded_query.y,
            request.auth.merkle_root,
            ark_babyjubjub::Fq::from(TREE_DEPTH as u64),
            request.share_identifier.oprf_key_id.into(),
            request.auth.action,
            request.auth.nonce,
        ];

        tracing::debug!("verifying user proof...");
        let valid = ark_groth16::Groth16::<Bn254>::verify_proof(
            &self.vk,
            &request.auth.proof.clone().into(),
            &public,
        )
        .unwrap();
        if valid {
            tracing::debug!("proof valid");
            Ok(())
        } else {
            tracing::debug!("proof INVALID");
            Err(OprfRequestAuthError::InvalidProof)
        }
    }
}
