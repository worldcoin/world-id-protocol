use crate::{
    auth::{
        merkle_watcher::MerkleWatcher,
        rp_registry_watcher::{RpRegistryWatcher, RpRegistryWatcherError},
        signature_history::{DuplicateSignatureError, SignatureHistory},
    },
    metrics::{METRICS_ID_NODE_REQUEST_AUTH_START, METRICS_ID_NODE_REQUEST_AUTH_VERIFIED},
};
use async_trait::async_trait;
use axum::{http::StatusCode, response::IntoResponse};
use std::time::{Duration, SystemTime};
use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator},
};
use uuid::Uuid;
use world_id_primitives::oprf::NullifierOprfRequestAuthV1;

/// Errors returned by the [`NullifierOprfReqAuthenticator`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum NullifierOprfRequestAuthError {
    /// An error returned from the RpRegistry watcher service during merkle look-up.
    #[error(transparent)]
    RpRegistryWatcherError(#[from] RpRegistryWatcherError),
    /// The current time stamp difference between client and service is larger than allowed.
    #[error("the time stamp difference is too large")]
    TimeStampDifference,
    /// A nonce signature was uses more than once
    #[error(transparent)]
    DuplicateSignatureError(#[from] DuplicateSignatureError),
    /// The signature over the nonce and time stamp is invalid
    #[error(transparent)]
    InvalidSignature(#[from] alloy::primitives::SignatureError),
    /// Rp signature signer is invalid
    #[error("the rp signer is not the same as in the signature")]
    InvalidSigner,
    /// Common OPRF request auth error
    #[error(transparent)]
    Common(#[from] crate::auth::OprfRequestAuthError),
    /// Internal server error
    #[error(transparent)]
    InternalServerError(#[from] eyre::Report),
}

impl IntoResponse for NullifierOprfRequestAuthError {
    fn into_response(self) -> axum::response::Response {
        match self {
            NullifierOprfRequestAuthError::RpRegistryWatcherError(err) => {
                tracing::error!("RpRegistry watcher error: {err}");
                (StatusCode::SERVICE_UNAVAILABLE.into_response()).into_response()
            }
            NullifierOprfRequestAuthError::TimeStampDifference => (
                StatusCode::BAD_REQUEST,
                "the time stamp difference is too large",
            )
                .into_response(),
            NullifierOprfRequestAuthError::InvalidSignature(err) => {
                (StatusCode::BAD_REQUEST, err.to_string()).into_response()
            }
            NullifierOprfRequestAuthError::InvalidSigner => {
                (StatusCode::BAD_REQUEST, "invalid signer").into_response()
            }
            NullifierOprfRequestAuthError::Common(err) => err.into_response(),
            NullifierOprfRequestAuthError::DuplicateSignatureError(err) => {
                (StatusCode::BAD_REQUEST, err.to_string()).into_response()
            }
            NullifierOprfRequestAuthError::InternalServerError(err) => {
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

pub(crate) struct NullifierOprfRequestAuthenticator {
    rp_registry_watcher: RpRegistryWatcher,
    signature_history: SignatureHistory,
    current_time_stamp_max_difference: Duration,
    common: crate::auth::OprfRequestAuthenticator,
}

impl NullifierOprfRequestAuthenticator {
    pub(crate) fn init(
        merkle_watcher: MerkleWatcher,
        rp_registry_watcher: RpRegistryWatcher,
        signature_history: SignatureHistory,
        current_time_stamp_max_difference: Duration,
    ) -> Self {
        Self {
            rp_registry_watcher,
            signature_history,
            current_time_stamp_max_difference,
            common: crate::auth::OprfRequestAuthenticator::init(merkle_watcher),
        }
    }
}

#[async_trait]
impl OprfRequestAuthenticator for NullifierOprfRequestAuthenticator {
    type RequestAuth = NullifierOprfRequestAuthV1;
    type RequestAuthError = NullifierOprfRequestAuthError;

    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, Self::RequestAuthError> {
        ::metrics::counter!(METRICS_ID_NODE_REQUEST_AUTH_START).increment(1);

        // check the time stamp against system time +/- difference
        let req_time_stamp = Duration::from_secs(request.auth.current_time_stamp);
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time is after unix epoch");
        if current_time.abs_diff(req_time_stamp) > self.current_time_stamp_max_difference {
            return Err(NullifierOprfRequestAuthError::TimeStampDifference);
        }

        // fetch the RP info
        let rp = self.rp_registry_watcher.get_rp(&request.auth.rp_id).await?;

        // check the RP nonce signature
        let msg = world_id_primitives::rp::compute_rp_signature_msg(
            request.auth.nonce,
            request.auth.current_time_stamp,
            request.auth.expiration_timestamp,
        );

        let recovered = request.auth.signature.recover_address_from_msg(&msg)?;
        if recovered != rp.signer {
            return Err(NullifierOprfRequestAuthError::InvalidSigner);
        }

        // add signature to history to check if the nonces where only used once
        self.signature_history
            .add_signature(request.auth.signature.as_bytes().to_vec())
            .await?;

        // common verification
        self.common
            .verify(
                &request.auth.proof.clone().into(),
                request.blinded_query,
                request.auth.merkle_root,
                rp.oprf_key_id,
                request.auth.action,
                request.auth.nonce,
            )
            .await?;

        ::metrics::counter!(METRICS_ID_NODE_REQUEST_AUTH_VERIFIED).increment(1);

        Ok(rp.oprf_key_id)
    }
}
