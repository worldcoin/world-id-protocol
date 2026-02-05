use crate::{
    auth::{
        merkle_watcher::MerkleWatcher,
        schema_issuer_registry_watcher::{
            SchemaIssuerRegistryWatcher, SchemaIssuerRegistryWatcherError,
        },
    },
    metrics::{METRICS_ID_NODE_REQUEST_AUTH_START, METRICS_ID_NODE_REQUEST_AUTH_VERIFIED},
};
use alloy::primitives::U160;
use ark_ff::AdditiveGroup;
use async_trait::async_trait;
use axum::{http::StatusCode, response::IntoResponse};
use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator},
};
use uuid::Uuid;
use world_id_primitives::oprf::CredentialBlindingFactorOprfRequestAuthV1;

/// Errors returned by the [`CredentialBlindingFactorOprfReqAuthenticator`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum CredentialBlindingFactorOprfRequestAuthError {
    /// An error returned from the CredentialSchemaIssuerRegistry watcher service.
    #[error(transparent)]
    SchemaIssuerRegistryWatcherError(#[from] SchemaIssuerRegistryWatcherError),
    /// The provided action is not valid (must be 0 for now, might change in the future)
    #[error("invalid action")]
    InvalidAction,
    /// Common OPRF request auth error
    #[error(transparent)]
    Common(#[from] crate::auth::OprfRequestAuthError),
    /// Internal server error
    #[error(transparent)]
    InternalServerError(#[from] eyre::Report),
}

impl IntoResponse for CredentialBlindingFactorOprfRequestAuthError {
    fn into_response(self) -> axum::response::Response {
        match self {
            CredentialBlindingFactorOprfRequestAuthError::SchemaIssuerRegistryWatcherError(err) => {
                tracing::error!("CredentialSchemaIssuerRegistry watcher error: {err}");
                (StatusCode::SERVICE_UNAVAILABLE.into_response()).into_response()
            }
            CredentialBlindingFactorOprfRequestAuthError::InvalidAction => (
                StatusCode::BAD_REQUEST,
                "invalid action (must be 0 for now)",
            )
                .into_response(),
            CredentialBlindingFactorOprfRequestAuthError::Common(err) => err.into_response(),
            CredentialBlindingFactorOprfRequestAuthError::InternalServerError(err) => {
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

pub(crate) struct CredentialBlindingFactorOprfRequestAuthenticator {
    schema_issuer_registry_watcher: SchemaIssuerRegistryWatcher,
    common: crate::auth::OprfRequestAuthenticator,
}

impl CredentialBlindingFactorOprfRequestAuthenticator {
    pub(crate) fn init(
        merkle_watcher: MerkleWatcher,
        schema_issuer_registry_watcher: SchemaIssuerRegistryWatcher,
    ) -> Self {
        Self {
            schema_issuer_registry_watcher,
            common: crate::auth::OprfRequestAuthenticator::init(merkle_watcher),
        }
    }
}

#[async_trait]
impl OprfRequestAuthenticator for CredentialBlindingFactorOprfRequestAuthenticator {
    type RequestAuth = CredentialBlindingFactorOprfRequestAuthV1;
    type RequestAuthError = CredentialBlindingFactorOprfRequestAuthError;

    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, Self::RequestAuthError> {
        ::metrics::counter!(METRICS_ID_NODE_REQUEST_AUTH_START).increment(1);

        // check that the action is valid (must be 0 for now, might change in the future)
        if request.auth.action != ark_babyjubjub::Fq::ZERO {
            return Err(CredentialBlindingFactorOprfRequestAuthError::InvalidAction);
        }

        let oprf_key_id = OprfKeyId::new(U160::from(request.auth.issuer_schema_id));

        // check that the issuer schema id is valid
        self.schema_issuer_registry_watcher
            .is_valid_issuer(request.auth.issuer_schema_id)
            .await?;

        // common verification
        self.common
            .verify(
                &request.auth.proof.clone().into(),
                request.blinded_query,
                request.auth.merkle_root,
                oprf_key_id,
                request.auth.action,
                request.auth.nonce,
            )
            .await?;

        ::metrics::counter!(METRICS_ID_NODE_REQUEST_AUTH_VERIFIED).increment(1);

        Ok(oprf_key_id)
    }
}
