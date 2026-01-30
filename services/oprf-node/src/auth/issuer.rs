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
use async_trait::async_trait;
use axum::{http::StatusCode, response::IntoResponse};
use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator},
};
use uuid::Uuid;
use world_id_primitives::oprf::SchemaIssuerOprfRequestAuthV1;

/// Errors returned by the [`SchemaIssuerOprfReqAuthenticator`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum SchemaIssuerOprfRequestAuthError {
    /// An error returned from the CredentialSchemaIssuerRegistry watcher service.
    #[error(transparent)]
    SchemaIssuerRegistryWatcherError(#[from] SchemaIssuerRegistryWatcherError),
    /// The provided OprfKeyId does not match the issuer schema id.
    #[error("oprf key id mismatch")]
    OprfKeyIdMismatch,
    /// Common OPRF request auth error
    #[error(transparent)]
    Common(#[from] crate::auth::OprfRequestAuthError),
    /// Internal server error
    #[error(transparent)]
    InternalServerError(#[from] eyre::Report),
}

impl IntoResponse for SchemaIssuerOprfRequestAuthError {
    fn into_response(self) -> axum::response::Response {
        match self {
            SchemaIssuerOprfRequestAuthError::SchemaIssuerRegistryWatcherError(err) => {
                tracing::error!("CredentialSchemaIssuerRegistry watcher error: {err}");
                (StatusCode::SERVICE_UNAVAILABLE.into_response()).into_response()
            }
            SchemaIssuerOprfRequestAuthError::OprfKeyIdMismatch => {
                (StatusCode::BAD_REQUEST, "oprf key id mismatch").into_response()
            }
            SchemaIssuerOprfRequestAuthError::Common(err) => err.into_response(),
            SchemaIssuerOprfRequestAuthError::InternalServerError(err) => {
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

pub(crate) struct SchemaIssuerOprfRequestAuthenticator {
    schema_issuer_registry_watcher: SchemaIssuerRegistryWatcher,
    common: crate::auth::OprfRequestAuthenticator,
}

impl SchemaIssuerOprfRequestAuthenticator {
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
impl OprfRequestAuthenticator for SchemaIssuerOprfRequestAuthenticator {
    type RequestAuth = SchemaIssuerOprfRequestAuthV1;
    type RequestAuthError = SchemaIssuerOprfRequestAuthError;

    async fn verify(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<(), Self::RequestAuthError> {
        ::metrics::counter!(METRICS_ID_NODE_REQUEST_AUTH_START).increment(1);

        // TODO verify that action is some specific value?

        // check if the oprf key id matches the issuer schema id
        if OprfKeyId::new(U160::from(request.auth.issuer_schema_id))
            != request.share_identifier.oprf_key_id
        {
            return Err(SchemaIssuerOprfRequestAuthError::OprfKeyIdMismatch);
        }

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
                request.share_identifier.oprf_key_id,
                request.auth.action,
                request.auth.nonce,
            )
            .await?;

        ::metrics::counter!(METRICS_ID_NODE_REQUEST_AUTH_VERIFIED).increment(1);

        Ok(())
    }
}
