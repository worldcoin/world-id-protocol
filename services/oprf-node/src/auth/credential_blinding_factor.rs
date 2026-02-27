use crate::auth::{
    merkle_watcher::MerkleWatcher,
    schema_issuer_registry_watcher::{
        SchemaIssuerRegistryWatcher, SchemaIssuerRegistryWatcherError,
    },
};
use alloy::primitives::U160;
use ark_ff::AdditiveGroup;
use async_trait::async_trait;
use axum::{http::StatusCode, response::IntoResponse};
use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator},
};
use tracing::instrument;
use uuid::Uuid;
use world_id_primitives::oprf::{CredentialBlindingFactorOprfRequestAuthV1, OprfRequestErrorResponse};

/// Errors returned by the [`CredentialBlindingFactorOprfRequestAuthenticator`].
#[derive(Debug)]
pub(crate) enum CredentialBlindingFactorOprfRequestAuthError {
    /// An error returned from the CredentialSchemaIssuerRegistry watcher service.
    SchemaIssuerRegistryWatcherError(SchemaIssuerRegistryWatcherError),
    /// The provided action is not valid (must be 0 for now, might change in the future).
    InvalidAction,
    /// Common OPRF request auth error.
    Common(crate::auth::OprfRequestAuthError),
    /// Internal server error.
    InternalServerError(eyre::Report),
}

impl From<SchemaIssuerRegistryWatcherError> for CredentialBlindingFactorOprfRequestAuthError {
    fn from(err: SchemaIssuerRegistryWatcherError) -> Self {
        Self::SchemaIssuerRegistryWatcherError(err)
    }
}

impl From<crate::auth::OprfRequestAuthError> for CredentialBlindingFactorOprfRequestAuthError {
    fn from(err: crate::auth::OprfRequestAuthError) -> Self {
        Self::Common(err)
    }
}

impl From<eyre::Report> for CredentialBlindingFactorOprfRequestAuthError {
    fn from(err: eyre::Report) -> Self {
        Self::InternalServerError(err)
    }
}

impl CredentialBlindingFactorOprfRequestAuthError {
    /// Lossy conversion to the compact wire-format error response.
    ///
    /// Internal details (e.g. alloy RPC errors, eyre chains) are
    /// intentionally dropped — only a client-safe error code survives.
    pub(crate) fn to_oprf_response(&self) -> OprfRequestErrorResponse {
        match self {
            Self::SchemaIssuerRegistryWatcherError(
                SchemaIssuerRegistryWatcherError::UnknownSchemaIssuer(id),
            ) => OprfRequestErrorResponse::UnknownSchemaIssuer {
                issuer_schema_id: format!("{id}"),
            },
            Self::SchemaIssuerRegistryWatcherError(
                SchemaIssuerRegistryWatcherError::AlloyError(_),
            ) => OprfRequestErrorResponse::ServiceUnavailable,
            Self::InvalidAction => OprfRequestErrorResponse::InvalidAction,
            Self::Common(err) => err.to_oprf_response(),
            Self::InternalServerError(_) => {
                let error_id = Uuid::new_v4();
                tracing::error!("{error_id} - {:?}", self);
                OprfRequestErrorResponse::InternalServerError {
                    error_id: error_id.to_string(),
                }
            }
        }
    }
}

/// `taceo-oprf-service` calls `.to_string()` on auth errors to build the
/// WebSocket close frame reason, so `Display` must emit the structured JSON
/// that clients parse back into [`OprfRequestErrorResponse`].
impl std::fmt::Display for CredentialBlindingFactorOprfRequestAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_oprf_response().to_json())
    }
}

impl std::error::Error for CredentialBlindingFactorOprfRequestAuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SchemaIssuerRegistryWatcherError(e) => Some(e),
            Self::Common(e) => Some(e),
            Self::InternalServerError(e) => Some(e.as_ref()),
            _ => None,
        }
    }
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

    #[instrument(level = "debug", skip_all)]
    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, Self::RequestAuthError> {
        tracing::trace!("checking that action is not 0...");
        // check that the action is valid (must be 0 for now, might change in the future)
        if request.auth.action != ark_babyjubjub::Fq::ZERO {
            return Err(CredentialBlindingFactorOprfRequestAuthError::InvalidAction);
        }

        let oprf_key_id = OprfKeyId::new(U160::from(request.auth.issuer_schema_id));

        tracing::trace!("checking schema-issuer...");
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

        tracing::trace!("authentication successful!");
        Ok(oprf_key_id)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use secrecy::ExposeSecret as _;
    use taceo_oprf::{
        core::oprf::BlindingFactor,
        service::StartedServices,
        types::api::{OprfRequest, OprfRequestAuthenticator as _},
    };
    use uuid::Uuid;
    use world_id_core::{FieldElement, proof::errors};
    use world_id_primitives::{
        TREE_DEPTH, circuit_inputs::QueryProofCircuitInput,
        oprf::CredentialBlindingFactorOprfRequestAuthV1,
    };

    use crate::auth::{
        OprfRequestAuthError,
        credential_blinding_factor::{
            CredentialBlindingFactorOprfRequestAuthError,
            CredentialBlindingFactorOprfRequestAuthenticator,
        },
        merkle_watcher::MerkleWatcher,
        schema_issuer_registry_watcher::{
            SchemaIssuerRegistryWatcher, SchemaIssuerRegistryWatcherError,
        },
        tests::OprfRequestAuthTestSetup,
    };

    pub(crate) struct CredentialBlindingFactorOprfRequestAuthTestSetup {
        setup: OprfRequestAuthTestSetup,
        request_authenticator: CredentialBlindingFactorOprfRequestAuthenticator,
        request: OprfRequest<CredentialBlindingFactorOprfRequestAuthV1>,
    }

    impl CredentialBlindingFactorOprfRequestAuthTestSetup {
        pub(crate) async fn new() -> eyre::Result<Self> {
            let mut rng = rand::thread_rng();
            let setup = OprfRequestAuthTestSetup::new().await?;

            let max_cache_size = 100;
            let cache_maintenance_interval = Duration::from_secs(60);
            let started_services = StartedServices::default();
            let cancellation_token = tokio_util::sync::CancellationToken::new();

            let (merkle_watcher, _) = MerkleWatcher::init(
                setup.world_id_registry,
                setup.anvil.ws_endpoint(),
                max_cache_size,
                cache_maintenance_interval,
                started_services.new_service(),
                cancellation_token.clone(),
            )
            .await?;

            let (schema_issuer_registry_watcher, _) = SchemaIssuerRegistryWatcher::init(
                setup.credential_schema_issuer_registry,
                setup.anvil.ws_endpoint(),
                max_cache_size,
                cache_maintenance_interval,
                started_services.new_service(),
                cancellation_token.clone(),
            )
            .await?;

            let request_authenticator = CredentialBlindingFactorOprfRequestAuthenticator::init(
                merkle_watcher.clone(),
                schema_issuer_registry_watcher,
            );

            let query_material = world_id_core::proof::load_embedded_query_material().unwrap();

            let query_blinding_factor = BlindingFactor::rand(&mut rng);
            let action = FieldElement::ZERO;

            let query_hash = world_id_primitives::authenticator::oprf_query_digest(
                setup.merkle_inclusion_proof.leaf_index,
                action,
                setup.issuer_schema_id.into(),
            );
            let signature = setup
                .signer
                .offchain_signer_private_key()
                .expose_secret()
                .sign(*query_hash);

            let siblings: [ark_babyjubjub::Fq; TREE_DEPTH] =
                setup.merkle_inclusion_proof.siblings.map(|s| *s);

            let query_proof_input = QueryProofCircuitInput::<TREE_DEPTH> {
                pk: setup.key_set.as_affine_array(),
                pk_index: setup.key_index.into(),
                s: signature.s,
                r: signature.r,
                merkle_root: *setup.merkle_inclusion_proof.root,
                depth: ark_babyjubjub::Fq::from(TREE_DEPTH as u64),
                mt_index: setup.merkle_inclusion_proof.leaf_index.into(),
                siblings,
                beta: query_blinding_factor.beta(),
                rp_id: *FieldElement::from(setup.issuer_schema_id),
                action: *action,
                nonce: setup.rp_fixture.nonce,
            };
            let _ = errors::check_query_input_validity(&query_proof_input)?;

            let (proof, public_inputs) =
                query_material.generate_proof(&query_proof_input, &mut rng)?;
            query_material.verify_proof(&proof, &public_inputs)?;

            let credential_blinding_factor_auth = CredentialBlindingFactorOprfRequestAuthV1 {
                proof: proof.clone().into(),
                action: *action,
                nonce: setup.rp_fixture.nonce,
                merkle_root: *setup.merkle_inclusion_proof.root,
                issuer_schema_id: setup.issuer_schema_id,
            };

            let request_id = Uuid::new_v4();

            let blinded_request = taceo_oprf::core::oprf::client::blind_query(
                *query_hash,
                query_blinding_factor.clone(),
            );

            let request = OprfRequest {
                request_id,
                blinded_query: blinded_request.blinded_query(),
                auth: credential_blinding_factor_auth,
            };

            Ok(Self {
                setup,
                request_authenticator,
                request,
            })
        }
    }

    #[tokio::test]
    async fn test_credential_blinding_factor_oprf_req_auth_success() -> eyre::Result<()> {
        let setup = CredentialBlindingFactorOprfRequestAuthTestSetup::new().await?;
        setup
            .request_authenticator
            .authenticate(&setup.request)
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_credential_blinding_factor_oprf_req_auth_invalid_merkle_root() -> eyre::Result<()>
    {
        let mut setup = CredentialBlindingFactorOprfRequestAuthTestSetup::new().await?;
        setup.request.auth.merkle_root = rand::random();
        let err = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CredentialBlindingFactorOprfRequestAuthError::Common(
                OprfRequestAuthError::InvalidMerkleRoot
            )
        ));
        Ok(())
    }

    #[tokio::test]
    async fn test_credential_blinding_factor_oprf_req_auth_invalid_schema_issuer_id()
    -> eyre::Result<()> {
        let mut setup = CredentialBlindingFactorOprfRequestAuthTestSetup::new().await?;
        let unknown_issuer_schema_id = rand::random();
        setup.request.auth.issuer_schema_id = unknown_issuer_schema_id;
        let err = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CredentialBlindingFactorOprfRequestAuthError::SchemaIssuerRegistryWatcherError(
                SchemaIssuerRegistryWatcherError::UnknownSchemaIssuer(id)
            ) if id == unknown_issuer_schema_id
        ));
        Ok(())
    }

    #[tokio::test]
    async fn test_credential_blinding_factor_oprf_req_auth_invalid_action() -> eyre::Result<()> {
        let mut setup = CredentialBlindingFactorOprfRequestAuthTestSetup::new().await?;
        setup.request.auth.action = rand::random();
        let err = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CredentialBlindingFactorOprfRequestAuthError::InvalidAction
        ));
        Ok(())
    }

    #[tokio::test]
    async fn test_credential_blinding_factor_oprf_req_auth_invalid_proof() -> eyre::Result<()> {
        let mut setup = CredentialBlindingFactorOprfRequestAuthTestSetup::new().await?;
        setup.request.auth.proof.pi_a = rand::random();
        let err = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CredentialBlindingFactorOprfRequestAuthError::Common(
                OprfRequestAuthError::InvalidProof
            )
        ));
        Ok(())
    }

    #[tokio::test]
    async fn test_credential_blinding_factor_oprf_req_auth_removed_issuer() -> eyre::Result<()> {
        let setup = CredentialBlindingFactorOprfRequestAuthTestSetup::new().await?;
        let deployer = setup.setup.anvil.signer(0)?;
        setup
            .setup
            .anvil
            .remove_issuer(
                setup.setup.credential_schema_issuer_registry,
                deployer.clone(),
                deployer,
                setup.setup.issuer_schema_id,
            )
            .await?;
        let err = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CredentialBlindingFactorOprfRequestAuthError::SchemaIssuerRegistryWatcherError(
                SchemaIssuerRegistryWatcherError::UnknownSchemaIssuer(id)
            ) if id == setup.setup.issuer_schema_id
        ));
        Ok(())
    }

    #[test]
    fn credential_auth_error_display_is_valid_json_within_budget() {
        use world_id_primitives::oprf::{MAX_CLOSE_REASON_BYTES, OprfRequestErrorResponse};

        let errors: Vec<CredentialBlindingFactorOprfRequestAuthError> = vec![
            CredentialBlindingFactorOprfRequestAuthError::InvalidAction,
            CredentialBlindingFactorOprfRequestAuthError::SchemaIssuerRegistryWatcherError(
                SchemaIssuerRegistryWatcherError::UnknownSchemaIssuer(u64::MAX),
            ),
            CredentialBlindingFactorOprfRequestAuthError::SchemaIssuerRegistryWatcherError(
                SchemaIssuerRegistryWatcherError::AlloyError(
                    alloy::contract::Error::UnknownFunction("test".to_string()),
                ),
            ),
            CredentialBlindingFactorOprfRequestAuthError::Common(
                OprfRequestAuthError::InvalidProof,
            ),
            CredentialBlindingFactorOprfRequestAuthError::Common(
                OprfRequestAuthError::InvalidMerkleRoot,
            ),
            CredentialBlindingFactorOprfRequestAuthError::InternalServerError(eyre::eyre!(
                "something broke"
            )),
        ];

        for err in errors {
            let display = format!("{err}");
            let parsed: OprfRequestErrorResponse =
                serde_json::from_str(&display).unwrap_or_else(|e| {
                    panic!("Display for {err:?} is not valid JSON: {display} ({e})")
                });
            assert!(
                display.len() <= MAX_CLOSE_REASON_BYTES,
                "{parsed:?} Display is {} bytes, exceeds {MAX_CLOSE_REASON_BYTES}: {display}",
                display.len()
            );
        }
    }
}
