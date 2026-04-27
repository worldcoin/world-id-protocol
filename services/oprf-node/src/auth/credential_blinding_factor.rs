//! Authentication for the credential blinding factor OPRF module.
//!
//! Validates that the action is zero, the issuer schema is registered, the
//! Merkle root is valid, and the ZK query proof verifies.

use std::sync::Arc;

use crate::auth::{
    merkle_watcher::{MerkleWatcher, MerkleWatcherError},
    schema_issuer_registry_watcher::{
        SchemaIssuerRegistryWatcher, SchemaIssuerRegistryWatcherError,
    },
};
use alloy::primitives::U160;
use ark_bn254::Bn254;
use ark_ff::AdditiveGroup;
use ark_groth16::PreparedVerifyingKey;
use async_trait::async_trait;
use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator, OprfRequestAuthenticatorError},
};
use tracing::instrument;
use world_id_primitives::{
    FieldElement,
    oprf::{CredentialBlindingFactorOprfRequestAuthV1, WorldIdRequestAuthError},
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum CredentialBlindingFactorModuleError {
    #[error("Invalid action - must be 0, was: {0}")]
    InvalidAction(FieldElement),
    #[error("Could not verify query proof")]
    InvalidQueryProof,
    #[error("invalid Merkle root")]
    InvalidMerkleRoot,
    /// Unknown schema issuer.
    #[error("unknown schema issuer: {0}")]
    UnknownSchemaIssuer(u64),
    /// Internal Error
    #[error(transparent)]
    Internal(#[from] eyre::Report),
}

impl From<Arc<SchemaIssuerRegistryWatcherError>> for CredentialBlindingFactorModuleError {
    fn from(value: Arc<SchemaIssuerRegistryWatcherError>) -> Self {
        match value.as_ref() {
            SchemaIssuerRegistryWatcherError::UnknownSchemaIssuerId(id) => {
                Self::UnknownSchemaIssuer(*id)
            }
            SchemaIssuerRegistryWatcherError::Internal(_) => {
                Self::Internal(eyre::Report::from(value))
            }
        }
    }
}

impl From<Arc<MerkleWatcherError>> for CredentialBlindingFactorModuleError {
    fn from(value: Arc<MerkleWatcherError>) -> Self {
        match value.as_ref() {
            MerkleWatcherError::InvalidMerkleRoot => Self::InvalidMerkleRoot,
            MerkleWatcherError::Internal(_) => Self::Internal(eyre::Report::from(value)),
        }
    }
}

impl From<CredentialBlindingFactorModuleError> for WorldIdRequestAuthError {
    fn from(value: CredentialBlindingFactorModuleError) -> Self {
        match value {
            CredentialBlindingFactorModuleError::InvalidAction(_) => {
                WorldIdRequestAuthError::InvalidActionSchemaIssuer
            }
            CredentialBlindingFactorModuleError::InvalidQueryProof => {
                WorldIdRequestAuthError::InvalidQueryProof
            }
            CredentialBlindingFactorModuleError::InvalidMerkleRoot => {
                WorldIdRequestAuthError::InvalidMerkleRoot
            }
            CredentialBlindingFactorModuleError::UnknownSchemaIssuer(_) => {
                WorldIdRequestAuthError::UnknownSchemaIssuerId
            }
            CredentialBlindingFactorModuleError::Internal(_) => WorldIdRequestAuthError::Internal,
        }
    }
}

impl CredentialBlindingFactorModuleError {
    fn log(&self) {
        if let CredentialBlindingFactorModuleError::Internal(report) = self {
            tracing::error!("{report:?}");
        } else {
            tracing::debug!("{self}");
        }
    }
}

pub(crate) struct CredentialBlindingFactorModuleAuth {
    schema_issuer_registry_watcher: SchemaIssuerRegistryWatcher,
    merkle_watcher: MerkleWatcher,
    query_vk: Arc<PreparedVerifyingKey<Bn254>>,
}

impl CredentialBlindingFactorModuleAuth {
    pub(crate) fn init(
        merkle_watcher: MerkleWatcher,
        schema_issuer_registry_watcher: SchemaIssuerRegistryWatcher,
        query_vk: Arc<PreparedVerifyingKey<Bn254>>,
    ) -> Self {
        Self {
            schema_issuer_registry_watcher,
            merkle_watcher,
            query_vk,
        }
    }

    async fn authenticate_inner(
        &self,
        request: &OprfRequest<CredentialBlindingFactorOprfRequestAuthV1>,
    ) -> Result<OprfKeyId, CredentialBlindingFactorModuleError> {
        tracing::trace!("checking that action is 0...");
        // check that the action is valid (must be 0 for now, might change in the future)
        if request.auth.action != ark_babyjubjub::Fq::ZERO {
            return Err(CredentialBlindingFactorModuleError::InvalidAction(
                FieldElement::from(request.auth.action),
            ));
        }

        let oprf_key_id = OprfKeyId::new(U160::from(request.auth.issuer_schema_id));

        // check that the issuer schema id is valid
        let (issuer_check, merkle_check) = tokio::join!(
            self.schema_issuer_registry_watcher
                .is_valid_issuer(request.auth.issuer_schema_id),
            self.merkle_watcher
                .ensure_root_valid(FieldElement::from(request.auth.merkle_root))
        );
        issuer_check?;
        merkle_check?;

        // common verification
        let valid = super::verify_query_proof(
            &self.query_vk,
            &request.auth.proof.clone().into(),
            request.blinded_query,
            request.auth.merkle_root,
            oprf_key_id,
            request.auth.action,
            request.auth.nonce,
        );
        if valid {
            tracing::trace!("authentication successful!");
            Ok(oprf_key_id)
        } else {
            Err(CredentialBlindingFactorModuleError::InvalidQueryProof)
        }
    }
}

#[async_trait]
impl OprfRequestAuthenticator for CredentialBlindingFactorModuleAuth {
    type RequestAuth = CredentialBlindingFactorOprfRequestAuthV1;

    #[instrument(level = "debug", skip_all)]
    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, OprfRequestAuthenticatorError> {
        Ok(self
            .authenticate_inner(request)
            .await
            .inspect_err(CredentialBlindingFactorModuleError::log)
            .map_err(WorldIdRequestAuthError::from)?)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::large_futures, reason = "Is ok in tests")]

    use std::sync::Arc;

    use ark_bn254::Bn254;
    use circom_types::groth16::VerificationKey;
    use taceo_oprf::types::api::{OprfRequest, OprfRequestAuthenticator as _};
    use uuid::Uuid;
    use world_id_primitives::{
        self as primitives, FieldElement, oprf::CredentialBlindingFactorOprfRequestAuthV1,
    };

    use crate::{
        QUERY_VERIFICATION_KEY,
        auth::{
            credential_blinding_factor::CredentialBlindingFactorModuleAuth,
            tests::{AuthModulesTestSetup, OprfRequestAuthTestSetup},
        },
    };

    pub(crate) struct CredentialBlindingFactorOprfRequestAuthTestSetup {
        setup: OprfRequestAuthTestSetup,
        request_authenticator: CredentialBlindingFactorModuleAuth,
        request: OprfRequest<CredentialBlindingFactorOprfRequestAuthV1>,
    }

    impl CredentialBlindingFactorOprfRequestAuthTestSetup {
        pub(crate) async fn new() -> eyre::Result<Self> {
            let infra = AuthModulesTestSetup::new().await?;
            let vk: VerificationKey<Bn254> =
                serde_json::from_str(QUERY_VERIFICATION_KEY).expect("can deserialize embedded vk");

            let request_authenticator = CredentialBlindingFactorModuleAuth::init(
                infra.merkle_watcher.clone(),
                infra.schema_issuer_registry_watcher.clone(),
                Arc::new(ark_groth16::prepare_verifying_key(&vk.into())),
            );

            let action = FieldElement::ZERO;

            let bundle = infra.generate_query_proof(action, infra.setup.issuer_schema_id.into())?;

            let credential_blinding_factor_auth = CredentialBlindingFactorOprfRequestAuthV1 {
                proof: bundle.proof,
                action: *action,
                nonce: bundle.nonce,
                merkle_root: *infra.setup.merkle_inclusion_proof.root,
                issuer_schema_id: infra.setup.issuer_schema_id,
            };

            let request = OprfRequest {
                request_id: Uuid::new_v4(),
                blinded_query: bundle.blinded_query,
                auth: credential_blinding_factor_auth,
            };

            Ok(Self {
                setup: infra.setup,
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
        let auth_error = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .expect_err("Should fail");
        assert_eq!(
            auth_error.code(),
            primitives::oprf::error_codes::INVALID_MERKLE_ROOT
        );
        assert_eq!(auth_error.message(), "invalid merkle root");
        Ok(())
    }

    #[tokio::test]
    async fn test_credential_blinding_factor_oprf_req_auth_invalid_schema_issuer_id()
    -> eyre::Result<()> {
        let mut setup = CredentialBlindingFactorOprfRequestAuthTestSetup::new().await?;
        let unknown_issuer_schema_id = rand::random();
        setup.request.auth.issuer_schema_id = unknown_issuer_schema_id;
        let auth_error = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .expect_err("Should fail");
        assert_eq!(
            auth_error.code(),
            primitives::oprf::error_codes::UNKNOWN_SCHEMA_ISSUER
        );
        assert_eq!(auth_error.message(), "unknown schema issuer id");
        Ok(())
    }

    #[tokio::test]
    async fn test_credential_blinding_factor_oprf_req_auth_invalid_action() -> eyre::Result<()> {
        let mut setup = CredentialBlindingFactorOprfRequestAuthTestSetup::new().await?;
        setup.request.auth.action = rand::random();
        let auth_error = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .expect_err("Should fail");
        assert_eq!(
            auth_error.code(),
            primitives::oprf::error_codes::INVALID_ACTION_SCHEMA_ISSUER
        );
        assert_eq!(
            auth_error.message(),
            "invalid action for credential sub blinding factor"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_credential_blinding_factor_oprf_req_auth_invalid_proof() -> eyre::Result<()> {
        let mut setup = CredentialBlindingFactorOprfRequestAuthTestSetup::new().await?;
        setup.request.auth.proof.pi_a = rand::random();
        let auth_error = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .expect_err("Should fail");
        assert_eq!(
            auth_error.code(),
            primitives::oprf::error_codes::INVALID_QUERY_PROOF
        );
        assert_eq!(auth_error.message(), "cannot verify query proof");
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
        let auth_error = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .expect_err("Should fail");
        assert_eq!(
            auth_error.code(),
            primitives::oprf::error_codes::UNKNOWN_SCHEMA_ISSUER
        );
        assert_eq!(auth_error.message(), "unknown schema issuer id");
        Ok(())
    }

    #[tokio::test]
    async fn test_credential_blinding_factor_oprf_req_auth_tampered_blinded_query()
    -> eyre::Result<()> {
        let mut setup = CredentialBlindingFactorOprfRequestAuthTestSetup::new().await?;
        setup.request.blinded_query = rand::random();
        let auth_error = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .expect_err("Should fail");
        assert_eq!(
            auth_error.code(),
            primitives::oprf::error_codes::INVALID_QUERY_PROOF
        );
        assert_eq!(auth_error.message(), "cannot verify query proof");
        Ok(())
    }

    #[tokio::test]
    async fn test_credential_blinding_factor_oprf_req_auth_tampered_nonce() -> eyre::Result<()> {
        let mut setup = CredentialBlindingFactorOprfRequestAuthTestSetup::new().await?;
        setup.request.auth.nonce = rand::random();
        let auth_error = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .expect_err("Should fail");
        assert_eq!(
            auth_error.code(),
            primitives::oprf::error_codes::INVALID_QUERY_PROOF
        );
        assert_eq!(auth_error.message(), "cannot verify query proof");
        Ok(())
    }
}
