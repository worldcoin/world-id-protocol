use crate::auth::{
    merkle_watcher::MerkleWatcher, schema_issuer_registry_watcher::SchemaIssuerRegistryWatcher,
};
use alloy::primitives::U160;
use ark_ff::AdditiveGroup;
use async_trait::async_trait;
use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator, OprfRequestAuthenticatorError},
};
use tracing::instrument;
use world_id_primitives::oprf::{
    CredentialBlindingFactorOprfRequestAuthV1, WorldIdRequestAuthError,
};

pub(crate) struct CredentialBlindingFactorOprfRequestAuthenticator {
    schema_issuer_registry_watcher: SchemaIssuerRegistryWatcher,
    query_auth: crate::auth::QueryProofAuthenticator,
}

impl CredentialBlindingFactorOprfRequestAuthenticator {
    pub(crate) fn init(
        merkle_watcher: MerkleWatcher,
        schema_issuer_registry_watcher: SchemaIssuerRegistryWatcher,
    ) -> Self {
        Self {
            schema_issuer_registry_watcher,
            query_auth: crate::auth::QueryProofAuthenticator::init(merkle_watcher),
        }
    }

    async fn authenticate_inner(
        &self,
        request: &OprfRequest<CredentialBlindingFactorOprfRequestAuthV1>,
    ) -> Result<OprfKeyId, WorldIdRequestAuthError> {
        tracing::trace!("checking that action is not 0...");
        // check that the action is valid (must be 0 for now, might change in the future)
        if request.auth.action != ark_babyjubjub::Fq::ZERO {
            return Err(WorldIdRequestAuthError::InvalidActionSchemaIssuer);
        }

        let oprf_key_id = OprfKeyId::new(U160::from(request.auth.issuer_schema_id));

        tracing::trace!("checking schema-issuer...");
        // check that the issuer schema id is valid
        self.schema_issuer_registry_watcher
            .is_valid_issuer(request.auth.issuer_schema_id)
            .await?;

        // common verification
        self.query_auth
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

#[async_trait]
impl OprfRequestAuthenticator for CredentialBlindingFactorOprfRequestAuthenticator {
    type RequestAuth = CredentialBlindingFactorOprfRequestAuthV1;

    #[instrument(level = "debug", skip_all)]
    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, OprfRequestAuthenticatorError> {
        Ok(self.authenticate_inner(request).await?)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::large_futures, reason = "Is ok in tests")]

    use taceo_oprf::types::api::{OprfRequest, OprfRequestAuthenticator as _};
    use uuid::Uuid;
    use world_id_core::{FieldElement, primitives};
    use world_id_primitives::oprf::CredentialBlindingFactorOprfRequestAuthV1;

    use crate::auth::{
        credential_blinding_factor::CredentialBlindingFactorOprfRequestAuthenticator,
        tests::{AuthModulesTestSetup, OprfRequestAuthTestSetup},
    };

    pub(crate) struct CredentialBlindingFactorOprfRequestAuthTestSetup {
        setup: OprfRequestAuthTestSetup,
        request_authenticator: CredentialBlindingFactorOprfRequestAuthenticator,
        request: OprfRequest<CredentialBlindingFactorOprfRequestAuthV1>,
    }

    impl CredentialBlindingFactorOprfRequestAuthTestSetup {
        pub(crate) async fn new() -> eyre::Result<Self> {
            let infra = AuthModulesTestSetup::new().await?;

            let request_authenticator = CredentialBlindingFactorOprfRequestAuthenticator::init(
                infra.merkle_watcher.clone(),
                infra.schema_issuer_registry_watcher.clone(),
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
        assert_eq!(auth_error.message(), "unknown schema issuer");
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
            "invalid action - must be 0 for schema-issuer blinding"
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
        assert_eq!(auth_error.message(), "unknown schema issuer");
        Ok(())
    }
}
