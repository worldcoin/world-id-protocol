use crate::auth::{
    RpSignatureError, RpSignatureValidation,
    merkle_watcher::{MerkleWatcher, MerkleWatcherError},
    nonce_history::NonceHistory,
    rp_registry_watcher::RpRegistryWatcher,
};
use ark_bn254::Bn254;
use ark_groth16::PreparedVerifyingKey;
use async_trait::async_trait;
use std::{sync::Arc, time::Duration};
use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator, OprfRequestAuthenticatorError},
};
use tracing::instrument;
use world_id_core::FieldElement;
use world_id_primitives::oprf::{NullifierOprfRequestAuthV1, WorldIdRequestAuthError};

#[derive(Debug, thiserror::Error)]
pub(crate) enum UniquenessModuleError {
    #[error("Invalid action - must have MSB as 0x00 but action was: {0}")]
    InvalidAction(FieldElement),
    #[error("Could not verify query proof")]
    InvalidQueryProof,
    #[error(transparent)]
    RpOprfRequestError(#[from] RpSignatureError),
    #[error(transparent)]
    MerkleWatcher(#[from] MerkleWatcherError),
}

impl UniquenessModuleError {
    fn into_world_oprf_error(self) -> WorldIdRequestAuthError {
        match self {
            UniquenessModuleError::InvalidAction(_) => {
                tracing::debug!("{self}");
                WorldIdRequestAuthError::InvalidActionNullifier
            }
            UniquenessModuleError::InvalidQueryProof => {
                tracing::debug!("{self}");
                WorldIdRequestAuthError::InvalidQueryProof
            }
            UniquenessModuleError::RpOprfRequestError(rp_oprf_request_error) => {
                rp_oprf_request_error.into_world_oprf_error()
            }
            UniquenessModuleError::MerkleWatcher(merkle_watcher_error) => {
                merkle_watcher_error.into_world_oprf_error()
            }
        }
    }
}

pub(crate) struct UniquenessModuleAuth {
    rp_signature_auth: RpSignatureValidation,
    merkle_watcher: MerkleWatcher,
    query_vk: Arc<PreparedVerifyingKey<Bn254>>,
}

impl UniquenessModuleAuth {
    pub(crate) fn init(
        merkle_watcher: MerkleWatcher,
        rp_registry_watcher: RpRegistryWatcher,
        nonce_history: NonceHistory,
        current_time_stamp_max_difference: Duration,
        query_vk: Arc<PreparedVerifyingKey<Bn254>>,
    ) -> Self {
        Self {
            rp_signature_auth: crate::auth::RpSignatureValidation::init(
                rp_registry_watcher,
                nonce_history,
                current_time_stamp_max_difference,
            ),
            merkle_watcher,
            query_vk,
        }
    }

    async fn authenticate_inner(
        &self,
        request: &OprfRequest<NullifierOprfRequestAuthV1>,
    ) -> Result<OprfKeyId, UniquenessModuleError> {
        tracing::trace!("Checking that MSB is set to 0x00");
        // check action prefix is set to 0x00
        let action = FieldElement::from(request.auth.action);
        if action.to_be_bytes()[0] != 0 {
            return Err(UniquenessModuleError::InvalidAction(action));
        }

        // Note that for this nullifier route, the requested action MUST always be signed
        let (rp_signature_check, merkle_check) = tokio::join!(
            self.rp_signature_auth
                .verify(Some(request.auth.action), request),
            self.merkle_watcher
                .ensure_root_valid(FieldElement::from(request.auth.merkle_root))
        );

        let oprf_key_id = rp_signature_check?;
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
            Err(UniquenessModuleError::InvalidQueryProof)
        }
    }
}

#[async_trait]
impl OprfRequestAuthenticator for UniquenessModuleAuth {
    type RequestAuth = NullifierOprfRequestAuthV1;

    #[instrument(level = "debug", skip_all)]
    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, OprfRequestAuthenticatorError> {
        Ok(self
            .authenticate_inner(request)
            .await
            .map_err(UniquenessModuleError::into_world_oprf_error)?)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::large_futures, reason = "Is ok in tests")]

    use std::sync::Arc;

    use alloy::signers::local::LocalSigner;
    use ark_bn254::Bn254;
    use ark_ff::PrimeField as _;
    use circom_types::groth16::VerificationKey;
    use taceo_oprf::types::api::{OprfRequest, OprfRequestAuthenticator as _};
    use uuid::Uuid;
    use world_id_core::primitives;
    use world_id_primitives::{oprf::NullifierOprfRequestAuthV1, rp::RpId};

    use crate::{
        QUERY_VERIFICATION_KEY,
        auth::{
            tests::{AuthModulesTestSetup, OprfRequestAuthTestSetup},
            uniqueness::UniquenessModuleAuth,
        },
    };

    pub(crate) struct NullifierOprfRequestAuthTestSetup {
        setup: OprfRequestAuthTestSetup,
        request_authenticator: UniquenessModuleAuth,
        request: OprfRequest<NullifierOprfRequestAuthV1>,
    }

    impl NullifierOprfRequestAuthTestSetup {
        pub(crate) async fn new() -> eyre::Result<Self> {
            let infra = AuthModulesTestSetup::new().await?;
            let vk: VerificationKey<Bn254> =
                serde_json::from_str(QUERY_VERIFICATION_KEY).expect("can deserialize embedded vk");

            let request_authenticator = UniquenessModuleAuth::init(
                infra.merkle_watcher.clone(),
                infra.rp_registry_watcher.clone(),
                infra.nonce_history.clone(),
                infra.current_time_stamp_max_difference,
                Arc::new(ark_groth16::prepare_verifying_key(&vk.into())),
            );

            let bundle = infra.generate_query_proof(
                infra.setup.rp_fixture.action.into(),
                infra.setup.rp_fixture.world_rp_id.into(),
            )?;

            let nullifier_auth = NullifierOprfRequestAuthV1 {
                proof: bundle.proof,
                action: infra.setup.rp_fixture.action,
                nonce: bundle.nonce,
                merkle_root: *infra.setup.merkle_inclusion_proof.root,
                current_time_stamp: infra.setup.rp_fixture.current_timestamp,
                expiration_timestamp: infra.setup.rp_fixture.expiration_timestamp,
                signature: infra.setup.rp_fixture.signature,
                rp_id: infra.setup.rp_fixture.world_rp_id,
            };

            let request = OprfRequest {
                request_id: Uuid::new_v4(),
                blinded_query: bundle.blinded_query,
                auth: nullifier_auth,
            };

            Ok(Self {
                setup: infra.setup,
                request_authenticator,
                request,
            })
        }
    }

    #[tokio::test]
    async fn test_nullifier_oprf_req_auth_success() -> eyre::Result<()> {
        let setup = NullifierOprfRequestAuthTestSetup::new().await?;
        setup
            .request_authenticator
            .authenticate(&setup.request)
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_nullifier_oprf_req_auth_expired_timestamp() -> eyre::Result<()> {
        let mut setup = NullifierOprfRequestAuthTestSetup::new().await?;
        setup.request.auth.current_time_stamp = u64::MAX;
        let auth_error = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .expect_err("Should fail");
        assert_eq!(
            auth_error.code(),
            primitives::oprf::error_codes::TIMESTAMP_TOO_OLD
        );
        assert_eq!(auth_error.message(), "timestamp in request too old");
        Ok(())
    }

    #[tokio::test]
    async fn test_nullifier_oprf_req_auth_invalid_merkle_root() -> eyre::Result<()> {
        let mut setup = NullifierOprfRequestAuthTestSetup::new().await?;
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
    async fn test_nullifier_oprf_req_auth_invalid_rp_id() -> eyre::Result<()> {
        let mut setup = NullifierOprfRequestAuthTestSetup::new().await?;
        let unknown_rp_id = RpId::new(rand::random());
        setup.request.auth.rp_id = unknown_rp_id;
        let auth_error = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .expect_err("Should fail");
        assert_eq!(auth_error.code(), primitives::oprf::error_codes::UNKNOWN_RP);
        assert_eq!(auth_error.message(), "unknown RP");
        Ok(())
    }

    #[tokio::test]
    async fn test_nullifier_oprf_req_auth_invalid_signer() -> eyre::Result<()> {
        let mut setup = NullifierOprfRequestAuthTestSetup::new().await?;
        setup.request.auth.nonce = rand::random();
        let auth_error = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .expect_err("Should fail");
        assert_eq!(
            auth_error.code(),
            primitives::oprf::error_codes::INVALID_RP_SIGNATURE
        );
        assert_eq!(auth_error.message(), "signature from RP cannot be verified");
        Ok(())
    }

    #[tokio::test]
    async fn test_nullifier_oprf_req_auth_invalid_proof() -> eyre::Result<()> {
        let mut setup = NullifierOprfRequestAuthTestSetup::new().await?;
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
    async fn test_nullifier_oprf_req_auth_replay() -> eyre::Result<()> {
        let setup = NullifierOprfRequestAuthTestSetup::new().await?;
        setup
            .request_authenticator
            .authenticate(&setup.request)
            .await?;
        let auth_error = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .expect_err("Should fail");
        assert_eq!(
            auth_error.code(),
            primitives::oprf::error_codes::DUPLICATE_NONCE
        );
        assert_eq!(auth_error.message(), "signature nonce already used");
        Ok(())
    }

    #[tokio::test]
    async fn test_nullifier_oprf_req_auth_inactive_rp() -> eyre::Result<()> {
        let setup = NullifierOprfRequestAuthTestSetup::new().await?;
        let rp_fixture = setup.setup.rp_fixture.clone();
        let deployer = setup.setup.anvil.signer(0)?;
        let rp_signer = LocalSigner::from_signing_key(rp_fixture.signing_key.clone());
        setup
            .setup
            .anvil
            .update_rp(
                setup.setup.rp_registry,
                deployer,
                rp_signer.clone(),
                rp_fixture.world_rp_id,
                true,
                rp_signer.address(),
                rp_signer.address(),
                "taceo.oprf".to_string(),
            )
            .await?;
        let auth_error = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .expect_err("Should fail");
        assert_eq!(
            auth_error.code(),
            primitives::oprf::error_codes::INACTIVE_RP
        );
        assert_eq!(auth_error.message(), "inactive RP");
        Ok(())
    }

    #[tokio::test]
    async fn test_nullifier_oprf_req_auth_invalid_action() -> eyre::Result<()> {
        let mut setup = NullifierOprfRequestAuthTestSetup::new().await?;
        // Construct an action with MSB = 0x01 (session prefix), which is invalid for nullifier
        let mut bytes = rand::random::<[u8; 32]>();
        bytes[0] = 0x01;
        setup.request.auth.action = ark_babyjubjub::Fq::from_be_bytes_mod_order(&bytes);
        let auth_error = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .expect_err("Should fail");
        assert_eq!(
            auth_error.code(),
            primitives::oprf::error_codes::INVALID_ACTION_NULLIFIER
        );
        assert_eq!(
            auth_error.message(),
            "invalid action - MSB must be 0x00 for nullifier"
        );
        Ok(())
    }
}
