use crate::auth::{
    self, merkle_watcher::MerkleWatcher, nonce_history::NonceHistory,
    rp_registry_watcher::RpRegistryWatcher,
};
use async_trait::async_trait;
use std::time::Duration;
use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator, OprfRequestAuthenticatorError},
};
use tracing::instrument;
use world_id_core::FieldElement;
use world_id_primitives::SessionFeType;
use world_id_primitives::{
    SessionFieldElement,
    oprf::{NullifierOprfRequestAuthV1, WorldIdRequestAuthError},
};

pub(crate) struct SessionOprfRequestAuthenticator(auth::OprfRequestAuthWithRpSignature);

impl SessionOprfRequestAuthenticator {
    pub(crate) fn init(
        merkle_watcher: MerkleWatcher,
        rp_registry_watcher: RpRegistryWatcher,
        nonce_history: NonceHistory,
        current_time_stamp_max_difference: Duration,
    ) -> Self {
        Self(crate::auth::OprfRequestAuthWithRpSignature::init(
            merkle_watcher,
            rp_registry_watcher,
            nonce_history,
            current_time_stamp_max_difference,
        ))
    }

    async fn authenticate_inner(
        &self,
        request: &OprfRequest<NullifierOprfRequestAuthV1>,
    ) -> Result<OprfKeyId, WorldIdRequestAuthError> {
        // check action prefix is set to 0x01 or 0x02
        let action = FieldElement::from(request.auth.action);
        if !action.is_valid_for_session(SessionFeType::OprfSeed)
            && !action.is_valid_for_session(SessionFeType::Action)
        {
            return Err(WorldIdRequestAuthError::InvalidActionSession);
        }

        // check the RP nonce signature
        let msg = world_id_primitives::rp::compute_rp_signature_msg(
            request.auth.nonce,
            request.auth.current_time_stamp,
            request.auth.expiration_timestamp,
            // Note that for this session route, the requested action is NEVER signed
            None,
        );

        self.0.verify(&msg, request).await
    }
}

#[async_trait]
impl OprfRequestAuthenticator for SessionOprfRequestAuthenticator {
    type RequestAuth = NullifierOprfRequestAuthV1;

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

    use alloy::signers::{SignerSync as _, local::PrivateKeySigner};
    use ark_ff::PrimeField as _;
    use taceo_oprf::types::api::{OprfRequest, OprfRequestAuthenticator as _};
    use uuid::Uuid;
    use world_id_core::{FieldElement, primitives};
    use world_id_primitives::{
        SessionFeType, SessionFieldElement as _, oprf::NullifierOprfRequestAuthV1, rp::RpId,
    };

    use crate::auth::{
        session::SessionOprfRequestAuthenticator,
        tests::{AuthModulesTestSetup, OprfRequestAuthTestSetup},
    };

    pub(crate) struct SessionOprfRequestAuthTestSetup {
        setup: OprfRequestAuthTestSetup,
        request_authenticator: SessionOprfRequestAuthenticator,
        request: OprfRequest<NullifierOprfRequestAuthV1>,
    }

    impl SessionOprfRequestAuthTestSetup {
        pub(crate) async fn new() -> eyre::Result<Self> {
            Self::with_session_type(SessionFeType::OprfSeed).await
        }

        pub(crate) async fn with_session_type(session_type: SessionFeType) -> eyre::Result<Self> {
            let mut rng = rand::thread_rng();
            let infra = AuthModulesTestSetup::new().await?;

            let request_authenticator = SessionOprfRequestAuthenticator::init(
                infra.merkle_watcher.clone(),
                infra.rp_registry_watcher.clone(),
                infra.nonce_history.clone(),
                infra.current_time_stamp_max_difference,
            );

            // Session action must have the correct prefix byte (0x01 or 0x02)
            let session_action = FieldElement::random_for_session(&mut rng, session_type);

            let bundle = infra
                .generate_query_proof(session_action, infra.setup.rp_fixture.world_rp_id.into())?;

            // Session RP signature does NOT include the action (None)
            let rp_signer =
                PrivateKeySigner::from_signing_key(infra.setup.rp_fixture.signing_key.clone());
            let msg = world_id_primitives::rp::compute_rp_signature_msg(
                infra.setup.rp_fixture.nonce,
                infra.setup.rp_fixture.current_timestamp,
                infra.setup.rp_fixture.expiration_timestamp,
                None,
            );
            let signature = rp_signer.sign_message_sync(&msg).expect("can sign");

            let session_auth = NullifierOprfRequestAuthV1 {
                proof: bundle.proof,
                action: *session_action,
                nonce: bundle.nonce,
                merkle_root: *infra.setup.merkle_inclusion_proof.root,
                current_time_stamp: infra.setup.rp_fixture.current_timestamp,
                expiration_timestamp: infra.setup.rp_fixture.expiration_timestamp,
                signature,
                rp_id: infra.setup.rp_fixture.world_rp_id,
            };

            let request = OprfRequest {
                request_id: Uuid::new_v4(),
                blinded_query: bundle.blinded_query,
                auth: session_auth,
            };

            Ok(Self {
                setup: infra.setup,
                request_authenticator,
                request,
            })
        }
    }

    #[tokio::test]
    async fn test_session_oprf_req_auth_success_oprf_seed() -> eyre::Result<()> {
        let setup = SessionOprfRequestAuthTestSetup::new().await?;
        setup
            .request_authenticator
            .authenticate(&setup.request)
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_session_oprf_req_auth_success_action() -> eyre::Result<()> {
        let setup =
            SessionOprfRequestAuthTestSetup::with_session_type(SessionFeType::Action).await?;
        setup
            .request_authenticator
            .authenticate(&setup.request)
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_session_oprf_req_auth_invalid_action_nullifier_prefix() -> eyre::Result<()> {
        let mut setup = SessionOprfRequestAuthTestSetup::new().await?;
        // rp_fixture.action is guaranteed to have 0x00 prefix, which is invalid for session
        setup.request.auth.action = setup.setup.rp_fixture.action;
        let auth_error = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .expect_err("Should fail");
        assert_eq!(
            auth_error.code(),
            primitives::oprf::error_codes::INVALID_ACTION_SESSION
        );
        assert_eq!(
            auth_error.message(),
            "invalid action - MSB must be 0x00 for internal nullifier or 0x01 for session_id_r_seed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_session_oprf_req_auth_invalid_action_random_prefix() -> eyre::Result<()> {
        let mut setup = SessionOprfRequestAuthTestSetup::new().await?;
        // Construct an action with MSB = 0x03, which is not a valid session prefix
        let mut bytes = rand::random::<[u8; 32]>();
        bytes[0] = 0x03;
        setup.request.auth.action = ark_babyjubjub::Fq::from_be_bytes_mod_order(&bytes);
        let auth_error = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .expect_err("Should fail");
        assert_eq!(
            auth_error.code(),
            primitives::oprf::error_codes::INVALID_ACTION_SESSION
        );
        assert_eq!(
            auth_error.message(),
            "invalid action - MSB must be 0x00 for internal nullifier or 0x01 for session_id_r_seed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_session_oprf_req_auth_expired_timestamp() -> eyre::Result<()> {
        let mut setup = SessionOprfRequestAuthTestSetup::new().await?;
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
    async fn test_session_oprf_req_auth_invalid_merkle_root() -> eyre::Result<()> {
        let mut setup = SessionOprfRequestAuthTestSetup::new().await?;
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
    async fn test_session_oprf_req_auth_invalid_rp_id() -> eyre::Result<()> {
        let mut setup = SessionOprfRequestAuthTestSetup::new().await?;
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
    async fn test_session_oprf_req_auth_invalid_signer() -> eyre::Result<()> {
        let mut setup = SessionOprfRequestAuthTestSetup::new().await?;
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
    async fn test_session_oprf_req_auth_invalid_proof() -> eyre::Result<()> {
        let mut setup = SessionOprfRequestAuthTestSetup::new().await?;
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
    async fn test_session_oprf_req_auth_replay() -> eyre::Result<()> {
        let setup = SessionOprfRequestAuthTestSetup::new().await?;
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
    async fn test_session_oprf_req_auth_inactive_rp() -> eyre::Result<()> {
        let setup = SessionOprfRequestAuthTestSetup::new().await?;
        let rp_fixture = setup.setup.rp_fixture.clone();
        let deployer = setup.setup.anvil.signer(0)?;
        let rp_signer = PrivateKeySigner::from_signing_key(rp_fixture.signing_key.clone());
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
}
