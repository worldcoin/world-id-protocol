use crate::auth::{
    OprfRequestAuthWithRpSignature, merkle_watcher::MerkleWatcher, nonce_history::NonceHistory,
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
use world_id_primitives::oprf::{NullifierOprfRequestAuthV1, WorldIdRequestAuthError};

pub(crate) struct NullifierOprfRequestAuthenticator(OprfRequestAuthWithRpSignature);

impl NullifierOprfRequestAuthenticator {
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
        // check action prefix is set to 0x00
        let action = FieldElement::from(request.auth.action);
        if action.to_be_bytes()[0] != 0 {
            return Err(WorldIdRequestAuthError::InvalidActionNullifier);
        }

        // check the RP nonce signature
        let msg = world_id_primitives::rp::compute_rp_signature_msg(
            request.auth.nonce,
            request.auth.current_time_stamp,
            request.auth.expiration_timestamp,
            // Note that for this nullifier route, the requested action MUST always be signed
            Some(request.auth.action),
        );

        self.0.verify(&msg, request).await
    }
}

#[async_trait]
impl OprfRequestAuthenticator for NullifierOprfRequestAuthenticator {
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
    use std::time::Duration;

    use alloy::signers::local::LocalSigner;
    use secrecy::ExposeSecret as _;
    use taceo_oprf::{
        core::oprf::BlindingFactor,
        service::StartedServices,
        types::api::{OprfRequest, OprfRequestAuthenticator as _},
    };
    use uuid::Uuid;
    use world_id_core::{FieldElement, primitives, proof::errors};
    use world_id_primitives::{
        TREE_DEPTH, circuit_inputs::QueryProofCircuitInput, oprf::NullifierOprfRequestAuthV1,
        rp::RpId,
    };

    use crate::auth::{
        merkle_watcher::MerkleWatcher, nonce_history::NonceHistory,
        nullifier::NullifierOprfRequestAuthenticator, rp_registry_watcher::RpRegistryWatcher,
        tests::OprfRequestAuthTestSetup,
    };

    pub(crate) struct NullifierOprfRequestAuthTestSetup {
        setup: OprfRequestAuthTestSetup,
        request_authenticator: NullifierOprfRequestAuthenticator,
        request: OprfRequest<NullifierOprfRequestAuthV1>,
    }

    impl NullifierOprfRequestAuthTestSetup {
        pub(crate) async fn new() -> eyre::Result<Self> {
            let mut rng = rand::thread_rng();
            let setup = OprfRequestAuthTestSetup::new().await?;

            let max_cache_size = 100;
            let cache_maintenance_interval = Duration::from_secs(60);
            let started_services = StartedServices::default();
            let cancellation_token = tokio_util::sync::CancellationToken::new();
            let current_time_stamp_max_difference = Duration::from_secs(300);

            let (merkle_watcher, _) = MerkleWatcher::init(
                setup.world_id_registry,
                setup.anvil.ws_endpoint(),
                max_cache_size,
                cache_maintenance_interval,
                started_services.new_service(),
                cancellation_token.clone(),
            )
            .await?;

            let (rp_registry_watcher, _) = RpRegistryWatcher::init(
                setup.rp_registry,
                setup.anvil.ws_endpoint(),
                max_cache_size,
                cache_maintenance_interval,
                started_services.new_service(),
                cancellation_token.clone(),
            )
            .await?;

            let nonce_history = NonceHistory::init(
                current_time_stamp_max_difference * 2,
                cache_maintenance_interval,
            );

            let request_authenticator = NullifierOprfRequestAuthenticator::init(
                merkle_watcher.clone(),
                rp_registry_watcher.clone(),
                nonce_history,
                current_time_stamp_max_difference,
            );

            let query_material = world_id_core::proof::load_embedded_query_material()
                .expect("Can load query material");

            let query_blinding_factor = BlindingFactor::rand(&mut rng);

            let query_hash = world_id_primitives::authenticator::oprf_query_digest(
                setup.merkle_inclusion_proof.leaf_index,
                setup.rp_fixture.action.into(),
                setup.rp_fixture.world_rp_id.into(),
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
                rp_id: *FieldElement::from(setup.rp_fixture.world_rp_id),
                action: setup.rp_fixture.action,
                nonce: setup.rp_fixture.nonce,
            };
            let _affine = errors::check_query_input_validity(&query_proof_input)?;

            let (proof, public_inputs) =
                query_material.generate_proof(&query_proof_input, &mut rng)?;
            query_material.verify_proof(&proof, &public_inputs)?;

            let nullifier_auth = NullifierOprfRequestAuthV1 {
                proof: proof.clone().into(),
                action: setup.rp_fixture.action,
                nonce: setup.rp_fixture.nonce,
                merkle_root: *setup.merkle_inclusion_proof.root,
                current_time_stamp: setup.rp_fixture.current_timestamp,
                expiration_timestamp: setup.rp_fixture.expiration_timestamp,
                signature: setup.rp_fixture.signature,
                rp_id: setup.rp_fixture.world_rp_id,
            };

            let request_id = Uuid::new_v4();

            let blinded_request =
                taceo_oprf::core::oprf::client::blind_query(*query_hash, query_blinding_factor);

            let request = OprfRequest {
                request_id,
                blinded_query: blinded_request.blinded_query(),
                auth: nullifier_auth,
            };

            Ok(Self {
                setup,
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
}
