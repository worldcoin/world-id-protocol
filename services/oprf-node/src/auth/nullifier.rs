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

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Duration};

    use alloy::primitives::U160;
    use secrecy::ExposeSecret as _;
    use taceo_oprf::{
        core::oprf::BlindingFactor,
        service::StartedServices,
        types::{
            OprfKeyId,
            api::{OprfRequest, OprfRequestAuthenticator as _},
        },
    };
    use uuid::Uuid;
    use world_id_core::FieldElement;
    use world_id_primitives::{
        TREE_DEPTH, circuit_inputs::QueryProofCircuitInput, oprf::NullifierOprfRequestAuthV1,
        rp::RpId,
    };

    use crate::auth::{
        OprfRequestAuthError,
        merkle_watcher::MerkleWatcher,
        nullifier::{NullifierOprfRequestAuthError, NullifierOprfRequestAuthenticator},
        rp_registry_watcher::{
            RpRegistry::{RpIdDoesNotExist, RpRegistryErrors},
            RpRegistryWatcher, RpRegistryWatcherError,
        },
        signature_history::{DuplicateSignatureError, SignatureHistory},
        tests::OprfRequestAuthTestSetup,
    };

    pub(crate) struct NullifierOprfRequestAuthTestSetup {
        #[expect(dead_code)]
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
            let mut started_services = StartedServices::default();
            let cancellation_token = tokio_util::sync::CancellationToken::new();
            let current_time_stamp_max_difference = Duration::from_secs(300);

            let merkle_watcher = MerkleWatcher::init(
                setup.world_id_registry,
                setup.anvil.ws_endpoint(),
                max_cache_size,
                cache_maintenance_interval,
                started_services.new_service(),
                cancellation_token.clone(),
            )
            .await?;

            let rp_registry_watcher = RpRegistryWatcher::init(
                setup.rp_registry,
                setup.anvil.ws_endpoint(),
                max_cache_size,
                cache_maintenance_interval,
                started_services.new_service(),
                cancellation_token.clone(),
            )
            .await?;

            let signature_history = SignatureHistory::init(
                current_time_stamp_max_difference * 2,
                cache_maintenance_interval,
            );

            let request_authenticator = NullifierOprfRequestAuthenticator::init(
                merkle_watcher.clone(),
                rp_registry_watcher.clone(),
                signature_history,
                current_time_stamp_max_difference,
            );

            let query_material =
                world_id_core::proof::load_embedded_query_material(Option::<PathBuf>::None)
                    .unwrap();

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

            let blinded_request = taceo_oprf::core::oprf::client::blind_query(
                *query_hash,
                query_blinding_factor.clone(),
            );

            let request = OprfRequest {
                request_id,
                blinded_query: blinded_request.blinded_query(),
                auth: nullifier_auth,
                oprf_key_id: OprfKeyId::new(U160::from(setup.rp_fixture.world_rp_id.into_inner())),
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
        setup.request_authenticator.verify(&setup.request).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_nullifier_oprf_req_auth_expired_timestamp() -> eyre::Result<()> {
        let mut setup = NullifierOprfRequestAuthTestSetup::new().await?;
        setup.request.auth.current_time_stamp = u64::MAX;
        let err = setup
            .request_authenticator
            .verify(&setup.request)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            NullifierOprfRequestAuthError::TimeStampDifference
        ));
        Ok(())
    }

    #[tokio::test]
    async fn test_nullifier_oprf_req_auth_invalid_merkle_root() -> eyre::Result<()> {
        let mut setup = NullifierOprfRequestAuthTestSetup::new().await?;
        setup.request.auth.merkle_root = rand::random();
        let err = setup
            .request_authenticator
            .verify(&setup.request)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            NullifierOprfRequestAuthError::Common(OprfRequestAuthError::InvalidMerkleRoot)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn test_nullifier_oprf_req_auth_invalid_oprf_key_id() -> eyre::Result<()> {
        let mut setup = NullifierOprfRequestAuthTestSetup::new().await?;
        setup.request.oprf_key_id = OprfKeyId::new(rand::random());
        let err = setup
            .request_authenticator
            .verify(&setup.request)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            NullifierOprfRequestAuthError::OprfKeyIdMismatch
        ));
        Ok(())
    }

    #[tokio::test]
    async fn test_nullifier_oprf_req_auth_invalid_rp_id() -> eyre::Result<()> {
        let mut setup = NullifierOprfRequestAuthTestSetup::new().await?;
        let unknown_rp_id = RpId::new(rand::random());
        setup.request.auth.rp_id = unknown_rp_id;
        let err = setup
            .request_authenticator
            .verify(&setup.request)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            NullifierOprfRequestAuthError::RpRegistryWatcherError(
                RpRegistryWatcherError::AlloyError(err)
            ) if matches!(err.as_decoded_interface_error::<RpRegistryErrors>().unwrap(), RpRegistryErrors::RpIdDoesNotExist(RpIdDoesNotExist))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn test_nullifier_oprf_req_auth_invalid_signer() -> eyre::Result<()> {
        let mut setup = NullifierOprfRequestAuthTestSetup::new().await?;
        setup.request.auth.nonce = rand::random();
        let err = setup
            .request_authenticator
            .verify(&setup.request)
            .await
            .unwrap_err();
        assert!(matches!(err, NullifierOprfRequestAuthError::InvalidSigner));
        Ok(())
    }

    #[tokio::test]
    async fn test_nullifier_oprf_req_auth_invalid_proof() -> eyre::Result<()> {
        let mut setup = NullifierOprfRequestAuthTestSetup::new().await?;
        setup.request.auth.proof.pi_a = rand::random();
        let err = setup
            .request_authenticator
            .verify(&setup.request)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            NullifierOprfRequestAuthError::Common(OprfRequestAuthError::InvalidProof)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn test_nullifier_oprf_req_auth_replay() -> eyre::Result<()> {
        let setup = NullifierOprfRequestAuthTestSetup::new().await?;
        setup.request_authenticator.verify(&setup.request).await?;
        let err = setup
            .request_authenticator
            .verify(&setup.request)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            NullifierOprfRequestAuthError::DuplicateSignatureError(DuplicateSignatureError)
        ));
        Ok(())
    }
}
