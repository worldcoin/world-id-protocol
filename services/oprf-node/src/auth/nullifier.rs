use crate::auth::{
    merkle_watcher::MerkleWatcher,
    rp_registry_watcher::{
        RpRegistry::{RpIdDoesNotExist, RpIdInactive, RpRegistryErrors},
        RpRegistryWatcher, RpRegistryWatcherError,
    },
    signature_history::{DuplicateSignatureError, SignatureHistory},
};
use async_trait::async_trait;
use axum::{http::StatusCode, response::IntoResponse};
use std::time::{Duration, SystemTime};
use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator},
};
use tracing::instrument;
use uuid::Uuid;
use world_id_primitives::oprf::{NullifierOprfRequestAuthV1, OprfRequestErrorResponse};

/// Errors returned by the [`NullifierOprfRequestAuthenticator`].
#[derive(Debug)]
pub(crate) enum NullifierOprfRequestAuthError {
    /// An error returned from the RpRegistry watcher service.
    RpRegistryWatcherError(RpRegistryWatcherError),
    /// The current time stamp difference between client and service is larger than allowed.
    TimeStampDifference,
    /// A nonce signature was used more than once.
    DuplicateSignatureError(DuplicateSignatureError),
    /// The signature over the nonce and time stamp is invalid.
    InvalidSignature(alloy::primitives::SignatureError),
    /// RP signature signer is invalid.
    InvalidSigner,
    /// Common OPRF request auth error.
    Common(crate::auth::OprfRequestAuthError),
    /// Internal server error.
    InternalServerError(eyre::Report),
}

impl From<RpRegistryWatcherError> for NullifierOprfRequestAuthError {
    fn from(err: RpRegistryWatcherError) -> Self {
        Self::RpRegistryWatcherError(err)
    }
}

impl From<DuplicateSignatureError> for NullifierOprfRequestAuthError {
    fn from(err: DuplicateSignatureError) -> Self {
        Self::DuplicateSignatureError(err)
    }
}

impl From<alloy::primitives::SignatureError> for NullifierOprfRequestAuthError {
    fn from(err: alloy::primitives::SignatureError) -> Self {
        Self::InvalidSignature(err)
    }
}

impl From<crate::auth::OprfRequestAuthError> for NullifierOprfRequestAuthError {
    fn from(err: crate::auth::OprfRequestAuthError) -> Self {
        Self::Common(err)
    }
}

impl From<eyre::Report> for NullifierOprfRequestAuthError {
    fn from(err: eyre::Report) -> Self {
        Self::InternalServerError(err)
    }
}

impl NullifierOprfRequestAuthError {
    /// Lossy conversion to the compact wire-format error response.
    ///
    /// Internal details (e.g. alloy RPC errors, eyre chains) are
    /// intentionally dropped — only a client-safe error code survives.
    pub(crate) fn to_oprf_response(&self) -> OprfRequestErrorResponse {
        match self {
            Self::RpRegistryWatcherError(RpRegistryWatcherError::UnknownRp(id)) => {
                OprfRequestErrorResponse::UnknownRp {
                    rp_id: format!("{id}"),
                }
            }
            Self::RpRegistryWatcherError(RpRegistryWatcherError::AlloyError(e)) => {
                match e.as_decoded_interface_error::<RpRegistryErrors>() {
                    Some(RpRegistryErrors::RpIdDoesNotExist(RpIdDoesNotExist { .. })) => {
                        OprfRequestErrorResponse::UnknownRp {
                            rp_id: String::new(),
                        }
                    }
                    Some(RpRegistryErrors::RpIdInactive(RpIdInactive { .. })) => {
                        OprfRequestErrorResponse::RpInactive
                    }
                    _ => OprfRequestErrorResponse::ServiceUnavailable,
                }
            }
            Self::TimeStampDifference => OprfRequestErrorResponse::TimestampTooLarge,
            Self::InvalidSignature(err) => OprfRequestErrorResponse::InvalidSignature {
                detail: err.to_string(),
            },
            Self::InvalidSigner => OprfRequestErrorResponse::InvalidSigner,
            Self::DuplicateSignatureError(_) => OprfRequestErrorResponse::DuplicateSignature,
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
impl std::fmt::Display for NullifierOprfRequestAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_oprf_response().to_json())
    }
}

impl std::error::Error for NullifierOprfRequestAuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RpRegistryWatcherError(e) => Some(e),
            Self::DuplicateSignatureError(e) => Some(e),
            Self::InvalidSignature(e) => Some(e),
            Self::Common(e) => Some(e),
            Self::InternalServerError(e) => Some(e.as_ref()),
            _ => None,
        }
    }
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

    #[instrument(level = "debug", skip_all)]
    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, Self::RequestAuthError> {
        tracing::trace!("checking timestamp...");
        // check the time stamp against system time +/- difference
        let req_time_stamp = Duration::from_secs(request.auth.current_time_stamp);
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time is after unix epoch");
        if current_time.abs_diff(req_time_stamp) > self.current_time_stamp_max_difference {
            return Err(NullifierOprfRequestAuthError::TimeStampDifference);
        }

        tracing::trace!("fetching RP info...");
        // fetch the RP info
        let rp = self.rp_registry_watcher.get_rp(&request.auth.rp_id).await?;

        tracing::trace!("check RP signature...");
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

        tracing::trace!("add signature to store...");
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

        tracing::trace!("authentication successful!");
        Ok(rp.oprf_key_id)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use alloy::signers::local::LocalSigner;
    use secrecy::ExposeSecret as _;
    use taceo_oprf::{
        core::oprf::BlindingFactor,
        service::StartedServices,
        types::api::{OprfRequest, OprfRequestAuthenticator as _},
    };
    use uuid::Uuid;
    use world_id_core::{FieldElement, proof::errors};
    use world_id_primitives::{
        TREE_DEPTH, circuit_inputs::QueryProofCircuitInput, oprf::NullifierOprfRequestAuthV1,
        rp::RpId,
    };

    use crate::auth::{
        OprfRequestAuthError,
        merkle_watcher::MerkleWatcher,
        nullifier::{NullifierOprfRequestAuthError, NullifierOprfRequestAuthenticator},
        rp_registry_watcher::{
            RpRegistry::{RpIdDoesNotExist, RpIdInactive, RpRegistryErrors},
            RpRegistryWatcher, RpRegistryWatcherError,
        },
        signature_history::{DuplicateSignatureError, SignatureHistory},
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

            let query_material = world_id_core::proof::load_embedded_query_material().unwrap();

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
            let _ = errors::check_query_input_validity(&query_proof_input)?;

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
        let err = setup
            .request_authenticator
            .authenticate(&setup.request)
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
            .authenticate(&setup.request)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            NullifierOprfRequestAuthError::Common(OprfRequestAuthError::InvalidMerkleRoot)
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
            .authenticate(&setup.request)
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
            .authenticate(&setup.request)
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
            .authenticate(&setup.request)
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
        setup
            .request_authenticator
            .authenticate(&setup.request)
            .await?;
        let err = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            NullifierOprfRequestAuthError::DuplicateSignatureError(DuplicateSignatureError)
        ));
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
        let err = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            NullifierOprfRequestAuthError::RpRegistryWatcherError(
                RpRegistryWatcherError::AlloyError(err)
            ) if matches!(err.as_decoded_interface_error::<RpRegistryErrors>().unwrap(), RpRegistryErrors::RpIdInactive(RpIdInactive))
        ));
        Ok(())
    }

    #[test]
    fn nullifier_auth_error_display_is_valid_json_within_budget() {
        use world_id_primitives::{
            oprf::{MAX_CLOSE_REASON_BYTES, OprfRequestErrorResponse},
            rp::RpId,
        };

        let errors: Vec<NullifierOprfRequestAuthError> = vec![
            NullifierOprfRequestAuthError::TimeStampDifference,
            NullifierOprfRequestAuthError::InvalidSigner,
            NullifierOprfRequestAuthError::DuplicateSignatureError(DuplicateSignatureError),
            NullifierOprfRequestAuthError::RpRegistryWatcherError(
                RpRegistryWatcherError::UnknownRp(RpId::from(u64::MAX)),
            ),
            NullifierOprfRequestAuthError::RpRegistryWatcherError(
                RpRegistryWatcherError::AlloyError(alloy::contract::Error::UnknownFunction(
                    "test".to_string(),
                )),
            ),
            NullifierOprfRequestAuthError::Common(OprfRequestAuthError::InvalidProof),
            NullifierOprfRequestAuthError::Common(OprfRequestAuthError::InvalidMerkleRoot),
            NullifierOprfRequestAuthError::InternalServerError(eyre::eyre!("something broke")),
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
