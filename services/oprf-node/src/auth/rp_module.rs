//! Unified RP-authenticated OPRF module.
//!
//! Both the session and uniqueness modules share identical struct fields, init
//! logic, and query-proof verification. They differ only in:
//! - how the action field is validated (`MSB == 0x00` for uniqueness vs `0x01/0x02` for sessions depending on the [`SessionFeType`])
//! - whether the action is included in the RP signature (`Some` for uniqueness, `None` for session)
//! - which [`WorldIdRequestAuthError`] variant is returned for an invalid action
//!
//! [`RpModuleKind`] captures these differences; [`RpModuleAuth`] holds the shared
//! state and branches on the kind at runtime.

use crate::auth::{
    merkle_watcher::{MerkleWatcher, MerkleWatcherError},
    nonce_history::{DuplicateNonce, NonceHistory},
    rp_registry_watcher::{RpRegistryWatcher, RpRegistryWatcherError},
};
use ark_bn254::Bn254;
use ark_groth16::PreparedVerifyingKey;
use async_trait::async_trait;
use std::{
    fmt,
    sync::Arc,
    time::{Duration, SystemTime},
};
use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator, OprfRequestAuthenticatorError},
};
use tracing::instrument;
use world_id_core::FieldElement;
use world_id_primitives::{
    SessionFeType, SessionFieldElement as _,
    oprf::{NullifierOprfRequestAuthV1, WorldIdRequestAuthError},
    rp::RpId,
};

/// Distinguishes the two RP-authenticated OPRF modules.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RpModuleKind {
    /// Session module: action MSB must be `0x01` (seed) or `0x02` (action); action is NOT signed.
    Session,
    /// Uniqueness module: action MSB must be `0x00`; action IS signed.
    Uniqueness,
}

impl fmt::Display for RpModuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RpModuleKind::Session => write!(f, "session (action MSB must be 0x01 or 0x02)"),
            RpModuleKind::Uniqueness => write!(f, "uniqueness (action MSB must be 0x00)"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RpModuleError {
    #[error("Invalid action for {kind}: {action}")]
    InvalidAction {
        kind: RpModuleKind,
        action: FieldElement,
    },
    #[error("Could not verify query proof")]
    InvalidQueryProof,
    #[error("invalid Merkle root")]
    InvalidMerkleRoot,
    #[error("Current Timestamp in request too old, current={current:?}, timestamp={timestamp:?}")]
    TimestampTooOld {
        current: Duration,
        timestamp: Duration,
    },
    #[error("unknown rp: {0}")]
    UnknownRp(RpId),
    #[error("inactive rp: {0}")]
    InactiveRp(RpId),
    #[error("Cannot build signature: {0}")]
    CorruptSignature(#[from] alloy::primitives::SignatureError),
    #[error("Invalid RP signature - recover signer failed")]
    InvalidSignature,
    #[error(transparent)]
    DuplicateNonce(#[from] DuplicateNonce),
    #[error(transparent)]
    Internal(#[from] eyre::Report),
}

impl From<MerkleWatcherError> for RpModuleError {
    fn from(value: MerkleWatcherError) -> Self {
        match value {
            MerkleWatcherError::InvalidMerkleRoot => Self::InvalidMerkleRoot,
            MerkleWatcherError::Internal(report) => Self::Internal(report),
        }
    }
}

impl From<RpRegistryWatcherError> for RpModuleError {
    fn from(value: RpRegistryWatcherError) -> Self {
        match value {
            RpRegistryWatcherError::UnknownRp(rp_id) => Self::UnknownRp(rp_id),
            RpRegistryWatcherError::InactiveRp(rp_id) => Self::InactiveRp(rp_id),
            RpRegistryWatcherError::Internal(report) => Self::Internal(report),
        }
    }
}

impl From<RpModuleError> for WorldIdRequestAuthError {
    fn from(value: RpModuleError) -> Self {
        match value {
            RpModuleError::InvalidAction { kind, .. } => match kind {
                RpModuleKind::Session => WorldIdRequestAuthError::InvalidActionSession,
                RpModuleKind::Uniqueness => WorldIdRequestAuthError::InvalidActionNullifier,
            },
            RpModuleError::InvalidQueryProof => WorldIdRequestAuthError::InvalidQueryProof,
            RpModuleError::InvalidMerkleRoot => WorldIdRequestAuthError::InvalidMerkleRoot,
            RpModuleError::TimestampTooOld {
                current: _,
                timestamp: _,
            } => WorldIdRequestAuthError::TimeStampTooOld,
            RpModuleError::UnknownRp(_) => WorldIdRequestAuthError::UnknownRp,
            RpModuleError::InactiveRp(_) => WorldIdRequestAuthError::InactiveRp,
            // we map to the same signature to not leak that a forged signature was build correctly
            RpModuleError::CorruptSignature(_) | RpModuleError::InvalidSignature => {
                WorldIdRequestAuthError::InvalidRpSignature
            }
            RpModuleError::DuplicateNonce(_) => WorldIdRequestAuthError::DuplicateNonce,
            RpModuleError::Internal(_) => WorldIdRequestAuthError::Internal,
        }
    }
}

impl RpModuleError {
    fn log(&self) {
        if let RpModuleError::Internal(report) = self {
            tracing::error!("{report:?}");
        } else {
            tracing::debug!("{self}");
        }
    }
}

pub(crate) struct RpModuleAuth {
    kind: RpModuleKind,
    rp_registry_watcher: RpRegistryWatcher,
    nonce_history: NonceHistory,
    current_time_stamp_max_difference: Duration,
    merkle_watcher: MerkleWatcher,
    query_vk: Arc<PreparedVerifyingKey<Bn254>>,
}

impl RpModuleAuth {
    fn new(
        kind: RpModuleKind,
        merkle_watcher: MerkleWatcher,
        rp_registry_watcher: RpRegistryWatcher,
        nonce_history: NonceHistory,
        current_time_stamp_max_difference: Duration,
        query_vk: Arc<PreparedVerifyingKey<Bn254>>,
    ) -> Self {
        Self {
            kind,
            rp_registry_watcher,
            nonce_history,
            current_time_stamp_max_difference,
            merkle_watcher,
            query_vk,
        }
    }

    /// Initializes a session-module authenticator.
    pub(crate) fn new_session(
        merkle_watcher: MerkleWatcher,
        rp_registry_watcher: RpRegistryWatcher,
        nonce_history: NonceHistory,
        current_time_stamp_max_difference: Duration,
        query_vk: Arc<PreparedVerifyingKey<Bn254>>,
    ) -> Self {
        Self::new(
            RpModuleKind::Session,
            merkle_watcher,
            rp_registry_watcher,
            nonce_history,
            current_time_stamp_max_difference,
            query_vk,
        )
    }

    /// Initializes a uniqueness-module authenticator.
    pub(crate) fn new_uniqueness(
        merkle_watcher: MerkleWatcher,
        rp_registry_watcher: RpRegistryWatcher,
        nonce_history: NonceHistory,
        current_time_stamp_max_difference: Duration,
        query_vk: Arc<PreparedVerifyingKey<Bn254>>,
    ) -> Self {
        Self::new(
            RpModuleKind::Uniqueness,
            merkle_watcher,
            rp_registry_watcher,
            nonce_history,
            current_time_stamp_max_difference,
            query_vk,
        )
    }

    async fn verify_rp_signature(
        &self,
        action: Option<ark_babyjubjub::Fq>,
        request: &OprfRequest<NullifierOprfRequestAuthV1>,
    ) -> Result<OprfKeyId, RpModuleError> {
        tracing::trace!("checking timestamp on signature...");
        // check the time stamp against system time +/- difference
        let req_time_stamp = Duration::from_secs(request.auth.current_time_stamp);
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time is after unix epoch");
        if current_time.abs_diff(req_time_stamp) > self.current_time_stamp_max_difference {
            return Err(RpModuleError::TimestampTooOld {
                current: current_time,
                timestamp: req_time_stamp,
            });
        }

        tracing::trace!("fetching RP info...");
        // fetch the RP info
        let rp = self.rp_registry_watcher.get_rp(&request.auth.rp_id).await?;

        // check the RP nonce signature
        let msg = world_id_primitives::rp::compute_rp_signature_msg(
            request.auth.nonce,
            request.auth.current_time_stamp,
            request.auth.expiration_timestamp,
            action,
        );

        tracing::trace!("check RP signature...");
        let recovered = request.auth.signature.recover_address_from_msg(msg)?;
        if recovered != rp.signer {
            return Err(RpModuleError::InvalidSignature);
        }

        tracing::trace!("add nonce to store...");
        // add nonce to history to check if the nonces where only used once
        self.nonce_history
            .add_nonce(FieldElement::from(request.auth.nonce))
            .await?;

        tracing::trace!("RP signature authentication successful!");
        Ok(rp.oprf_key_id)
    }
    async fn authenticate_inner(
        &self,
        request: &OprfRequest<NullifierOprfRequestAuthV1>,
    ) -> Result<OprfKeyId, RpModuleError> {
        tracing::trace!("Validating action for {}", self.kind);
        let action = FieldElement::from(request.auth.action);

        match self.kind {
            RpModuleKind::Session => {
                if !action.is_valid_for_session(SessionFeType::OprfSeed)
                    && !action.is_valid_for_session(SessionFeType::Action)
                {
                    return Err(RpModuleError::InvalidAction {
                        kind: self.kind,
                        action,
                    });
                }
            }
            RpModuleKind::Uniqueness => {
                if action.to_be_bytes()[0] != 0 {
                    return Err(RpModuleError::InvalidAction {
                        kind: self.kind,
                        action,
                    });
                }
            }
        }

        // Session does not include the action in the RP signature; uniqueness does.
        let signed_action = match self.kind {
            RpModuleKind::Session => None,
            RpModuleKind::Uniqueness => Some(request.auth.action),
        };

        let (rp_check, merkle_check) = tokio::join!(
            self.verify_rp_signature(signed_action, request),
            self.merkle_watcher
                .ensure_root_valid(FieldElement::from(request.auth.merkle_root))
        );

        let oprf_key_id = rp_check?;
        merkle_check?;

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
            Err(RpModuleError::InvalidQueryProof)
        }
    }
}

#[async_trait]
impl OprfRequestAuthenticator for RpModuleAuth {
    type RequestAuth = NullifierOprfRequestAuthV1;

    #[instrument(level = "debug", skip_all)]
    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, OprfRequestAuthenticatorError> {
        Ok(self
            .authenticate_inner(request)
            .await
            .inspect_err(RpModuleError::log)
            .map_err(WorldIdRequestAuthError::from)?)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::large_futures, reason = "Is ok in tests")]

    use std::sync::Arc;

    use alloy::signers::{SignerSync as _, local::LocalSigner};
    use ark_bn254::Bn254;
    use ark_ff::PrimeField as _;
    use circom_types::groth16::VerificationKey;
    use taceo_oprf::types::api::{OprfRequest, OprfRequestAuthenticator as _};
    use uuid::Uuid;
    use world_id_core::{FieldElement, primitives};
    use world_id_primitives::{
        SessionFeType, SessionFieldElement as _, oprf::NullifierOprfRequestAuthV1, rp::RpId,
    };

    use crate::{
        QUERY_VERIFICATION_KEY,
        auth::{
            rp_module::{RpModuleAuth, RpModuleKind},
            tests::{AuthModulesTestSetup, OprfRequestAuthTestSetup},
        },
    };

    pub(crate) struct RpModuleTestSetup {
        pub(crate) setup: OprfRequestAuthTestSetup,
        pub(crate) request_authenticator: RpModuleAuth,
        pub(crate) request: OprfRequest<NullifierOprfRequestAuthV1>,
    }

    impl RpModuleTestSetup {
        /// Constructs a valid test setup for the given kind.
        ///
        /// Session defaults to [`SessionFeType::OprfSeed`].
        /// Use [`Self::new_session`] to specify a different session type.
        pub(crate) async fn new(kind: RpModuleKind) -> eyre::Result<Self> {
            match kind {
                RpModuleKind::Session => Self::new_session(SessionFeType::OprfSeed).await,
                RpModuleKind::Uniqueness => Self::new_uniqueness().await,
            }
        }

        /// Constructs a valid session test setup with the given session type.
        pub(crate) async fn new_session(session_type: SessionFeType) -> eyre::Result<Self> {
            let mut rng = rand::thread_rng();
            let infra = AuthModulesTestSetup::new().await?;
            let vk: VerificationKey<Bn254> =
                serde_json::from_str(QUERY_VERIFICATION_KEY).expect("can deserialize embedded vk");

            let request_authenticator = RpModuleAuth::new_session(
                infra.merkle_watcher.clone(),
                infra.rp_registry_watcher.clone(),
                infra.nonce_history.clone(),
                infra.current_time_stamp_max_difference,
                Arc::new(ark_groth16::prepare_verifying_key(&vk.into())),
            );

            // Session action must have the correct prefix byte (0x01 or 0x02)
            let session_action = FieldElement::random_for_session(&mut rng, session_type);
            let bundle = infra
                .generate_query_proof(session_action, infra.setup.rp_fixture.world_rp_id.into())?;

            // Session RP signature does NOT include the action
            let rp_signer =
                LocalSigner::from_signing_key(infra.setup.rp_fixture.signing_key.clone());
            let msg = world_id_primitives::rp::compute_rp_signature_msg(
                infra.setup.rp_fixture.nonce,
                infra.setup.rp_fixture.current_timestamp,
                infra.setup.rp_fixture.expiration_timestamp,
                None,
            );
            let signature = rp_signer.sign_message_sync(&msg).expect("can sign");

            let auth = NullifierOprfRequestAuthV1 {
                proof: bundle.proof,
                action: *session_action,
                nonce: bundle.nonce,
                merkle_root: *infra.setup.merkle_inclusion_proof.root,
                current_time_stamp: infra.setup.rp_fixture.current_timestamp,
                expiration_timestamp: infra.setup.rp_fixture.expiration_timestamp,
                signature,
                rp_id: infra.setup.rp_fixture.world_rp_id,
            };

            Ok(Self {
                setup: infra.setup,
                request_authenticator,
                request: OprfRequest {
                    request_id: Uuid::new_v4(),
                    blinded_query: bundle.blinded_query,
                    auth,
                },
            })
        }

        async fn new_uniqueness() -> eyre::Result<Self> {
            let infra = AuthModulesTestSetup::new().await?;
            let vk: VerificationKey<Bn254> =
                serde_json::from_str(QUERY_VERIFICATION_KEY).expect("can deserialize embedded vk");

            let request_authenticator = RpModuleAuth::new_uniqueness(
                infra.merkle_watcher.clone(),
                infra.rp_registry_watcher.clone(),
                infra.nonce_history.clone(),
                infra.current_time_stamp_max_difference,
                Arc::new(ark_groth16::prepare_verifying_key(&vk.into())),
            );

            // Uniqueness uses the fixture's pre-generated action (guaranteed 0x00 MSB)
            // and a signature that includes the action
            let bundle = infra.generate_query_proof(
                infra.setup.rp_fixture.action.into(),
                infra.setup.rp_fixture.world_rp_id.into(),
            )?;

            let auth = NullifierOprfRequestAuthV1 {
                proof: bundle.proof,
                action: infra.setup.rp_fixture.action,
                nonce: bundle.nonce,
                merkle_root: *infra.setup.merkle_inclusion_proof.root,
                current_time_stamp: infra.setup.rp_fixture.current_timestamp,
                expiration_timestamp: infra.setup.rp_fixture.expiration_timestamp,
                signature: infra.setup.rp_fixture.signature,
                rp_id: infra.setup.rp_fixture.world_rp_id,
            };

            Ok(Self {
                setup: infra.setup,
                request_authenticator,
                request: OprfRequest {
                    request_id: Uuid::new_v4(),
                    blinded_query: bundle.blinded_query,
                    auth,
                },
            })
        }
    }

    // ── Shared test helpers ──────────────────────────────────────────────────

    async fn check_success(kind: RpModuleKind) -> eyre::Result<()> {
        let setup = RpModuleTestSetup::new(kind).await?;
        setup
            .request_authenticator
            .authenticate(&setup.request)
            .await?;
        Ok(())
    }

    async fn check_expired_timestamp(kind: RpModuleKind) -> eyre::Result<()> {
        let mut setup = RpModuleTestSetup::new(kind).await?;
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

    async fn check_invalid_query_proof(kind: RpModuleKind) -> eyre::Result<()> {
        let mut setup = RpModuleTestSetup::new(kind).await?;
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

    async fn check_invalid_merkle_root(kind: RpModuleKind) -> eyre::Result<()> {
        let mut setup = RpModuleTestSetup::new(kind).await?;
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

    async fn check_invalid_rp_id(kind: RpModuleKind) -> eyre::Result<()> {
        let mut setup = RpModuleTestSetup::new(kind).await?;
        setup.request.auth.rp_id = RpId::new(rand::random());
        let auth_error = setup
            .request_authenticator
            .authenticate(&setup.request)
            .await
            .expect_err("Should fail");
        assert_eq!(auth_error.code(), primitives::oprf::error_codes::UNKNOWN_RP);
        assert_eq!(auth_error.message(), "unknown RP");
        Ok(())
    }

    async fn check_invalid_signer(kind: RpModuleKind) -> eyre::Result<()> {
        let mut setup = RpModuleTestSetup::new(kind).await?;
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

    async fn check_invalid_proof(kind: RpModuleKind) -> eyre::Result<()> {
        let mut setup = RpModuleTestSetup::new(kind).await?;
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

    async fn check_replay(kind: RpModuleKind) -> eyre::Result<()> {
        let setup = RpModuleTestSetup::new(kind).await?;
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

    async fn check_inactive_rp(kind: RpModuleKind) -> eyre::Result<()> {
        let setup = RpModuleTestSetup::new(kind).await?;
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

    async fn check_tampered_blinded_query(kind: RpModuleKind) -> eyre::Result<()> {
        let mut setup = RpModuleTestSetup::new(kind).await?;
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

    async fn check_tampered_expiration_timestamp(kind: RpModuleKind) -> eyre::Result<()> {
        let mut setup = RpModuleTestSetup::new(kind).await?;
        setup.request.auth.expiration_timestamp = rand::random();
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

    async fn check_timestamp_zero(kind: RpModuleKind) -> eyre::Result<()> {
        let mut setup = RpModuleTestSetup::new(kind).await?;
        setup.request.auth.current_time_stamp = 0;
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

    // ── Session-specific tests ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_session_success_oprf_seed() -> eyre::Result<()> {
        check_success(RpModuleKind::Session).await
    }

    #[tokio::test]
    async fn test_session_success_action() -> eyre::Result<()> {
        let setup = RpModuleTestSetup::new_session(SessionFeType::Action).await?;
        setup
            .request_authenticator
            .authenticate(&setup.request)
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_session_invalid_action_nullifier_prefix() -> eyre::Result<()> {
        let mut setup = RpModuleTestSetup::new(RpModuleKind::Session).await?;
        // rp_fixture.action has 0x00 prefix, which is valid for uniqueness but NOT for session
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
            "invalid action - MSB must be 0x02 for internal nullifier or 0x01 for session_id_r_seed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_session_invalid_action_random_prefix() -> eyre::Result<()> {
        let mut setup = RpModuleTestSetup::new(RpModuleKind::Session).await?;
        // MSB = 0x03 is not a valid session prefix
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
            "invalid action - MSB must be 0x02 for internal nullifier or 0x01 for session_id_r_seed"
        );
        Ok(())
    }

    // ── Uniqueness-specific tests ────────────────────────────────────────────

    #[tokio::test]
    async fn test_uniqueness_success() -> eyre::Result<()> {
        check_success(RpModuleKind::Uniqueness).await
    }

    #[tokio::test]
    async fn test_uniqueness_invalid_action() -> eyre::Result<()> {
        let mut setup = RpModuleTestSetup::new(RpModuleKind::Uniqueness).await?;
        // MSB = 0x01 is a session prefix, which is invalid for uniqueness
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

    #[tokio::test]
    async fn test_uniqueness_invalid_action_session_prefix() -> eyre::Result<()> {
        let mut setup = RpModuleTestSetup::new(RpModuleKind::Uniqueness).await?;
        // MSB = 0x02 is the session Action prefix, invalid for uniqueness
        let mut bytes = rand::random::<[u8; 32]>();
        bytes[0] = 0x02;
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

    // ── Shared tests: session ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_session_expired_timestamp() -> eyre::Result<()> {
        check_expired_timestamp(RpModuleKind::Session).await
    }

    #[tokio::test]
    async fn test_session_invalid_merkle_root() -> eyre::Result<()> {
        check_invalid_merkle_root(RpModuleKind::Session).await
    }

    #[tokio::test]
    async fn test_session_invalid_rp_id() -> eyre::Result<()> {
        check_invalid_rp_id(RpModuleKind::Session).await
    }

    #[tokio::test]
    async fn test_session_invalid_signer() -> eyre::Result<()> {
        check_invalid_signer(RpModuleKind::Session).await
    }

    #[tokio::test]
    async fn test_session_invalid_proof() -> eyre::Result<()> {
        check_invalid_proof(RpModuleKind::Session).await
    }

    #[tokio::test]
    async fn test_session_replay() -> eyre::Result<()> {
        check_replay(RpModuleKind::Session).await
    }

    #[tokio::test]
    async fn test_session_inactive_rp() -> eyre::Result<()> {
        check_inactive_rp(RpModuleKind::Session).await
    }

    #[tokio::test]
    async fn test_session_tampered_blinded_query() -> eyre::Result<()> {
        check_tampered_blinded_query(RpModuleKind::Session).await
    }

    #[tokio::test]
    async fn test_session_tampered_expiration_timestamp() -> eyre::Result<()> {
        check_tampered_expiration_timestamp(RpModuleKind::Session).await
    }

    #[tokio::test]
    async fn test_session_timestamp_zero() -> eyre::Result<()> {
        check_timestamp_zero(RpModuleKind::Session).await
    }

    #[tokio::test]
    async fn test_session_invalid_query_proof() -> eyre::Result<()> {
        check_invalid_query_proof(RpModuleKind::Session).await
    }

    // ── Shared tests: uniqueness ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_uniqueness_expired_timestamp() -> eyre::Result<()> {
        check_expired_timestamp(RpModuleKind::Uniqueness).await
    }

    #[tokio::test]
    async fn test_uniqueness_invalid_merkle_root() -> eyre::Result<()> {
        check_invalid_merkle_root(RpModuleKind::Uniqueness).await
    }

    #[tokio::test]
    async fn test_uniqueness_invalid_rp_id() -> eyre::Result<()> {
        check_invalid_rp_id(RpModuleKind::Uniqueness).await
    }

    #[tokio::test]
    async fn test_uniqueness_invalid_signer() -> eyre::Result<()> {
        check_invalid_signer(RpModuleKind::Uniqueness).await
    }

    #[tokio::test]
    async fn test_uniqueness_invalid_proof() -> eyre::Result<()> {
        check_invalid_proof(RpModuleKind::Uniqueness).await
    }

    #[tokio::test]
    async fn test_uniqueness_replay() -> eyre::Result<()> {
        check_replay(RpModuleKind::Uniqueness).await
    }

    #[tokio::test]
    async fn test_uniqueness_inactive_rp() -> eyre::Result<()> {
        check_inactive_rp(RpModuleKind::Uniqueness).await
    }

    #[tokio::test]
    async fn test_uniqueness_tampered_blinded_query() -> eyre::Result<()> {
        check_tampered_blinded_query(RpModuleKind::Uniqueness).await
    }

    #[tokio::test]
    async fn test_uniqueness_tampered_expiration_timestamp() -> eyre::Result<()> {
        check_tampered_expiration_timestamp(RpModuleKind::Uniqueness).await
    }

    #[tokio::test]
    async fn test_uniqueness_timestamp_zero() -> eyre::Result<()> {
        check_timestamp_zero(RpModuleKind::Uniqueness).await
    }

    #[tokio::test]
    async fn test_uniqueness_invalid_query_proof() -> eyre::Result<()> {
        check_invalid_query_proof(RpModuleKind::Uniqueness).await
    }
}
