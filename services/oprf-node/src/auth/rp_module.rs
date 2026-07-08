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

use crate::{
    accountant_batcher::AccountantBatcherHandle,
    auth::{
        merkle_watcher::{MerkleWatcher, MerkleWatcherError},
        nonce_history::{DuplicateNonce, NonceHistory, NonceScope},
        rp_registry_watcher::{RpRegistryWatcher, RpRegistryWatcherError},
    },
    metrics,
};
use alloy::primitives::{Address, U256};
use ark_bn254::Bn254;
use ark_groth16::PreparedVerifyingKey;
use async_trait::async_trait;
use chrono::Utc;
use oprf_accountant::api::BillableRpRequest;
use std::{fmt, sync::Arc, time::Duration};
use taceo_nodes_common::web3;
use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator, OprfRequestAuthenticatorError},
};
use tracing::instrument;
use world_id_primitives::{
    FieldElement, SessionFeType, SessionFieldElement as _,
    oprf::{NullifierOprfRequestAuthV1, WorldIdRequestAuthError},
};

pub(crate) mod wip101;

/// Distinguishes the two RP-authenticated OPRF modules.
#[derive(Clone)]
pub(crate) enum RpModuleKind {
    /// Session module: action MSB must be `0x01` (seed) or `0x02` (action); action is NOT signed.
    Session,
    /// Uniqueness module: action MSB must be `0x00`; action IS signed.
    Uniqueness(AccountantBatcherHandle),
}

impl fmt::Debug for RpModuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session => write!(f, "Session"),
            Self::Uniqueness(_) => write!(f, "Uniqueness"),
        }
    }
}

impl fmt::Display for RpModuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RpModuleKind::Session => write!(f, "session (action MSB must be 0x01 or 0x02)"),
            RpModuleKind::Uniqueness(_) => write!(f, "uniqueness (action MSB must be 0x00)"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RpModuleError {
    #[error("Invalid action for session (action MSB must be 0x01 or 0x02): {action}")]
    InvalidActionSession { action: FieldElement },

    #[error("Invalid action for uniqueness (action MSB must be 0x00): {action}")]
    InvalidActionUniqueness { action: FieldElement },
    #[error("Could not verify query proof")]
    InvalidQueryProof,
    #[error(transparent)]
    MerkleWatcher(#[from] Arc<MerkleWatcherError>),
    #[error(transparent)]
    RpRegistry(#[from] Arc<RpRegistryWatcherError>),
    #[error("Current Timestamp in request too old, timestamp={timestamp:?}, current={current:?}")]
    TimestampTooOld {
        timestamp: chrono::DateTime<Utc>,
        current: chrono::DateTime<Utc>,
    },
    #[error(
        "Current Timestamp in request too far in future, timestamp={timestamp:?}, current={current:?}"
    )]
    TimestampTooFarInFuture {
        timestamp: chrono::DateTime<Utc>,
        current: chrono::DateTime<Utc>,
    },
    #[error("RP signature expired at {expired_timestamp:?}, current={current:?}")]
    RpSignatureExpired {
        current: chrono::DateTime<Utc>,
        expired_timestamp: chrono::DateTime<Utc>,
    },
    #[error("Invalid Unix timestamp: {0}")]
    InvalidTimestamp(u64),
    #[error("Cannot build signature: {0}")]
    CorruptSignature(#[from] alloy::primitives::SignatureError),
    #[error("Invalid RP signature - recover signer failed")]
    InvalidSignature,
    #[error("RP signature is required for EOA-backed signers")]
    RpSignatureMissing,
    #[error("Auxiliary data must be empty with EOA backed signer")]
    Wip101AuxDataOnEoa,
    #[error(transparent)]
    DuplicateNonce(#[from] DuplicateNonce),
    #[error("RP signer is a contract but does not conform to WIP101")]
    Wip101IncompatibleRpSigner,
    #[error("Ran into timeout while verifying RP signature")]
    Wip101VerificationTimeout,
    #[error("RP signer contract reverted with custom error")]
    Wip101CustomRevert,
    #[error("RP signer contract reverts with code: {0:?}")]
    Wip101VerificationFailed(Option<U256>),
    #[error("Auxiliary data for WIP101 contract too large")]
    Wip101AuxDataTooLarge,
    #[error("Internal error: {0:?}")]
    Internal(#[from] eyre::Report),
}

impl From<&RpModuleError> for WorldIdRequestAuthError {
    fn from(value: &RpModuleError) -> Self {
        match value {
            RpModuleError::InvalidActionSession { .. } => Self::InvalidActionSession,
            RpModuleError::InvalidActionUniqueness { .. } => Self::InvalidActionNullifier,
            RpModuleError::InvalidQueryProof => Self::InvalidQueryProof,
            RpModuleError::MerkleWatcher(e) => e.as_ref().into(),
            RpModuleError::RpRegistry(e) => e.as_ref().into(),
            RpModuleError::TimestampTooOld { .. } => Self::TimestampTooOld,
            RpModuleError::TimestampTooFarInFuture { .. } => Self::TimestampTooFarInFuture,
            RpModuleError::RpSignatureExpired { .. } => Self::RpSignatureExpired,
            RpModuleError::InvalidTimestamp(_) => Self::InvalidTimestamp,
            RpModuleError::RpSignatureMissing => Self::RpSignatureMissing,
            RpModuleError::CorruptSignature(_) | RpModuleError::InvalidSignature => {
                Self::InvalidRpSignature
            }
            RpModuleError::DuplicateNonce(_) => Self::DuplicateNonce,
            RpModuleError::Wip101IncompatibleRpSigner => Self::Wip101IncompatibleRpSigner,
            RpModuleError::Wip101VerificationTimeout => Self::Wip101VerificationTimeout,
            RpModuleError::Wip101VerificationFailed(code) => Self::Wip101VerificationFailed(*code),
            RpModuleError::Wip101CustomRevert => Self::Wip101CustomRevert,
            RpModuleError::Wip101AuxDataOnEoa => Self::Wip101AuxDataOnEoa,
            RpModuleError::Wip101AuxDataTooLarge => Self::Wip101AuxDataTooLarge,
            RpModuleError::Internal(_) => Self::Internal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RpAccountType {
    Eoa,
    Contract,
    IncompatibleWip101,
}

impl fmt::Display for RpAccountType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpAccountType::Eoa => write!(f, "eoa"),
            RpAccountType::Contract => write!(f, "contract"),
            RpAccountType::IncompatibleWip101 => write!(f, "incompatible wip101 contract"),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RelyingParty {
    pub(crate) signer: Address,
    pub(crate) oprf_key_id: OprfKeyId,
    pub(crate) account_type: RpAccountType,
}

pub(crate) struct RpModuleAuth {
    kind: RpModuleKind,
    rp_registry_watcher: RpRegistryWatcher,
    nonce_history: NonceHistory,
    current_time_stamp_max_difference: Duration,
    timeout_external_eth_call: Duration,
    merkle_watcher: MerkleWatcher,
    rpc_provider: web3::HttpRpcProvider,
    query_vk: Arc<PreparedVerifyingKey<Bn254>>,
}

impl RelyingParty {
    fn verify_eoa(
        &self,
        action: Option<ark_babyjubjub::Fq>,
        request: &OprfRequest<NullifierOprfRequestAuthV1>,
    ) -> Result<(), RpModuleError> {
        let signature = request
            .auth
            .signature
            .ok_or_else(|| RpModuleError::RpSignatureMissing)?;
        if request.auth.wip101_data.is_some() {
            return Err(RpModuleError::Wip101AuxDataOnEoa);
        }
        // check the RP nonce signature
        let msg = world_id_primitives::rp::compute_rp_signature_msg(
            request.auth.nonce,
            request.auth.current_time_stamp,
            request.auth.expiration_timestamp,
            action,
        );

        tracing::trace!("check RP signature...");
        let recovered = signature.recover_address_from_msg(msg)?;
        if recovered != self.signer {
            return Err(RpModuleError::InvalidSignature);
        }
        Ok(())
    }

    async fn ensure_signature_valid(
        &self,
        kind: &RpModuleKind,
        action: ark_babyjubjub::Fq,
        request: &OprfRequest<NullifierOprfRequestAuthV1>,
        wip101_timeout: Duration,
        rpc_provider: &web3::HttpRpcProvider,
    ) -> Result<(), RpModuleError> {
        match self.account_type {
            RpAccountType::Eoa => {
                tracing::trace!("RP signer is EOA");
                let action = match kind {
                    RpModuleKind::Uniqueness(_) => Some(action),
                    RpModuleKind::Session => None,
                };
                self.verify_eoa(action, request)
            }
            RpAccountType::Contract => {
                tracing::trace!("RP signer is WIP101");
                // TODO(session-proofs): WIP-101 does not currently support session proofs.
                self.verify_wip101(action, &request.auth, rpc_provider, wip101_timeout)
                    .await
            }
            RpAccountType::IncompatibleWip101 => {
                tracing::trace!("RP signer is incompatible WIP101");
                Err(RpModuleError::Wip101IncompatibleRpSigner)
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct RpModuleAuthArgs {
    pub(crate) merkle_watcher: MerkleWatcher,
    pub(crate) rp_registry_watcher: RpRegistryWatcher,
    pub(crate) nonce_history: NonceHistory,
    pub(crate) current_time_stamp_max_difference: Duration,
    pub(crate) timeout_external_eth_call: Duration,
    pub(crate) rpc_provider: web3::HttpRpcProvider,
    pub(crate) query_vk: Arc<PreparedVerifyingKey<Bn254>>,
}

impl RpModuleAuth {
    /// Initializes a session-module authenticator.
    pub(crate) fn new_session(args: RpModuleAuthArgs) -> Self {
        let RpModuleAuthArgs {
            merkle_watcher,
            rp_registry_watcher,
            nonce_history,
            current_time_stamp_max_difference,
            timeout_external_eth_call,
            rpc_provider,
            query_vk,
        } = args;
        Self {
            kind: RpModuleKind::Session,
            rp_registry_watcher,
            nonce_history,
            current_time_stamp_max_difference,
            timeout_external_eth_call,
            merkle_watcher,
            rpc_provider,
            query_vk,
        }
    }

    /// Initializes a uniqueness-module authenticator.
    pub(crate) fn new_uniqueness(
        args: RpModuleAuthArgs,
        accountant_batcher: AccountantBatcherHandle,
    ) -> Self {
        let RpModuleAuthArgs {
            merkle_watcher,
            rp_registry_watcher,
            nonce_history,
            current_time_stamp_max_difference,
            timeout_external_eth_call,
            rpc_provider,
            query_vk,
        } = args;
        Self {
            kind: RpModuleKind::Uniqueness(accountant_batcher),
            rp_registry_watcher,
            nonce_history,
            current_time_stamp_max_difference,
            timeout_external_eth_call,
            merkle_watcher,
            rpc_provider,
            query_vk,
        }
    }

    async fn verify_rp_signature(
        &self,
        action: ark_babyjubjub::Fq,
        request: &OprfRequest<NullifierOprfRequestAuthV1>,
    ) -> Result<OprfKeyId, RpModuleError> {
        let current_time = Utc::now();
        let req_expiration_time_stamp = parse_timestamp(request.auth.expiration_timestamp)?;
        tracing::trace!("checking expiration timestamp on signature...");

        if req_expiration_time_stamp <= current_time {
            return Err(RpModuleError::RpSignatureExpired {
                current: current_time,
                expired_timestamp: req_expiration_time_stamp,
            });
        }

        // check the time stamp against system time +/- difference
        tracing::trace!("checking timestamp on signature...");
        let req_time_stamp = parse_timestamp(request.auth.current_time_stamp)?;
        let diff = current_time.signed_duration_since(req_time_stamp);
        let abs_diff = diff
            .abs()
            .to_std()
            .expect("absolute value is always non-negative");

        if abs_diff > self.current_time_stamp_max_difference {
            if diff < chrono::Duration::zero() {
                // req is in the future
                return Err(RpModuleError::TimestampTooFarInFuture {
                    timestamp: req_time_stamp,
                    current: current_time,
                });
            }
            // req is in the past
            return Err(RpModuleError::TimestampTooOld {
                timestamp: req_time_stamp,
                current: current_time,
            });
        }

        tracing::trace!("fetching RP info...");
        // fetch the RP info
        let rp = self.rp_registry_watcher.get_rp(&request.auth.rp_id).await?;

        rp.ensure_signature_valid(
            &self.kind,
            action,
            request,
            self.timeout_external_eth_call,
            &self.rpc_provider,
        )
        .await?;

        tracing::trace!("add nonce to store...");
        // Add nonce to history to check if the nonce was only used once in this scope.
        let nonce_scope = match self.kind {
            RpModuleKind::Uniqueness(_) => NonceScope::Uniqueness,
            RpModuleKind::Session => {
                let action = FieldElement::from(action);
                if action.is_valid_for_session(SessionFeType::OprfSeed) {
                    NonceScope::SessionOprfSeed
                } else if action.is_valid_for_session(SessionFeType::Action) {
                    NonceScope::SessionAction
                } else {
                    return Err(RpModuleError::InvalidActionSession { action });
                }
            }
        };
        self.nonce_history
            .add_nonce(FieldElement::from(request.auth.nonce), nonce_scope)
            .await?;

        tracing::trace!("RP signature authentication successful");
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
                metrics::auth_module::inc_session();
                if !action.is_valid_for_session(SessionFeType::OprfSeed)
                    && !action.is_valid_for_session(SessionFeType::Action)
                {
                    return Err(RpModuleError::InvalidActionSession { action });
                }
            }
            RpModuleKind::Uniqueness(_) => {
                metrics::auth_module::inc_nullifier();
                if action.to_be_bytes()[0] != 0 {
                    return Err(RpModuleError::InvalidActionUniqueness { action });
                }
            }
        }

        let (verify_rp_signature_check, merkle_check) = tokio::join!(
            self.verify_rp_signature(request.auth.action, request),
            self.merkle_watcher
                .ensure_root_valid(FieldElement::from(request.auth.merkle_root))
        );

        let oprf_key_id = verify_rp_signature_check?;
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

fn parse_timestamp(t: u64) -> Result<chrono::DateTime<Utc>, RpModuleError> {
    chrono::DateTime::from_timestamp_secs(
        i64::try_from(t).map_err(|_| RpModuleError::InvalidTimestamp(t))?,
    )
    .ok_or_else(|| RpModuleError::InvalidTimestamp(t))
}

#[async_trait]
impl OprfRequestAuthenticator for RpModuleAuth {
    type RequestAuth = NullifierOprfRequestAuthV1;

    #[instrument(level = "debug", skip_all)]
    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, OprfRequestAuthenticatorError> {
        Ok(Box::pin(self.authenticate_inner(request))
            .await
            .inspect(|_| {
                if let RpModuleKind::Uniqueness(handle) = &self.kind {
                    handle.record_request(BillableRpRequest::from(&request.auth));
                }
            })
            .map_err(|err| {
                let mapped = WorldIdRequestAuthError::from(&err);
                super::log_auth_module_error(&err, mapped, "RP-module");
                mapped
            })?)
    }
}

#[cfg(test)]
mod tests;
