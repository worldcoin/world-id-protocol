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
    auth::{
        merkle_watcher::{MerkleWatcher, MerkleWatcherError},
        nonce_history::{DuplicateNonce, NonceHistory},
        rp_registry_watcher::{RpRegistryWatcher, RpRegistryWatcherError},
    },
    metrics::{
        METRICS_ATTRVAL_RP_TYPE_CONTRACT, METRICS_ATTRVAL_RP_TYPE_EOA,
        METRICS_ATTRVAL_RP_TYPE_INCOMPATIBLE_WIP101_CONTRACT,
    },
};
use alloy::primitives::{Address, U256};
use ark_bn254::Bn254;
use ark_groth16::PreparedVerifyingKey;
use async_trait::async_trait;
use chrono::Utc;
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
    rp::RpId,
};

pub(crate) mod wip101;

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
    #[error("unknown rp: {0}")]
    UnknownRp(RpId),
    #[error("inactive rp: {0}")]
    InactiveRp(RpId),
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
    #[error("Ran into timeout while doing wip101 account check on RP: {0}")]
    Wip101AccountCheckTimeout(RpId),
    #[error("Ran into timeout while verifying RP signature")]
    Wip101VerificationTimeout,
    #[error("RP signer contract reverted with custom error")]
    Wip101CustomRevert,
    #[error("RP signer contract reverts with code: {0:?}")]
    Wip101VerificationFailed(Option<U256>),
    #[error("Auxiliary data for WIP101 contract too large")]
    Wip101AuxDataTooLarge,
    #[error(transparent)]
    Internal(#[from] eyre::Report),
}

impl From<Arc<MerkleWatcherError>> for RpModuleError {
    fn from(value: Arc<MerkleWatcherError>) -> Self {
        match value.as_ref() {
            MerkleWatcherError::InvalidMerkleRoot => Self::InvalidMerkleRoot,
            MerkleWatcherError::Internal(_) => Self::Internal(eyre::Report::from(value)),
        }
    }
}

impl From<Arc<RpRegistryWatcherError>> for RpModuleError {
    fn from(value: Arc<RpRegistryWatcherError>) -> Self {
        match value.as_ref() {
            RpRegistryWatcherError::UnknownRp(rp_id) => Self::UnknownRp(*rp_id),
            RpRegistryWatcherError::InactiveRp(rp_id) => Self::InactiveRp(*rp_id),
            RpRegistryWatcherError::Timeout(rp_id) => Self::Wip101AccountCheckTimeout(*rp_id),
            RpRegistryWatcherError::Internal(_) => Self::Internal(eyre::Report::from(value)),
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
            } => WorldIdRequestAuthError::TimestampTooOld,
            RpModuleError::TimestampTooFarInFuture {
                current: _,
                timestamp: _,
            } => WorldIdRequestAuthError::TimestampTooFarInFuture,
            RpModuleError::RpSignatureExpired {
                current: _,
                expired_timestamp: _,
            } => WorldIdRequestAuthError::RpSignatureExpired,
            RpModuleError::InvalidTimestamp(_) => WorldIdRequestAuthError::InvalidTimestamp,
            RpModuleError::RpSignatureMissing => WorldIdRequestAuthError::RpSignatureMissing,
            RpModuleError::Wip101AccountCheckTimeout(_) => {
                WorldIdRequestAuthError::Wip101AccountCheckTimeout
            }
            RpModuleError::UnknownRp(_) => WorldIdRequestAuthError::UnknownRp,
            RpModuleError::InactiveRp(_) => WorldIdRequestAuthError::InactiveRp,
            RpModuleError::CorruptSignature(_) | RpModuleError::InvalidSignature => {
                WorldIdRequestAuthError::InvalidRpSignature
            }
            RpModuleError::DuplicateNonce(_) => WorldIdRequestAuthError::DuplicateNonce,
            RpModuleError::Wip101IncompatibleRpSigner => {
                WorldIdRequestAuthError::Wip101IncompatibleRpSigner
            }
            RpModuleError::Wip101VerificationTimeout => {
                WorldIdRequestAuthError::Wip101VerificationTimeout
            }
            RpModuleError::Wip101VerificationFailed(code) => {
                WorldIdRequestAuthError::Wip101VerificationFailed(code)
            }
            RpModuleError::Wip101CustomRevert => WorldIdRequestAuthError::Wip101CustomRevert,
            RpModuleError::Wip101AuxDataOnEoa => WorldIdRequestAuthError::Wip101AuxDataOnEoa,
            RpModuleError::Wip101AuxDataTooLarge => WorldIdRequestAuthError::Wip101AuxDataTooLarge,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RpAccountType {
    Eoa,
    Contract,
    IncompatibleWip101,
}

impl RpAccountType {
    pub(crate) fn metrics_label(self) -> &'static str {
        match self {
            RpAccountType::Eoa => METRICS_ATTRVAL_RP_TYPE_EOA,
            RpAccountType::Contract => METRICS_ATTRVAL_RP_TYPE_CONTRACT,
            RpAccountType::IncompatibleWip101 => {
                METRICS_ATTRVAL_RP_TYPE_INCOMPATIBLE_WIP101_CONTRACT
            }
        }
    }
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
        kind: RpModuleKind,
        action: ark_babyjubjub::Fq,
        request: &OprfRequest<NullifierOprfRequestAuthV1>,
        wip101_timeout: Duration,
        rpc_provider: &web3::HttpRpcProvider,
    ) -> Result<(), RpModuleError> {
        match self.account_type {
            RpAccountType::Eoa => {
                tracing::trace!("RP signer is EOA");
                let action = match kind {
                    RpModuleKind::Uniqueness => Some(action),
                    RpModuleKind::Session => None,
                };
                self.verify_eoa(action, request)
            }
            RpAccountType::Contract => {
                tracing::trace!("RP signer is WIP101");
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

impl RpModuleAuth {
    /// Initializes a session-module authenticator.
    pub(crate) fn new_session(
        merkle_watcher: MerkleWatcher,
        rp_registry_watcher: RpRegistryWatcher,
        nonce_history: NonceHistory,
        current_time_stamp_max_difference: Duration,
        timeout_external_eth_call: Duration,
        rpc_provider: web3::HttpRpcProvider,
        query_vk: Arc<PreparedVerifyingKey<Bn254>>,
    ) -> Self {
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
        merkle_watcher: MerkleWatcher,
        rp_registry_watcher: RpRegistryWatcher,
        nonce_history: NonceHistory,
        current_time_stamp_max_difference: Duration,
        timeout_external_eth_call: Duration,
        rpc_provider: web3::HttpRpcProvider,
        query_vk: Arc<PreparedVerifyingKey<Bn254>>,
    ) -> Self {
        Self {
            kind: RpModuleKind::Uniqueness,
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
            self.kind,
            action,
            request,
            self.timeout_external_eth_call,
            &self.rpc_provider,
        )
        .await?;

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

        let oprf_key_id = self
            .verify_rp_signature(request.auth.action, request)
            .await?;

        self.merkle_watcher
            .ensure_root_valid(FieldElement::from(request.auth.merkle_root))
            .await?;

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
        Ok(self
            .authenticate_inner(request)
            .await
            .inspect_err(RpModuleError::log)
            .map_err(WorldIdRequestAuthError::from)?)
    }
}

#[cfg(test)]
mod tests;
