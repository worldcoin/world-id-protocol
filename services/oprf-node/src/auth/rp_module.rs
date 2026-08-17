//! Unified RP-authenticated OPRF module.
//!
//! Both the session and uniqueness modules share identical struct fields, init
//! logic, and query-proof verification. They differ only in:
//! - how the action field is validated (`MSB == 0x00` for uniqueness vs `0x01/0x02` for sessions, via [`OprfPrefix`])
//! - how the typed proof/session intent authorizes the OPRF action
//! - which [`WorldIdRequestAuthError`] variant is returned for an invalid action
//!
//! [`RpModuleKind`] captures these differences; [`RpModuleAuth`] holds the shared
//! state and branches on the kind at runtime.

use crate::{
    auth::{
        merkle_watcher::{MerkleWatcher, MerkleWatcherError},
        nonce_history::{DuplicateNonce, NonceHistory, NonceScope},
        rp_registry_watcher::{RpRegistryWatcher, RpRegistryWatcherError},
    },
    metrics,
};
use alloy::primitives::Address;
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
    FieldElement, OprfPrefix, OprfPrefixedFieldElement as _, ProofType, RequestVersion,
    oprf::{NullifierOprfRequestAuthV1, WorldIdRequestAuthError},
    rp::{RpRequestAuthorization, RpRequestSessionMode, session_seed_authorization},
};

pub(crate) mod wip101;

/// Distinguishes the two RP-authenticated OPRF modules.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RpModuleKind {
    /// Session module: action MSB must be `0x01` (seed) or `0x02` (action).
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
    #[error("Invalid action for session (action MSB must be 0x01 or 0x02): {action}")]
    InvalidActionSession { action: FieldElement },

    #[error("Invalid action for uniqueness (action MSB must be 0x00): {action}")]
    InvalidActionUniqueness { action: FieldElement },
    #[error("Invalid RP signature verification data: {context}")]
    InvalidRpSignatureVerification { context: &'static str },
    #[error("Could not verify query proof")]
    InvalidQueryProof,
    #[error(transparent)]
    MerkleWatcher(#[from] Arc<MerkleWatcherError>),
    #[error(transparent)]
    RpRegistry(#[from] Arc<RpRegistryWatcherError>),
    #[error("created_at in request too old, created_at={created_at:?}, current={current:?}")]
    TimestampTooOld {
        created_at: chrono::DateTime<Utc>,
        current: chrono::DateTime<Utc>,
    },
    #[error(
        "expires_at in request too far in future, created_at={created_at:?}, expires_at={expires_at:?}"
    )]
    ExpiresAtTooFarInFuture {
        expires_at: chrono::DateTime<Utc>,
        created_at: chrono::DateTime<Utc>,
    },
    #[error(
        "created_at in request too far in future, created_at={created_at:?}, current={current:?}"
    )]
    TimestampTooFarInFuture {
        created_at: chrono::DateTime<Utc>,
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
    #[error(transparent)]
    DuplicateNonce(#[from] DuplicateNonce),
    #[error(transparent)]
    Wip101(#[from] wip101::Wip101Error),
    #[error("Internal error: {0:?}")]
    Internal(#[from] eyre::Report),
}

impl From<&RpModuleError> for WorldIdRequestAuthError {
    fn from(value: &RpModuleError) -> Self {
        match value {
            RpModuleError::InvalidActionSession { .. } => Self::InvalidActionSession,
            RpModuleError::InvalidActionUniqueness { .. } => Self::InvalidActionNullifier,
            RpModuleError::InvalidRpSignatureVerification { .. } => {
                Self::InvalidRpSignatureVerification
            }
            RpModuleError::InvalidQueryProof => Self::InvalidQueryProof,
            RpModuleError::MerkleWatcher(e) => Self::from(e.as_ref()),
            RpModuleError::RpRegistry(e) => Self::from(e.as_ref()),
            RpModuleError::TimestampTooOld { .. } => Self::CreatedAtTooOld,
            RpModuleError::TimestampTooFarInFuture { .. } => Self::CreatedAtTooFarInFuture,
            RpModuleError::ExpiresAtTooFarInFuture { .. } => Self::ExpiresAtTooFarInFuture,
            RpModuleError::RpSignatureExpired { .. } => Self::RpSignatureExpired,
            RpModuleError::InvalidTimestamp(_) => Self::InvalidTimestamp,
            RpModuleError::RpSignatureMissing => Self::RpSignatureMissing,
            RpModuleError::CorruptSignature(_) | RpModuleError::InvalidSignature => {
                Self::InvalidRpSignature
            }
            RpModuleError::DuplicateNonce(_) => Self::DuplicateNonce,
            RpModuleError::Wip101(e) => Self::from(e),
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
            RpAccountType::Contract => write!(f, "contract (WIP-101)"),
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
    created_at_max_difference: chrono::Duration,
    expires_at_max_difference: chrono::Duration,
    timeout_external_eth_call: Duration,
    merkle_watcher: MerkleWatcher,
    rpc_provider: web3::HttpRpcProvider,
    rp_registry_address: Address,
    chain_id: u64,
    query_vk: Arc<PreparedVerifyingKey<Bn254>>,
}

impl RelyingParty {
    fn signature(
        request: &OprfRequest<NullifierOprfRequestAuthV1>,
    ) -> Result<alloy::primitives::Signature, RpModuleError> {
        let signature = request
            .auth
            .signature
            .ok_or_else(|| RpModuleError::RpSignatureMissing)?;
        if request.auth.wip101_data.is_some() {
            return Err(RpModuleError::Wip101(wip101::Wip101Error::AuxDataOnEoa));
        }
        Ok(signature)
    }

    fn verify_eoa(
        &self,
        authorization: &RpRequestAuthorization,
        chain_id: u64,
        rp_registry_address: Address,
        request: &OprfRequest<NullifierOprfRequestAuthV1>,
    ) -> Result<(), RpModuleError> {
        let signature = Self::signature(request)?;
        let digest = authorization.signing_hash(chain_id, rp_registry_address);

        tracing::trace!("checking EIP-712 RP signature");
        let recovered = signature.recover_address_from_prehash(&digest)?;
        if recovered != self.signer {
            return Err(RpModuleError::InvalidSignature);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct RpModuleAuthArgs {
    pub(crate) merkle_watcher: MerkleWatcher,
    pub(crate) rp_registry_watcher: RpRegistryWatcher,
    pub(crate) nonce_history: NonceHistory,
    pub(crate) created_at_max_difference: chrono::Duration,
    pub(crate) expires_at_max_difference: chrono::Duration,
    pub(crate) timeout_external_eth_call: Duration,
    pub(crate) rpc_provider: web3::HttpRpcProvider,
    pub(crate) rp_registry_address: Address,
    /// Chain of the RP registry, resolved once at startup and bound into the EIP-712 domain.
    pub(crate) chain_id: u64,
    pub(crate) query_vk: Arc<PreparedVerifyingKey<Bn254>>,
}

impl RpModuleAuth {
    /// Initializes a session-module authenticator.
    pub(crate) fn new_session(args: RpModuleAuthArgs) -> Self {
        Self::new(RpModuleKind::Session, args)
    }

    /// Initializes a uniqueness-module authenticator.
    pub(crate) fn new_uniqueness(args: RpModuleAuthArgs) -> Self {
        Self::new(RpModuleKind::Uniqueness, args)
    }

    fn new(kind: RpModuleKind, args: RpModuleAuthArgs) -> Self {
        let RpModuleAuthArgs {
            merkle_watcher,
            rp_registry_watcher,
            nonce_history,
            created_at_max_difference,
            expires_at_max_difference,
            timeout_external_eth_call,
            rpc_provider,
            rp_registry_address,
            chain_id,
            query_vk,
        } = args;
        Self {
            kind,
            rp_registry_watcher,
            nonce_history,
            created_at_max_difference,
            expires_at_max_difference,
            timeout_external_eth_call,
            merkle_watcher,
            rpc_provider,
            rp_registry_address,
            chain_id,
            query_vk,
        }
    }

    /// Checks that the signature has not expired and that the request timestamp
    /// is within the configured window around the node's system time.
    fn validate_timestamps(&self, auth: &NullifierOprfRequestAuthV1) -> Result<(), RpModuleError> {
        let current_time = Utc::now();

        tracing::trace!("checking expiration timestamp on signature...");
        let expires_at = parse_timestamp(auth.expires_at)?;
        if expires_at <= current_time {
            return Err(RpModuleError::RpSignatureExpired {
                current: current_time,
                expired_timestamp: expires_at,
            });
        }

        tracing::trace!("checking timestamp on signature...");
        let created_at = parse_timestamp(auth.created_at)?;
        if created_at > current_time + self.created_at_max_difference {
            return Err(RpModuleError::TimestampTooFarInFuture {
                created_at,
                current: current_time,
            });
        }
        if created_at < current_time - self.created_at_max_difference {
            return Err(RpModuleError::TimestampTooOld {
                created_at,
                current: current_time,
            });
        }

        tracing::trace!("checking delta between created at and expires_at...");
        let max_expires_at = created_at + self.expires_at_max_difference;
        if expires_at > max_expires_at {
            return Err(RpModuleError::ExpiresAtTooFarInFuture {
                expires_at,
                created_at,
            });
        }
        Ok(())
    }

    async fn ensure_signature_valid(
        &self,
        rp: &RelyingParty,
        action: ark_babyjubjub::Fq,
        request: &OprfRequest<NullifierOprfRequestAuthV1>,
    ) -> Result<(), RpModuleError> {
        match rp.account_type {
            RpAccountType::Eoa => {
                tracing::trace!("RP signer is EOA");
                rp.verify_eoa(
                    &request.auth.rp_request_authorization,
                    self.chain_id,
                    self.rp_registry_address,
                    request,
                )
            }
            RpAccountType::Contract => Ok(rp
                .verify_wip101(
                    action,
                    &request.auth.rp_request_authorization,
                    &request.auth,
                    &self.rpc_provider,
                    self.timeout_external_eth_call,
                )
                .await?),
            RpAccountType::IncompatibleWip101 => {
                tracing::trace!("RP signer is incompatible WIP101");
                Err(RpModuleError::Wip101(
                    wip101::Wip101Error::IncompatibleRpSigner,
                ))
            }
        }
    }

    async fn verify_rp_signature(
        &self,
        action: ark_babyjubjub::Fq,
        request: &OprfRequest<NullifierOprfRequestAuthV1>,
    ) -> Result<OprfKeyId, RpModuleError> {
        self.validate_timestamps(&request.auth)?;

        tracing::trace!("fetching RP info...");
        // fetch the RP info
        let rp = self.rp_registry_watcher.get_rp(request.auth.rp_id).await?;

        if request.auth.rp_request_authorization.oprf_key_id != rp.oprf_key_id {
            return Err(RpModuleError::InvalidRpSignatureVerification {
                context: "signed OPRF key does not match the RP registry",
            });
        }

        self.ensure_signature_valid(&rp, action, request).await?;

        tracing::trace!("RP signature authentication successful");
        Ok(rp.oprf_key_id)
    }

    async fn authenticate_inner(
        &self,
        request: &OprfRequest<NullifierOprfRequestAuthV1>,
    ) -> Result<OprfKeyId, RpModuleError> {
        tracing::trace!("Validating action for {}", self.kind);
        let action = FieldElement::from(request.auth.action);

        Self::validate_authorization_transport(&request.auth)?;

        // Validate the action per kind and derive the nonce scope it consumes.
        let nonce_scope = self.validate_action(
            &request.auth.rp_request_authorization,
            action,
            &request.auth,
        )?;

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
            tracing::trace!("add nonce to store...");
            // Add nonce to history to check if the nonce was only used once in this scope.
            // Only add if everything else was successful
            self.nonce_history
                .add_nonce(FieldElement::from(request.auth.nonce), nonce_scope)
                .await?;
            tracing::trace!("authentication successful!");
            Ok(oprf_key_id)
        } else {
            Err(RpModuleError::InvalidQueryProof)
        }
    }

    fn validate_authorization_transport(
        auth: &NullifierOprfRequestAuthV1,
    ) -> Result<(), RpModuleError> {
        let authorization = &auth.rp_request_authorization;
        if authorization.request_version != RequestVersion::V1 {
            return Err(RpModuleError::InvalidRpSignatureVerification {
                context: "typed authorization must use request version 1",
            });
        }
        if authorization.details_hash == alloy::primitives::B256::ZERO {
            return Err(RpModuleError::InvalidRpSignatureVerification {
                context: "request-details commitment must be non-zero",
            });
        }
        if authorization.rp_id != auth.rp_id
            || *authorization.nonce != auth.nonce
            || authorization.created_at != auth.created_at
            || authorization.expires_at != auth.expires_at
        {
            return Err(RpModuleError::InvalidRpSignatureVerification {
                context: "typed authorization does not match OPRF request metadata",
            });
        }

        let valid_shape = matches!(
            (
                authorization.proof_type,
                authorization.session_mode,
                authorization.action,
            ),
            (
                ProofType::Uniqueness,
                RpRequestSessionMode::None | RpRequestSessionMode::Create,
                Some(_),
            ) | (
                ProofType::Session,
                RpRequestSessionMode::Create | RpRequestSessionMode::Existing,
                None,
            )
        );
        if !valid_shape {
            return Err(RpModuleError::InvalidRpSignatureVerification {
                context: "invalid proof, session, and action combination",
            });
        }

        let has_existing_seed_authorization =
            authorization.existing_session_seed_authorization != alloy::primitives::B256::ZERO;
        if has_existing_seed_authorization
            != matches!(authorization.session_mode, RpRequestSessionMode::Existing)
        {
            return Err(RpModuleError::InvalidRpSignatureVerification {
                context: "existing-session seed authorization does not match session mode",
            });
        }
        Ok(())
    }

    fn validate_action(
        &self,
        authorization: &RpRequestAuthorization,
        action: FieldElement,
        auth: &NullifierOprfRequestAuthV1,
    ) -> Result<NonceScope, RpModuleError> {
        match self.kind {
            RpModuleKind::Uniqueness => {
                metrics::auth_module::inc_nullifier();
                if action.to_be_bytes()[0] != 0 {
                    return Err(RpModuleError::InvalidActionUniqueness { action });
                }
                if authorization.proof_type != ProofType::Uniqueness
                    || authorization.action != Some(action)
                    || auth.session_seed_opening.is_some()
                {
                    return Err(RpModuleError::InvalidRpSignatureVerification {
                        context: "authorization does not permit this uniqueness query",
                    });
                }
                Ok(NonceScope::Uniqueness)
            }
            RpModuleKind::Session => {
                metrics::auth_module::inc_session();
                if action.has_prefix(OprfPrefix::SessionOprfSeed) {
                    let permitted = match (
                        authorization.proof_type,
                        authorization.session_mode,
                        auth.session_seed_opening,
                    ) {
                        (
                            ProofType::Uniqueness | ProofType::Session,
                            RpRequestSessionMode::Create,
                            None,
                        ) => true,
                        (ProofType::Session, RpRequestSessionMode::Existing, Some(opening)) => {
                            session_seed_authorization(opening, action)
                                == authorization.existing_session_seed_authorization
                        }
                        _ => false,
                    };
                    if !permitted {
                        return Err(RpModuleError::InvalidRpSignatureVerification {
                            context: "authorization does not permit this session-seed query",
                        });
                    }
                    Ok(NonceScope::SessionOprfSeed)
                } else if action.has_prefix(OprfPrefix::SessionAction) {
                    if authorization.proof_type != ProofType::Session
                        || !matches!(
                            authorization.session_mode,
                            RpRequestSessionMode::Create | RpRequestSessionMode::Existing
                        )
                        || auth.session_seed_opening.is_some()
                    {
                        return Err(RpModuleError::InvalidRpSignatureVerification {
                            context: "authorization does not permit this session-action query",
                        });
                    }
                    Ok(NonceScope::SessionAction)
                } else {
                    Err(RpModuleError::InvalidActionSession { action })
                }
            }
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
            .map_err(|err| super::auth_module_error(err, "RP-module"))?)
    }
}

#[cfg(test)]
mod tests;
