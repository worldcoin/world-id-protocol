//! RP verification of Uniqueness and Session Proofs without calling `WorldIDVerifier`.
//!
//! [`verify_world_id_proof`] checks a [`ProofResponse`] against the RP's own [`ProofRequest`]
//! and runs every check `WorldIDVerifier` runs on-chain, reading on-chain state through a
//! [`WorldIdState`]. A state that follows the registries' events keeps proofs off the RPC: the
//! node never sees a nullifier, nonce or signal.
//!
//! The RP remains responsible for what the contract does not check either: the request is its own,
//! its `nonce` is one it issued and has not seen used (request expiry does not replace this), and
//! each nullifier is used at most once per action, compared as a field element, not as a string.

use std::{
    error::Error as StdError,
    future::Future,
    time::{SystemTime, SystemTimeError, UNIX_EPOCH},
};

use eddsa_babyjubjub::EdDSAPublicKey;
use world_id_primitives::{
    FieldElement, ProofRequest, ProofResponse, ProofType, RequestItem, ResponseItem,
    ValidationError, rp::RpId,
};
use world_id_proof::{
    NullifierProofKind, NullifierProofVerificationError, NullifierPublicInputs,
    nullifier_proof_verification::merkle_root, verify_nullifier_proof,
};

/// A point on `BabyJubJub`, the curve of OPRF public keys.
pub type OprfPublicKey = ark_babyjubjub::EdwardsAffine;

type BoxError = Box<dyn StdError + Send + Sync>;

/// The on-chain state `WorldIDVerifier` reads.
///
/// Implementations SHOULD answer from local state that follows the registries' events, so that
/// verifying a proof sends nothing about it to an RPC node. Every method fails closed: an error
/// rejects the proof. Implementations MUST:
/// - return an error instead of an answer when their view of the chain may be stale, e.g. when an
///   event follower has fallen behind the chain head by more than the RP tolerates;
/// - bound every lookup with a timeout and return an error when it expires;
/// - reflect removals: a removed schema or a deleted OPRF key is `None`.
pub trait WorldIdState: Sync {
    /// The error of a lookup.
    type Error: Into<BoxError>;

    /// Whether `root` is valid in `WorldIDRegistry` at time `now` (`isValidRoot`): the latest root,
    /// or a known root recorded no longer than the root validity window before `now`.
    fn is_valid_root(
        &self,
        root: FieldElement,
        now: u64,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// The Issuer key `CredentialSchemaIssuerRegistry` holds for `issuer_schema_id`, or `None` if
    /// the schema is not registered (`issuerSchemaIdToPubkey`). A key with a zero coordinate is
    /// rejected as unregistered either way, as the contract does.
    fn issuer_public_key(
        &self,
        issuer_schema_id: u64,
    ) -> impl Future<Output = Result<Option<EdDSAPublicKey>, Self::Error>> + Send;

    /// The OPRF public key `OprfKeyRegistry` holds for the RP's OPRF key, or `None` if it has none.
    fn oprf_public_key(
        &self,
        rp_id: RpId,
    ) -> impl Future<Output = Result<Option<OprfPublicKey>, Self::Error>> + Send;

    /// `WorldIDVerifier.getMinExpirationThreshold`, in seconds.
    fn min_expiration_threshold(&self) -> impl Future<Output = Result<u64, Self::Error>> + Send;
}

/// Why a Uniqueness or Session Proof was rejected.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WorldIdProofVerificationError {
    /// The request is neither a Uniqueness nor a Session Proof request.
    #[error("the request is not a uniqueness or session request")]
    NotWorldIdProof,
    /// The response does not answer the request.
    #[error(transparent)]
    Response(#[from] ValidationError),
    /// The system clock is before the Unix epoch.
    #[error("the system clock is before the Unix epoch: {0}")]
    Clock(#[from] SystemTimeError),
    /// The request expired before verification.
    #[error("the request expired at {expires_at}")]
    RequestExpired {
        /// The request's `expires_at`.
        expires_at: u64,
    },
    /// A response item uses another credential schema than the request item it answers.
    #[error("{identifier} answers with issuer schema {got}, the request asks for {expected}")]
    IssuerSchemaMismatch {
        /// The item's identifier.
        identifier: String,
        /// The request item's schema.
        expected: u64,
        /// The response item's schema.
        got: u64,
    },
    /// The response binds the proof to a session whose commitment is `0`, which the contract
    /// rejects (`InvalidSessionId`).
    #[error("the session id commitment is zero")]
    ZeroSessionId,
    /// The proof's minimum credential expiration is older than the threshold allows, or adding the
    /// threshold overflows (which reverts on-chain).
    #[error("{0}: expires_at_min is older than the minimum expiration threshold")]
    ExpirationTooOld(String),
    /// The proof's Merkle root is not a valid `WorldIDRegistry` root.
    #[error("{0}: the merkle root is not a valid root")]
    InvalidRoot(String),
    /// The credential schema has no registered Issuer key.
    #[error("issuer schema {0} is not registered")]
    UnregisteredIssuerSchemaId(u64),
    /// The RP has no OPRF key.
    #[error("rp {0} has no oprf key")]
    UnknownOprfKey(RpId),
    /// A state lookup failed.
    #[error("could not read world id state: {0}")]
    State(BoxError),
    /// The proof does not verify.
    #[error("{identifier}: {source}")]
    Proof {
        /// The item's identifier.
        identifier: String,
        /// Why the proof was rejected.
        source: NullifierProofVerificationError,
    },
}

/// Verifies the Uniqueness or Session Proof `response` to the RP's own `request`.
///
/// Time checks use the system clock, where the contract uses `block.timestamp`; a clock behind the
/// chain accepts proofs the contract has started to reject. Use [`verify_world_id_proof_at`] to
/// supply the time.
///
/// # Errors
/// The first failing check, see [`WorldIdProofVerificationError`].
pub async fn verify_world_id_proof<S: WorldIdState>(
    request: &ProofRequest,
    response: &ProofResponse,
    state: &S,
) -> Result<(), WorldIdProofVerificationError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    verify_world_id_proof_at(request, response, state, now).await
}

/// [`verify_world_id_proof`] at time `now`, in Unix seconds, e.g. the latest block's timestamp.
///
/// # Errors
/// The first failing check, see [`WorldIdProofVerificationError`].
pub async fn verify_world_id_proof_at<S: WorldIdState>(
    request: &ProofRequest,
    response: &ProofResponse,
    state: &S,
    now: u64,
) -> Result<(), WorldIdProofVerificationError> {
    use WorldIdProofVerificationError as Error;

    let kind = match request.proof_type {
        ProofType::Uniqueness { .. } => NullifierProofKind::Uniqueness,
        ProofType::Session => NullifierProofKind::Session,
        ProofType::EmbeddingSimilarity(_) => return Err(Error::NotWorldIdProof),
    };
    request.validate_response(response)?;
    if now > request.expires_at {
        return Err(Error::RequestExpired {
            expires_at: request.expires_at,
        });
    }
    let session_id = session_id_input(request, response)?;
    let threshold = state
        .min_expiration_threshold()
        .await
        .map_err(|err| Error::State(err.into()))?;
    let oprf_public_key = state
        .oprf_public_key(request.rp_id)
        .await
        .map_err(|err| Error::State(err.into()))?
        .ok_or(Error::UnknownOprfKey(request.rp_id))?;

    for item in &response.responses {
        // `validate_response` guarantees a request item for every response item.
        let request_item = request
            .requests
            .iter()
            .find(|r| r.identifier == item.identifier)
            .ok_or_else(|| ValidationError::UnexpectedCredential(item.identifier.clone()))?;
        verify_item(
            request,
            request_item,
            item,
            kind,
            session_id,
            oprf_public_key,
            threshold,
            state,
            now,
        )
        .await?;
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "one call site, all values distinct"
)]
async fn verify_item<S: WorldIdState>(
    request: &ProofRequest,
    request_item: &RequestItem,
    item: &ResponseItem,
    kind: NullifierProofKind,
    session_id: FieldElement,
    oprf_public_key: OprfPublicKey,
    threshold: u64,
    state: &S,
    now: u64,
) -> Result<(), WorldIdProofVerificationError> {
    use WorldIdProofVerificationError as Error;

    if item.issuer_schema_id != request_item.issuer_schema_id {
        return Err(Error::IssuerSchemaMismatch {
            identifier: item.identifier.clone(),
            expected: request_item.issuer_schema_id,
            got: item.issuer_schema_id,
        });
    }
    if item
        .expires_at_min
        .checked_add(threshold)
        .is_none_or(|min_expiration| min_expiration < now)
    {
        return Err(Error::ExpirationTooOld(item.identifier.clone()));
    }
    let root = merkle_root(&item.proof).ok_or_else(|| Error::Proof {
        identifier: item.identifier.clone(),
        source: NullifierProofVerificationError::MerkleRootNotInField,
    })?;
    if !state
        .is_valid_root(root, now)
        .await
        .map_err(|err| Error::State(err.into()))?
    {
        return Err(Error::InvalidRoot(item.identifier.clone()));
    }
    let issuer_public_key = state
        .issuer_public_key(item.issuer_schema_id)
        .await
        .map_err(|err| Error::State(err.into()))?
        .filter(|key| ![key.pk.x, key.pk.y].contains(&ark_babyjubjub::Fq::from(0u64)))
        .ok_or(Error::UnregisteredIssuerSchemaId(item.issuer_schema_id))?;

    // `validate_response` guarantees the nullifier of the request's proof type.
    let (nullifier, action) = match &request.proof_type {
        ProofType::Uniqueness { action } => (
            item.nullifier
                .ok_or_else(|| ValidationError::MissingNullifier(item.identifier.clone()))?
                .inner,
            *action,
        ),
        ProofType::Session | ProofType::EmbeddingSimilarity(_) => {
            let session_nullifier = item
                .session_nullifier
                .ok_or_else(|| ValidationError::MissingSessionNullifier(item.identifier.clone()))?;
            (session_nullifier.nullifier(), session_nullifier.action())
        }
    };
    let public = NullifierPublicInputs {
        nullifier,
        issuer_schema_id: item.issuer_schema_id,
        issuer_public_key,
        expires_at_min: item.expires_at_min,
        genesis_issued_at_min: request_item.genesis_issued_at_min.unwrap_or(0),
        rp_id: request.rp_id.into_inner(),
        action,
        oprf_public_key,
        signal_hash: request_item.signal_hash(),
        nonce: request.nonce,
        session_id,
    };
    verify_nullifier_proof(kind, &item.proof, &public).map_err(|source| Error::Proof {
        identifier: item.identifier.clone(),
        source,
    })
}

/// The session id public input: the commitment of the session the proof is bound to, `0` for a
/// Uniqueness Proof bound to none.
fn session_id_input(
    request: &ProofRequest,
    response: &ProofResponse,
) -> Result<FieldElement, WorldIdProofVerificationError> {
    if request.session_id.is_none() {
        return Ok(FieldElement::ZERO);
    }
    // `validate_response` guarantees the response carries the session the request asks for.
    let session = response
        .session_id
        .ok_or(ValidationError::MissingSessionId)?;
    if session.commitment == FieldElement::ZERO {
        return Err(WorldIdProofVerificationError::ZeroSessionId);
    }
    Ok(session.commitment)
}

#[cfg(test)]
mod tests {
    use world_id_primitives::SessionId;

    use super::*;

    const CREATED_AT: u64 = 1_725_381_192;

    fn request(proof_type_and_session: &str) -> ProofRequest {
        ProofRequest::from_json(&format!(
            r#"{{
  "id": "req",
  "version": 1,
  "created_at": {CREATED_AT},
  "expires_at": {expires_at},
  "rp_id": "rp_0000000000000001",
  "oprf_key_id": "0x1",
  {proof_type_and_session},
  "signature": "0xa1fd06f0d8ceb541f6096fe2e865063eac1ff085c9d2bac2eedcc9ed03804bfc18d956b38c5ac3a8f7e71fde43deff3bda254d369c699f3c7a3f8e6b8477a5f51c",
  "nonce": "0x0000000000000000000000000000000000000000000000000000000000000001",
  "proof_requests": [{{ "identifier": "orb", "issuer_schema_id": 1 }}]
}}"#,
            expires_at = CREATED_AT + 300,
        ))
        .unwrap()
    }

    fn uniqueness_request() -> ProofRequest {
        request(
            r#""session_id": null, "action": "0x000000000000000000000000000000000000000000000000000000000000002a""#,
        )
    }

    /// A response whose proof points are all the point at infinity, under Merkle root `1`.
    fn uniqueness_response(issuer_schema_id: u64) -> ProofResponse {
        let proof = format!("{}{:064x}", "0".repeat(256), 1);
        ProofResponse::from_json(&format!(
            r#"{{
  "id": "req",
  "version": 1,
  "responses": [{{
    "identifier": "orb",
    "issuer_schema_id": {issuer_schema_id},
    "proof": "{proof}",
    "nullifier": "nil_00000000000000000000000000000000000000000000000000000000000003e9",
    "expires_at_min": {CREATED_AT}
  }}]
}}"#
        ))
        .unwrap()
    }

    struct State {
        valid_root: bool,
        issuer: Option<EdDSAPublicKey>,
        oprf: Option<OprfPublicKey>,
        threshold: u64,
        unavailable: bool,
    }

    impl Default for State {
        fn default() -> Self {
            Self {
                valid_root: true,
                issuer: Some(EdDSAPublicKey {
                    pk: ark_babyjubjub::EdwardsAffine::new_unchecked(1u64.into(), 2u64.into()),
                }),
                oprf: Some(OprfPublicKey::default()),
                threshold: 3600,
                unavailable: false,
            }
        }
    }

    impl State {
        fn answer<T>(&self, value: T) -> Result<T, std::io::Error> {
            if self.unavailable {
                Err(std::io::Error::other("rpc down"))
            } else {
                Ok(value)
            }
        }
    }

    impl WorldIdState for State {
        type Error = std::io::Error;

        fn is_valid_root(
            &self,
            _root: FieldElement,
            _now: u64,
        ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
            std::future::ready(self.answer(self.valid_root))
        }

        fn issuer_public_key(
            &self,
            _issuer_schema_id: u64,
        ) -> impl Future<Output = Result<Option<EdDSAPublicKey>, Self::Error>> + Send {
            std::future::ready(self.answer(self.issuer.clone()))
        }

        fn oprf_public_key(
            &self,
            _rp_id: RpId,
        ) -> impl Future<Output = Result<Option<OprfPublicKey>, Self::Error>> + Send {
            std::future::ready(self.answer(self.oprf))
        }

        fn min_expiration_threshold(
            &self,
        ) -> impl Future<Output = Result<u64, Self::Error>> + Send {
            std::future::ready(self.answer(self.threshold))
        }
    }

    async fn verify(
        response: &ProofResponse,
        state: &State,
        now: u64,
    ) -> Result<(), WorldIdProofVerificationError> {
        verify_world_id_proof_at(&uniqueness_request(), response, state, now).await
    }

    #[tokio::test]
    async fn runs_the_proof_check_once_the_state_checks_pass() {
        let result = verify(&uniqueness_response(1), &State::default(), CREATED_AT).await;
        assert!(matches!(
            result,
            Err(WorldIdProofVerificationError::Proof {
                source: NullifierProofVerificationError::ProofInvalid,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn rejects_a_failing_state_check() {
        use WorldIdProofVerificationError as Error;
        let response = uniqueness_response(1);
        let state = |change: fn(&mut State)| {
            let mut state = State::default();
            change(&mut state);
            state
        };
        assert!(matches!(
            verify(&response, &state(|s| s.valid_root = false), CREATED_AT).await,
            Err(Error::InvalidRoot(_))
        ));
        assert!(matches!(
            verify(&response, &state(|s| s.issuer = None), CREATED_AT).await,
            Err(Error::UnregisteredIssuerSchemaId(1))
        ));
        assert!(matches!(
            verify(&response, &state(|s| s.oprf = None), CREATED_AT).await,
            Err(Error::UnknownOprfKey(_))
        ));
        assert!(matches!(
            verify(&response, &state(|s| s.unavailable = true), CREATED_AT).await,
            Err(Error::State(_))
        ));
        assert!(matches!(
            verify(&response, &state(|s| s.threshold = 0), CREATED_AT + 1).await,
            Err(Error::ExpirationTooOld(_))
        ));
        assert!(matches!(
            verify(&response, &state(|s| s.threshold = u64::MAX), CREATED_AT).await,
            Err(Error::ExpirationTooOld(_))
        ));
        // `issuerSchemaIdToPubkey` answers an unregistered schema with a zero key.
        assert!(matches!(
            verify(
                &response,
                &state(|s| s.issuer = Some(EdDSAPublicKey {
                    pk: ark_babyjubjub::EdwardsAffine::default(),
                })),
                CREATED_AT
            )
            .await,
            Err(Error::UnregisteredIssuerSchemaId(1))
        ));
    }

    #[tokio::test]
    async fn rejects_expired_requests_and_other_schemas() {
        use WorldIdProofVerificationError as Error;
        assert!(matches!(
            verify(&uniqueness_response(1), &State::default(), CREATED_AT + 301).await,
            Err(Error::RequestExpired { .. })
        ));
        assert!(matches!(
            verify(&uniqueness_response(2), &State::default(), CREATED_AT).await,
            Err(Error::IssuerSchemaMismatch {
                expected: 1,
                got: 2,
                ..
            })
        ));
    }

    #[test]
    fn binds_the_session_the_request_asks_for() {
        let mut response = uniqueness_response(1);
        assert_eq!(
            session_id_input(&uniqueness_request(), &response).unwrap(),
            FieldElement::ZERO
        );

        let create = request(
            r#""session_id": "create", "action": "0x000000000000000000000000000000000000000000000000000000000000002a""#,
        );
        assert!(matches!(
            session_id_input(&create, &response),
            Err(WorldIdProofVerificationError::Response(
                ValidationError::MissingSessionId
            ))
        ));
        let commitment = FieldElement::from(5u64);
        response.session_id = Some(SessionId {
            commitment,
            oprf_seed: FieldElement::from(6u64),
        });
        assert_eq!(session_id_input(&create, &response).unwrap(), commitment);
        response.session_id = Some(SessionId {
            commitment: FieldElement::ZERO,
            oprf_seed: FieldElement::from(6u64),
        });
        assert!(matches!(
            session_id_input(&create, &response),
            Err(WorldIdProofVerificationError::ZeroSessionId)
        ));
    }
}
