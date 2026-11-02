use crate::{
    config::AppState,
    error::{IndexerErrorBody, IndexerErrorResponse},
};
use alloy::{
    primitives::U256,
    providers::DynProvider,
    sol_types::{Panic, PanicKind},
};
use axum::{Json, extract::State};
use world_id_primitives::api_types::{
    IndexerErrorCode, IndexerVerifyInputs, IndexerVerifyRequest, IndexerVerifyResponse,
};
use world_id_registries::world_id_verifier::{
    DeletedId, InvalidSessionId, ProofInvalid, PublicInputNotInField, UnknownId,
    WorldIdVerifier::{self, WorldIdVerifierInstance},
};

/// Verify one World ID proof against explicit public inputs using the configured verifier.
///
/// RPs must match these inputs to their expected request and enforce nonce consumption
/// and nullifier uniqueness themselves. This endpoint does not consume proofs.
#[utoipa::path(
    post,
    path = "/verify",
    request_body = IndexerVerifyRequest,
    responses(
        (status = 200, body = IndexerVerifyResponse),
        (status = 400, description = "Proof or public inputs rejected", body = IndexerErrorBody),
        (status = 500, description = "Verification unavailable", body = IndexerErrorBody),
        (status = 504, description = "Verification timed out", body = IndexerErrorBody),
    ),
    tag = "indexer"
)]
pub(crate) async fn handler(
    State(state): State<AppState>,
    Json(req): Json<IndexerVerifyRequest>,
) -> Result<Json<IndexerVerifyResponse>, IndexerErrorResponse> {
    verify(&state.verifier, req).await
}

async fn verify(
    verifier: &WorldIdVerifierInstance<DynProvider>,
    req: IndexerVerifyRequest,
) -> Result<Json<IndexerVerifyResponse>, IndexerErrorResponse> {
    let proof = req.proof.as_ethereum_representation();
    let result = match req.verification {
        IndexerVerifyInputs::Uniqueness { nullifier, action } => verifier
            .verify(
                nullifier,
                action,
                req.rp_id,
                req.nonce,
                req.signal_hash,
                req.expires_at_min,
                req.issuer_schema_id,
                req.credential_genesis_issued_at_min,
                proof,
            )
            .call()
            .await
            .map(|_| ()),
        IndexerVerifyInputs::Session {
            session_id,
            session_nullifier,
        } => verifier
            .verifySession(
                req.rp_id,
                req.nonce,
                req.signal_hash,
                req.expires_at_min,
                req.issuer_schema_id,
                req.credential_genesis_issued_at_min,
                session_id,
                session_nullifier.as_ethereum_representation(),
                proof,
            )
            .call()
            .await
            .map(|_| ()),
    };

    if let Err(error) = result {
        // Confirm this specific input overflow before classifying a Solidity panic as 400.
        // Other panics remain server errors. The extra read is only needed on this error path.
        if error
            .as_decoded_error::<Panic>()
            .is_some_and(|panic| panic.code == U256::from(PanicKind::UnderOverflow as u32))
        {
            let threshold = verifier
                .getMinExpirationThreshold()
                .call()
                .await
                .map_err(verification_error)?;
            if threshold > U256::from(u64::MAX - req.expires_at_min) {
                return Err(IndexerErrorResponse::bad_request(
                    IndexerErrorCode::InvalidProof,
                    "Credential expiration lower bound overflows the verifier's threshold"
                        .to_string(),
                ));
            }
        }
        return Err(verification_error(error));
    }
    Ok(Json(IndexerVerifyResponse { valid: true }))
}

fn verification_error(error: alloy::contract::Error) -> IndexerErrorResponse {
    let reason = if error.as_decoded_error::<ProofInvalid>().is_some() {
        Some("Invalid zero-knowledge proof")
    } else if error.as_decoded_error::<PublicInputNotInField>().is_some() {
        Some("Public input is outside the circuit field")
    } else if error
        .as_decoded_error::<WorldIdVerifier::InvalidMerkleRoot>()
        .is_some()
    {
        Some("Merkle root is not valid")
    } else if error
        .as_decoded_error::<WorldIdVerifier::ExpirationTooOld>()
        .is_some()
    {
        Some("Credential expiration lower bound is too old")
    } else if error
        .as_decoded_error::<WorldIdVerifier::UnregisteredIssuerSchemaId>()
        .is_some()
    {
        Some("Issuer schema is not registered")
    } else if error
        .as_decoded_error::<WorldIdVerifier::InvalidAction>()
        .is_some()
    {
        Some("Action is not valid for this proof type")
    } else if error.as_decoded_error::<InvalidSessionId>().is_some() {
        Some("Session commitment is not valid")
    } else if error.as_decoded_error::<UnknownId>().is_some() {
        Some("RP OPRF key is not available")
    } else if error.as_decoded_error::<DeletedId>().is_some() {
        Some("RP OPRF key has been deleted")
    } else {
        None
    };

    if let Some(reason) = reason {
        IndexerErrorResponse::bad_request(IndexerErrorCode::InvalidProof, reason.to_string())
    } else {
        tracing::error!("RPC error verifying proof: {error}");
        IndexerErrorResponse::internal_server_error()
    }
}
