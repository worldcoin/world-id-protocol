use crate::{config::AppState, error::IndexerErrorResponse};
use alloy::primitives::U256;
use axum::{Json, extract::State};
use http::StatusCode;
use semaphore_rs_trees::{Branch, proof::InclusionProof};
use world_id_core::api_types::{AccountInclusionProof, IndexerErrorCode, IndexerQueryRequest};
use world_id_primitives::{
    FieldElement, TREE_DEPTH,
    authenticator::{SparseAuthenticatorPubkeysError, decode_sparse_authenticator_pubkeys},
    merkle::MerkleInclusionProof,
};

use crate::tree::PoseidonHasher;

/// OpenAPI schema representation of the `AccountInclusionProof` response.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct AccountInclusionProofSchema {
    /// The root hash of the Merkle tree (hex string)
    #[schema(value_type = String, format = "hex", example = "0x1a2b3c4d5e6f7890")]
    root: String,
    /// The World ID's leaf position in the Merkle tree
    #[schema(value_type = String, format = "hex", example = "0x2a")]
    leaf_index: String,
    /// The sibling path up to the Merkle root (array of hex strings)
    #[schema(value_type = Vec<String>, format = "hex")]
    siblings: Vec<String>,
    /// The compressed authenticator public keys for the account.
    ///
    /// Entries are optional to preserve sparse slot positions (`null` for removed authenticators).
    #[schema(value_type = Vec<Option<String>>, format = "hex")]
    authenticator_pubkeys: Vec<Option<String>>,
}

/// Get Inclusion Proof
///
/// Returns a Merkle inclusion proof for the given leaf index to the current `WorldIDRegistry` tree. In
/// addition, it also includes the entire authenticator slot list for the World ID account.
/// Removed authenticators are represented as `null` entries to preserve `pubkey_id` positions.
#[utoipa::path(
    post,
    path = "/inclusion-proof",
    request_body = IndexerQueryRequest,
    responses(
        (status = 200, body = AccountInclusionProofSchema, description = "Merkle inclusion proof with authenticator public keys"),
    ),
    tag = "indexer"
)]
pub(crate) async fn handler(
    State(state): State<AppState>,
    Json(req): Json<IndexerQueryRequest>,
) -> Result<Json<AccountInclusionProof<TREE_DEPTH>>, IndexerErrorResponse> {
    let leaf_index = req.leaf_index;

    if leaf_index == 0 {
        return Err(IndexerErrorResponse::bad_request(
            IndexerErrorCode::InvalidLeafIndex,
            "Leaf index cannot be 0.".to_string(),
        ));
    }

    let (offchain_signer_commitment, pubkeys) = state
        .db
        .accounts()
        .get_offchain_signer_commitment_and_authenticator_pubkeys_by_leaf_index(leaf_index)
        .await
        .map_err(|_err| IndexerErrorResponse::internal_server_error())?
        .ok_or(IndexerErrorResponse::not_found())?;

    let authenticator_pubkeys = decode_sparse_authenticator_pubkeys(pubkeys).map_err(|e| {
        match e {
            SparseAuthenticatorPubkeysError::SlotOutOfBounds {
                slot_index,
                max_supported_slot,
            } => tracing::error!(
                leaf_index = %leaf_index,
                "Invalid authenticator slot index returned from DB: {slot_index} (max {max_supported_slot})"
            ),
            SparseAuthenticatorPubkeysError::InvalidCompressedPubkey { slot_index, reason } => {
                tracing::error!(
                    leaf_index = %leaf_index,
                    "Invalid public key stored for account at slot {slot_index}: {reason}"
                );
            }
        }
        IndexerErrorResponse::internal_server_error()
    })?;

    let index_as_usize = leaf_index as usize;
    let capacity = state.tree_state.capacity();
    if index_as_usize >= capacity {
        return Err(IndexerErrorResponse::bad_request(
            IndexerErrorCode::InvalidLeafIndex,
            "Leaf index out of range.".to_string(),
        ));
    }

    let (leaf, proof, root) = state.tree_state.leaf_proof_and_root(index_as_usize).await;

    if leaf == U256::ZERO {
        return Err(IndexerErrorResponse::new(
            IndexerErrorCode::Locked,
            "Insertion is still pending.".to_string(),
            StatusCode::LOCKED,
        ));
    }

    if leaf != offchain_signer_commitment {
        tracing::error!(
            leaf_index = %leaf_index,
            leaf_hash = %leaf,
            offchain_signer_commitment = %offchain_signer_commitment,
           "Tree is out of sync with DB. Leaf hash does not match offchain signer commitment.",
        );
        return Err(IndexerErrorResponse::internal_server_error());
    }

    // Convert proof siblings to FieldElement array
    let siblings_vec: Vec<FieldElement> = proof_to_vec(&proof)
        .into_iter()
        .map(|u| u.try_into().unwrap())
        .collect();

    // Pad the siblings array to TREE_DEPTH (the compile-time constant used in the type system)
    // This is needed because the actual tree may have a smaller depth (e.g., 6 in tests)
    // but the response type uses the hardcoded TREE_DEPTH constant (30)
    let mut siblings = [FieldElement::default(); TREE_DEPTH];
    for (i, sibling) in siblings_vec.into_iter().enumerate() {
        if i < TREE_DEPTH {
            siblings[i] = sibling;
        }
    }

    let merkle_proof = MerkleInclusionProof::new(root.try_into().unwrap(), leaf_index, siblings);

    let resp = AccountInclusionProof::new(merkle_proof, authenticator_pubkeys)
        .expect("authenticator_pubkeys already validated");
    Ok(Json(resp))
}

fn proof_to_vec(proof: &InclusionProof<PoseidonHasher>) -> Vec<U256> {
    proof
        .0
        .iter()
        .map(|b| match b {
            Branch::Left(sib) => *sib,
            Branch::Right(sib) => *sib,
        })
        .collect()
}
