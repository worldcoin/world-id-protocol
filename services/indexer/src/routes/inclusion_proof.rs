use crate::config::AppState;
use alloy::primitives::U256;
use axum::{extract::State, Json};
use http::StatusCode;
use semaphore_rs_trees::proof::InclusionProof;
use semaphore_rs_trees::Branch;
use sqlx::Row;
use world_id_core::{
    types::{AccountInclusionProof, IndexerErrorCode, IndexerErrorResponse, IndexerQueryRequest},
    EdDSAPublicKey,
};
use world_id_primitives::{
    authenticator::AuthenticatorPublicKeySet, merkle::MerkleInclusionProof, FieldElement,
    TREE_DEPTH,
};

use crate::tree::{PoseidonHasher, GLOBAL_TREE};

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
    /// The compressed authenticator public keys for the account (array of hex strings)
    #[schema(value_type = Vec<String>, format = "hex")]
    authenticator_pubkeys: Vec<String>,
}

/// Get Inclusion Proof
///
/// Returns a Merkle inclusion proof for the given leaf index to the current `WorldIDRegistry` tree. In
/// addition, it also includes the entire list of Authenticator public keys registered for the World ID.
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

    let account_row = sqlx::query(
        "select offchain_signer_commitment, authenticator_pubkeys from accounts where leaf_index = $1",
    )
    .bind(leaf_index.to_string())
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    if account_row.is_none() {
        return Err(IndexerErrorResponse::not_found());
    }

    let row = account_row.unwrap();
    let pubkeys: sqlx::types::Json<Vec<String>> = row.get("authenticator_pubkeys");
    let pubkeys: Vec<EdDSAPublicKey> = pubkeys
        .0
        .iter()
        .filter_map(|s| {
            // TODO: store validated pubkeys
            let pubkey = s.parse::<U256>().map_err(|_| {
                tracing::error!(leaf_index = %leaf_index, "Invalid public key stored for account: {s}")
            }).ok()?;

            // Encoding matches insertion in core::authenticator::Authenticator operations
            EdDSAPublicKey::from_compressed_bytes(pubkey.to_le_bytes()).map_err(|_| {
                tracing::error!(leaf_index = %leaf_index, "Invalid public key stored for account (not affine compressed): {s}");
            }).ok()
        }).collect();

    let authenticator_pubkeys = AuthenticatorPublicKeySet::new(Some(pubkeys)).map_err(|e| {
        tracing::error!(leaf_index = %leaf_index, "Invalid public key set stored for account: {e}");
        IndexerErrorResponse::internal_server_error()
    })?;

    let offchain_signer_commitment: U256 = row
        .get::<String, _>("offchain_signer_commitment")
        .parse()
        .unwrap(); // TODO: error handling

    let tree = GLOBAL_TREE.read().await;

    let index_as_usize = leaf_index.as_limbs()[0] as usize;
    let capacity = crate::tree::tree_capacity().await;
    if index_as_usize >= capacity {
        return Err(IndexerErrorResponse::bad_request(
            IndexerErrorCode::InvalidLeafIndex,
            "Leaf index out of range.".to_string(),
        ));
    }

    let leaf = tree.get_leaf(index_as_usize);

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

    let proof = tree.proof(index_as_usize);

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

    let merkle_proof = MerkleInclusionProof::new(
        tree.root().try_into().unwrap(),
        leaf_index.as_limbs()[0],
        siblings,
    );

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
