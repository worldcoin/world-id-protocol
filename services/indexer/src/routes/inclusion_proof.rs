use alloy::primitives::U256;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use sqlx::{PgPool, Row};
use world_id_core::types::AccountInclusionProof;
use world_id_primitives::{
    authenticator::MAX_AUTHENTICATOR_KEYS, merkle::MerkleInclusionProof, FieldElement, TREE_DEPTH,
};

use crate::{proof_to_vec, tree_capacity, GLOBAL_TREE};

pub(crate) async fn handler(
    Path(idx_str): Path<String>,
    State(pool): State<PgPool>,
) -> impl axum::response::IntoResponse {
    let account_index: U256 = idx_str.parse().unwrap();
    if account_index == 0 {
        return (axum::http::StatusCode::BAD_REQUEST, "invalid account index").into_response();
    }

    let account_row = sqlx::query(
        "select offchain_signer_commitment, authenticator_pubkeys from accounts where account_index = $1",
    )
    .bind(account_index.to_string())
    .fetch_optional(&pool)
    .await
    .ok()
    .flatten();

    if account_row.is_none() {
        return (axum::http::StatusCode::NOT_FOUND, "account not found").into_response();
    }

    let row = account_row.unwrap();
    let pubkeys_json: sqlx::types::Json<Vec<String>> = row.get("authenticator_pubkeys");
    let authenticator_pubkeys: Vec<U256> = pubkeys_json
        .0
        .iter()
        .filter_map(|s| s.parse::<U256>().ok())
        .collect();
    let offchain_signer_commitment: U256 = row
        .get::<String, _>("offchain_signer_commitment")
        .parse()
        .unwrap(); // TODO: error handling

    let leaf_index = account_index.as_limbs()[0] as usize - 1;
    if leaf_index >= tree_capacity() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "leaf index out of range",
        )
            .into_response();
    }
    // Validate the number of authenticator keys
    if authenticator_pubkeys.len() > MAX_AUTHENTICATOR_KEYS {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Account has {} authenticator keys, which exceeds the maximum of {}",
                authenticator_pubkeys.len(),
                MAX_AUTHENTICATOR_KEYS
            ),
        )
            .into_response();
    }

    let tree = GLOBAL_TREE.read().await;
    let leaf = tree.get_leaf(leaf_index);

    if leaf == U256::ZERO {
        return (axum::http::StatusCode::LOCKED, "insertion pending").into_response();
    }

    if leaf != offchain_signer_commitment {
        // TODO: log more details
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "tree out of sync with DB",
        )
            .into_response();
    }

    let proof = tree.proof(leaf_index);

    // Convert proof siblings to FieldElement array
    let siblings_vec: Vec<FieldElement> = proof_to_vec(&proof)
        .into_iter()
        .map(|u| u.try_into().unwrap())
        .collect();
    let siblings: [FieldElement; TREE_DEPTH] = siblings_vec.try_into().unwrap();

    let merkle_proof = MerkleInclusionProof::new(
        tree.root().try_into().unwrap(),
        leaf_index as u64,
        account_index.as_limbs()[0],
        siblings,
    );

    let resp = AccountInclusionProof::new(merkle_proof, authenticator_pubkeys)
        .expect("authenticator_pubkeys already validated");
    (axum::http::StatusCode::OK, axum::Json(resp)).into_response()
}
