//! OPRF query proof (π1) over a query digest that includes the World ID's secret-shared
//! blinding secret `s`, so every OPRF output depends on `s`.
use babyjubjub::BabyJubJubPoint;
use bjj_fast::blinded_query;
use world_id_components::{
    authentication, merkle::key_set_commitment, secret_share, types::AccountInputs,
};

pub struct QueryInputs {
    pub account: AccountInputs,
    /// The blinding secret, committed in the registry leaf.
    pub s: Field,
    /// `0` for accounts without XMSS credentials.
    pub xmss_set_root: Field,
    /// OPRF blinding factor.
    pub beta: Field,
}

/// Returns the blinded query point sent to the OPRF nodes.
fn main(
    merkle_root: pub Field,
    rp_id: pub Field,
    action: pub Field,
    // Binds the proof to the OPRF request.
    nonce: pub Field,
    inputs: QueryInputs,
) -> pub [Field; 2] {
    assert(nonce != 0, "nonce must not be zero");
    let blinded = query_point(merkle_root, rp_id, action, inputs);
    [blinded.x(), blinded.y()]
}

pub fn query_point(
    merkle_root: Field,
    rp_id: Field,
    action: Field,
    inputs: QueryInputs,
) -> BabyJubJubPoint {
    let query = authorized_query(merkle_root, rp_id, action, inputs);
    blinded_query(inputs.beta, query)
}

/// The query digest, after proving that a registered key of the World ID signed it and that `s`
/// is the secret committed in the World ID's leaf.
pub fn authorized_query(
    merkle_root: Field,
    rp_id: Field,
    action: Field,
    inputs: QueryInputs,
) -> Field {
    let query = secret_share::query(inputs.account.leaf_index, rp_id, action, inputs.s);
    let leaf = secret_share::registry_leaf(
        key_set_commitment(inputs.account.user_pk),
        secret_share::secret_commitment(inputs.s),
        inputs.xmss_set_root,
    );
    let _ = authentication::verify_with_leaf(merkle_root, leaf, query, inputs.account);
    query
}
