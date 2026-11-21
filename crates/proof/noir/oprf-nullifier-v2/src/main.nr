//! OPRF evaluation and nullifier over the `s`-dependent query digest: the OPRF core of the
//! Uniqueness Proof (π2).
// TODO: Add the Credential Verification and Session Commitment checks of the full π2 before
// using this beyond benchmarks.
use babyjubjub::{BabyJubJubPoint, BabyJubJubPointInSubgroup};
use oprf::oprf_output::verified_oprf;
use world_id_components::{
    authentication,
    constants::DS_NULLIFIER,
    merkle::key_set_commitment,
    secret_share,
    types::{AccountInputs, PublicKey},
};

/// b"DLOG Equality Proof", the separator of the OPRF nodes' Chaum-Pedersen proofs.
global DS_DLOG: Field = 1523098184080632582082867317389990410064981862;

pub struct NullifierInputs {
    pub account: AccountInputs,
    pub s: Field,
    pub xmss_set_root: Field,
    pub beta: Field,
    /// The OPRF nodes' DLog equality proof for the blinded response.
    pub dlog_e: Field,
    pub dlog_s: Field,
    /// The unblinded OPRF response, injected to avoid an in-circuit inversion of `beta`.
    pub oprf_response: [Field; 2],
}

/// Returns the nullifier `H(DS_NULLIFIER; q', oprf_response)`.
fn main(
    merkle_root: pub Field,
    rp_id: pub Field,
    action: pub Field,
    nonce: pub Field,
    oprf_pk: pub PublicKey,
    inputs: NullifierInputs,
) -> pub Field {
    assert(nonce != 0, "nonce must not be zero");
    let query = secret_share::query(inputs.account.leaf_index, rp_id, action, inputs.s);
    let leaf = secret_share::registry_leaf(
        key_set_commitment(inputs.account.user_pk),
        secret_share::secret_commitment(inputs.s),
        inputs.xmss_set_root,
    );
    let _ = authentication::verify_with_leaf(merkle_root, leaf, query, inputs.account);

    verified_oprf(
        inputs.beta,
        BabyJubJubPointInSubgroup::new(oprf_pk.x, oprf_pk.y),
        inputs.dlog_e,
        inputs.dlog_s,
        BabyJubJubPoint::new(inputs.oprf_response[0], inputs.oprf_response[1]),
        query,
        DS_DLOG,
        DS_NULLIFIER,
    )
}
