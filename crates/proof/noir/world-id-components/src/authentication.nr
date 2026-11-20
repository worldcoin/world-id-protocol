// World ID Authentication (WIP-100 §6.1).
use super::{constants::NUM_KEYS, merkle, types::AccountInputs};

/// Proves that a registered Authenticator key of the World ID at `account.leaf_index`
/// signed `message`, and returns that `leaf_index`.
///
/// The caller computes `message` under its own domain separator.
pub fn verify(merkle_root: Field, message: Field, account: AccountInputs) -> Field {
    verify_with_leaf(
        merkle_root,
        merkle::key_set_commitment(account.user_pk),
        message,
        account,
    )
}

/// [`verify`] against a registry `leaf` the caller derived from `account.user_pk`, for leaf
/// layouts that commit to more than the key set.
pub fn verify_with_leaf(
    merkle_root: Field,
    leaf: Field,
    message: Field,
    account: AccountInputs,
) -> Field {
    // Select the key.
    account.pk_index.assert_max_bit_size::<3>();
    assert((account.pk_index as u8) < NUM_KEYS as u8, "pk_index out of range");
    let pk = account.user_pk[account.pk_index as u32];

    // Prove registration of the leaf.
    assert(
        merkle::compute_merkle_root(leaf, account.leaf_index, account.siblings) == merkle_root,
        "merkle proof verification failed",
    );

    // Inactive slots are the identity, which signature verification rejects.
    assert(account.sig.verify(pk, message), "invalid authorization signature");
    account.leaf_index
}
