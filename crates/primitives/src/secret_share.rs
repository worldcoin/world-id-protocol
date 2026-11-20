//! The secret-shared OPRF blinding secret `s`: registry leaf, query digest and share fetches.
//!
//! Each World ID holds a random secret `s`, Shamir-shared across the OPRF nodes and committed
//! write-once in its registry leaf. Folding `s` into the OPRF query digest makes every OPRF output
//! depend on it, so recovering an OPRF key alone does not let anyone recompute a user's outputs.
//!
//! An authenticator fetches its shares once (new device or recovery). Two ways to authorize a
//! fetch exist: an XMSS proof (`share-fetch-xmss` circuit), whose security rests only on hashes,
//! and [`ShareFetchRequest`], an `EdDSA` signature the nodes check natively, which reuses the
//! current authenticator keys but is not post-quantum.

use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSASignature};

use crate::{
    AuthenticatorPublicKeySet, FieldElement,
    poseidon::{self, ds},
};

/// Number of XMSS credential slots per World ID, one per authenticator key slot.
pub const NUM_XMSS_SLOTS: usize = 7;

/// `sCommit`, the registry's write-once commitment to `s`.
#[must_use]
pub fn secret_commitment(s: FieldElement) -> FieldElement {
    poseidon::hash(ds::SECRET_COMMITMENT, [s])
}

/// The registry leaf over the key set commitment, `sCommit` and the XMSS credential set root.
/// Accounts without XMSS credentials use `xmss_set_root = 0`.
#[must_use]
pub fn registry_leaf(
    key_set: &AuthenticatorPublicKeySet,
    s_commitment: FieldElement,
    xmss_set_root: FieldElement,
) -> FieldElement {
    poseidon::hash(
        ds::REGISTRY_LEAF,
        [key_set.leaf_hash().into(), s_commitment, xmss_set_root],
    )
}

/// Commitment to an account's XMSS credential slots; inactive slots hold `0`.
#[must_use]
pub fn xmss_set_root(commitments: [FieldElement; NUM_XMSS_SLOTS]) -> FieldElement {
    poseidon::hash(ds::XMSS_SET, commitments)
}

/// The OPRF query digest `q' = H(leaf_index, rp_id, action, s)`.
#[must_use]
pub fn oprf_query_digest(
    leaf_index: u64,
    rp_id: FieldElement,
    action: FieldElement,
    s: FieldElement,
) -> FieldElement {
    poseidon::hash(
        ds::OPRF_QUERY_V2,
        [FieldElement::from(leaf_index), rp_id, action, s],
    )
}

/// The message a share fetch authorizes, for both the XMSS proof and [`ShareFetchRequest`].
///
/// `epoch` bounds the replay window; `kem_pk_hash` binds the key the nodes encrypt the shares to,
/// so a replayed request only ever returns shares the requester can decrypt.
#[must_use]
pub fn share_fetch_message(leaf_index: u64, epoch: u64, kem_pk_hash: FieldElement) -> FieldElement {
    poseidon::hash(
        ds::SHARE_FETCH,
        [
            FieldElement::from(leaf_index),
            FieldElement::from(epoch),
            kem_pk_hash,
        ],
    )
}

/// A share fetch authorized with a registered authenticator's `EdDSA` key, checked natively by each
/// OPRF node against the key set it indexes from the registry.
///
/// Not post-quantum: the authenticator public keys are emitted on-chain, so a quantum adversary can
/// forge this signature and fetch the shares.
#[derive(Clone, Debug)]
pub struct ShareFetchRequest {
    /// The World ID whose shares are fetched.
    pub leaf_index: u64,
    /// The replay window the request is valid in.
    pub epoch: u64,
    /// Hash of the ML-KEM key the nodes encrypt the shares to.
    pub kem_pk_hash: FieldElement,
    /// Slot of the signing key in the account's key set.
    pub key_index: usize,
    /// Signature over [`share_fetch_message`].
    pub signature: EdDSASignature,
}

impl ShareFetchRequest {
    /// Signs a fetch request with the authenticator key at `key_index`.
    #[must_use]
    pub fn sign(
        signer: &EdDSAPrivateKey,
        key_index: usize,
        leaf_index: u64,
        epoch: u64,
        kem_pk_hash: FieldElement,
    ) -> Self {
        let message = share_fetch_message(leaf_index, epoch, kem_pk_hash);
        Self {
            leaf_index,
            epoch,
            kem_pk_hash,
            key_index,
            signature: signer.sign(*message),
        }
    }

    /// Whether the request is signed by the key at `key_index` of the account's `key_set`.
    ///
    /// The node must take `key_set` from the registry for `leaf_index`, and check `epoch` against
    /// its replay window itself.
    #[must_use]
    pub fn verify(&self, key_set: &AuthenticatorPublicKeySet) -> bool {
        let message = share_fetch_message(self.leaf_index, self.epoch, self.kem_pk_hash);
        key_set
            .get(self.key_index)
            .is_some_and(|key| key.verify(*message, &self.signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> (EdDSAPrivateKey, AuthenticatorPublicKeySet) {
        let sk = EdDSAPrivateKey::from_bytes([7u8; 32]);
        let key_set = AuthenticatorPublicKeySet::new(vec![sk.public()]).unwrap();
        (sk, key_set)
    }

    #[test]
    fn test_share_fetch_request_verifies_for_the_signing_key() {
        let (sk, key_set) = account();
        let request = ShareFetchRequest::sign(&sk, 0, 5, 100, FieldElement::from(9u64));
        assert!(request.verify(&key_set));
    }

    #[test]
    fn test_share_fetch_request_rejects_altered_fields() {
        let (sk, key_set) = account();
        let request = ShareFetchRequest::sign(&sk, 0, 5, 100, FieldElement::from(9u64));

        let mut other_leaf = request.clone();
        other_leaf.leaf_index = 6;
        assert!(!other_leaf.verify(&key_set));

        let mut other_epoch = request.clone();
        other_epoch.epoch = 101;
        assert!(!other_epoch.verify(&key_set));

        let mut other_kem = request.clone();
        other_kem.kem_pk_hash = FieldElement::from(10u64);
        assert!(!other_kem.verify(&key_set));

        let mut inactive_slot = request;
        inactive_slot.key_index = 1;
        assert!(!inactive_slot.verify(&key_set));
    }

    #[test]
    fn test_query_digest_depends_on_the_secret() {
        let rp_id = FieldElement::from(2u64);
        let action = FieldElement::from(3u64);
        assert_ne!(
            oprf_query_digest(1, rp_id, action, FieldElement::from(4u64)),
            oprf_query_digest(1, rp_id, action, FieldElement::from(5u64)),
        );
    }
}
