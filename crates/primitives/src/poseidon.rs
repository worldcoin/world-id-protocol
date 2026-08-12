//! Domain-separated Poseidon2 hashing over a fixed number of field elements.
//!
//! Every protocol hash of this shape uses one layout, mirroring the circuits (see
//! `circom/client_side_proofs/oprf_nullifier.circom`, *"capacity element at 0, so we
//! take [1] below"*):
//!
//! - slot `0` is the capacity and holds the domain separator,
//! - slots `1..t` are the rate and hold the inputs, zero-padded,
//! - the digest is slot `1` of the permuted state.
//!
//! Prefer [`hash`] over calling `poseidon2::bn254::t*::permutation*` directly: it
//! selects the permutation width, places the domain separator, and squeezes the
//! right element. Arbitrary-length byte inputs are hashed with
//! [`sponge::hash_bytes_to_field_element`](crate::sponge::hash_bytes_to_field_element)
//! instead, which uses the same [`DomainSeparator`] type but a different layout.

use ark_babyjubjub::Fq;
use ark_ff::AdditiveGroup as _;

use crate::FieldElement;

/// The domain separators of every Poseidon2 hash in the protocol.
///
/// Domain separators are part of the protocol's wire format: they are hashed into
/// the circuits, so a tag may never be edited in place. Add a new constant instead.
pub mod ds {
    use super::DomainSeparator;

    /// Separates the canonical hash of a [`CredentialVersion::V1`](crate::CredentialVersion) credential.
    pub const CREDENTIAL_V1: DomainSeparator = DomainSeparator::new(b"POSEIDON2+EDDSA-BJJ");
    /// Separates the blinded subject (`sub`) of a credential.
    pub const CREDENTIAL_SUB: DomainSeparator = DomainSeparator::new(b"H_CS(id, r)");
    /// Separates the commitment of a [`SessionId`](crate::SessionId).
    ///
    /// TODO: Change DS to not use the same DS as the base Query Proof
    pub const SESSION_COMMITMENT: DomainSeparator = DomainSeparator::new(b"H(id, r)");
    /// Separates the registry leaf hash of an
    /// [`AuthenticatorPublicKeySet`](crate::AuthenticatorPublicKeySet).
    pub const AUTHENTICATOR_KEY_SET: DomainSeparator = DomainSeparator::new(b"World ID PK");
    /// Separates the OPRF query digest, and is the OPRF evaluation's own separator.
    pub const OPRF_QUERY: DomainSeparator = DomainSeparator::new(b"World ID Query");
    /// Separates the OPRF finalization hash (the nullifier), and is the separator
    /// handed to the OPRF nodes for the nullifier module.
    pub const OPRF_PROOF: DomainSeparator = DomainSeparator::new(b"World ID Proof");
    /// Separates the message an authenticator signs for an ownership proof (WIP-103).
    pub const OWNERSHIP_PROOF: DomainSeparator = DomainSeparator::new(b"WIP103");
    /// Separates the digest of a trust anchor key token (WIP-106).
    pub const TRUST_ANCHOR_KEY_TOKEN: DomainSeparator = DomainSeparator::new(b"WORLD_ID_TAKT_V1");
    /// Separates the hash of a single raw-bytes credential claim.
    pub const CLAIMS_HASH_V1: DomainSeparator = DomainSeparator::new(b"CLAIMS_HASH_V1");
    /// Separates the hash of a credential's associated data.
    pub const ASSOCIATED_DATA_V1: DomainSeparator =
        DomainSeparator::new(b"ASSOCIATED_DATA_HASH_V1");
}

/// A domain separator, lowered into a single field element when hashed.
///
/// Construct these as `const` items in [`ds`] so that the length invariant is
/// checked at compile time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DomainSeparator(&'static [u8]);

impl DomainSeparator {
    /// The largest tag that is guaranteed to survive lowering into the field
    /// unreduced (248 bits < the BN254 scalar field modulus).
    const MAX_LEN_BYTES: usize = 31;

    /// Defines a domain separator from its raw tag.
    ///
    /// # Panics
    /// Panics if the tag is empty or longer than 31 bytes, which would be reduced
    /// modulo the field and could therefore alias a different tag. In a `const`
    /// context — the intended usage — this is a compile-time error.
    #[must_use]
    pub const fn new(tag: &'static [u8]) -> Self {
        assert!(
            !tag.is_empty() && tag.len() <= Self::MAX_LEN_BYTES,
            "a domain separator must be between 1 and 31 bytes"
        );
        Self(tag)
    }

    /// Returns the raw tag.
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        self.0
    }

    /// Lowers the tag into a field element, as placed in the capacity slot.
    #[must_use]
    pub fn as_field_element(self) -> FieldElement {
        FieldElement::from_be_bytes_mod_order(self.0)
    }
}

/// Compile-time guard on the input count accepted by [`hash`].
struct Arity<const N: usize>;

impl<const N: usize> Arity<N> {
    /// Referencing this from [`hash`] turns an unsupported arity into a compile error.
    const CHECK: () = assert!(
        N >= 1 && N <= 15,
        "a domain-separated Poseidon2 hash takes between 1 and 15 inputs"
    );
}

/// Hashes a fixed number of field elements under a domain separator.
///
/// The permutation width is the smallest supported width larger than `N` (so
/// `N + 1` rounded up to one of `2, 3, 4, 8, 12, 16`); unused rate slots are zero.
/// The input count is fixed per call site by the array's length, so the width
/// cannot vary with runtime data.
///
/// Inputs longer than 15 elements, or empty, are a compile error. Hashing a
/// variable number of inputs at a *pinned* width — where padding is load-bearing —
/// is not expressible here and must keep building the state explicitly.
///
/// ```
/// use world_id_primitives::{FieldElement, poseidon::{self, ds}};
///
/// let sub = poseidon::hash(
///     ds::CREDENTIAL_SUB,
///     [FieldElement::from(7u64), FieldElement::from(42u64)],
/// );
/// assert_ne!(sub, FieldElement::ZERO);
/// ```
#[must_use]
pub fn hash<const N: usize>(ds: DomainSeparator, inputs: [FieldElement; N]) -> FieldElement {
    let () = Arity::<N>::CHECK;

    let ds = *ds.as_field_element();
    match N {
        1 => hash_padded(ds, &inputs, poseidon2::bn254::t2::permutation_in_place),
        2 => hash_padded(ds, &inputs, poseidon2::bn254::t3::permutation_in_place),
        3 => hash_padded(ds, &inputs, poseidon2::bn254::t4::permutation_in_place),
        4..=7 => hash_padded(ds, &inputs, poseidon2::bn254::t8::permutation_in_place),
        8..=11 => hash_padded(ds, &inputs, poseidon2::bn254::t12::permutation_in_place),
        _ => hash_padded(ds, &inputs, poseidon2::bn254::t16::permutation_in_place),
    }
}

/// Compresses a pair of field elements with the Poseidon2 `t2` permutation in
/// **compression mode**: `left` is fed forward into the permuted state.
///
/// This is the node hash of the protocol's Merkle trees, matching
/// `circom/merkle_tree/binary_merkle_root.circom`, which uses Poseidon2 in
/// compression rather than sponge mode.
///
/// Unlike [`hash`], this has **no domain separator** and no capacity slot: the
/// argument order is all that distinguishes a node from its mirror, so callers must
/// pass the children in tree order.
#[must_use]
pub fn compress(left: FieldElement, right: FieldElement) -> FieldElement {
    let mut state = poseidon2::bn254::t2::permutation(&[*left, *right]);
    state[0] += *left;
    state[0].into()
}

/// Runs the protocol's sponge layout at width `T`: domain separator in the capacity
/// slot, inputs in the rate, digest squeezed from slot 1.
fn hash_padded<const T: usize>(
    ds: Fq,
    inputs: &[FieldElement],
    permute: fn(&mut [Fq; T]),
) -> FieldElement {
    debug_assert!(inputs.len() < T, "inputs do not fit the rate");

    let mut state = [Fq::ZERO; T];
    state[0] = ds;
    for (slot, input) in state[1..].iter_mut().zip(inputs) {
        *slot = **input;
    }
    permute(&mut state);
    state[1].into()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use ark_ff::AdditiveGroup as _;

    use super::{DomainSeparator, FieldElement, Fq, ds, hash};

    const TEST_DS: DomainSeparator = DomainSeparator::new(b"TEST_DS");

    /// Every constant in [`ds`], to keep the collision and length checks exhaustive.
    const ALL_DS: [DomainSeparator; 10] = [
        ds::CREDENTIAL_V1,
        ds::CREDENTIAL_SUB,
        ds::SESSION_COMMITMENT,
        ds::AUTHENTICATOR_KEY_SET,
        ds::OPRF_QUERY,
        ds::OPRF_PROOF,
        ds::OWNERSHIP_PROOF,
        ds::TRUST_ANCHOR_KEY_TOKEN,
        ds::CLAIMS_HASH_V1,
        ds::ASSOCIATED_DATA_V1,
    ];

    #[test]
    fn domain_separators_are_distinct_and_unreduced() {
        let mut seen = HashSet::new();
        for separator in ALL_DS {
            assert!(
                !separator.as_bytes().is_empty()
                    && separator.as_bytes().len() <= DomainSeparator::MAX_LEN_BYTES
            );
            assert!(
                seen.insert(separator.as_field_element()),
                "duplicate domain separator: {:?}",
                separator.as_bytes()
            );
        }
    }

    /// The lowered tags are a cross-language contract with the circuits, which
    /// hardcode them as decimal literals.
    #[test]
    fn domain_separators_match_circuit_literals() {
        assert_eq!(
            ds::OPRF_QUERY.as_field_element(),
            FieldElement::from(1_773_399_373_884_719_043_551_600_379_785_849_u128),
            "see oprf_nullifier.circom / oprf_query.circom"
        );
        assert_eq!(
            ds::AUTHENTICATOR_KEY_SET.as_field_element(),
            FieldElement::from(105_702_839_725_298_824_521_994_315_u128),
        );
    }

    #[test]
    fn hash_matches_hand_rolled_layout() {
        let inputs: [FieldElement; 15] = std::array::from_fn(|i| FieldElement::from(i as u64 + 1));
        let ds_element = *TEST_DS.as_field_element();

        macro_rules! assert_width {
            ($n:literal, $t:literal, $module:ident) => {{
                let mut state = [Fq::ZERO; $t];
                state[0] = ds_element;
                for (slot, input) in state[1..].iter_mut().zip(&inputs[..$n]) {
                    *slot = **input;
                }
                poseidon2::bn254::$module::permutation_in_place(&mut state);

                let expected = FieldElement::from(state[1]);
                let actual = hash(
                    TEST_DS,
                    <[FieldElement; $n]>::try_from(&inputs[..$n]).unwrap(),
                );
                assert_eq!(actual, expected, "width {} mismatch", $t);
            }};
        }

        // Widths currently in use by the protocol.
        assert_width!(2, 3, t3);
        assert_width!(3, 4, t4);
        assert_width!(7, 8, t8);
        assert_width!(14, 16, t16);
        // Remaining widths and the zero-padded arities within each.
        assert_width!(1, 2, t2);
        assert_width!(4, 8, t8);
        assert_width!(6, 8, t8);
        assert_width!(8, 12, t12);
        assert_width!(11, 12, t12);
        assert_width!(12, 16, t16);
        assert_width!(15, 16, t16);
    }

    #[test]
    fn hash_separates_domains_arities_and_inputs() {
        let a = FieldElement::from(1u64);
        let b = FieldElement::from(2u64);

        let base = hash(TEST_DS, [a, b]);
        assert_ne!(base, FieldElement::ZERO);
        assert_eq!(base, hash(TEST_DS, [a, b]));

        assert_ne!(base, hash(ds::CREDENTIAL_SUB, [a, b]));
        assert_ne!(base, hash(TEST_DS, [b, a]));
    }
}
