//! Domain-separated Poseidon2 hashing over a fixed number of field elements.
//!
//! Every protocol hash of this shape uses one layout, mirroring the circuits (see
//! `circom/client_side_proofs/oprf_nullifier.circom`, *"capacity element at 0, so we
//! take `[1]` below"*):
//!
//! - slot `0` is the capacity and holds the domain separator,
//! - slots `1..t` are the rate and hold the inputs, zero-padded,
//! - the digest is slot `1` of the permuted state.
//!
//! Prefer [`hash`] over calling `poseidon2::bn254::t*::permutation*` directly: it
//! selects the permutation width, places the domain separator, and squeezes the
//! right element. A [`DomainSeparator`] declares how many inputs its message takes,
//! so the width follows from the separator alone and a call site cannot silently
//! change it by passing a different number of inputs.
//!
//! Arbitrary-length byte inputs use a different construction and a separate
//! separator type: see [`VariableLengthDomainSeparator`] and
//! [`sponge::hash_bytes_to_field_element`](crate::sponge::hash_bytes_to_field_element).

use ark_babyjubjub::Fq;
use ark_ff::AdditiveGroup as _;

use crate::FieldElement;

/// The largest tag that is guaranteed to survive lowering into the field unreduced
/// (248 bits < the BN254 scalar field modulus).
const MAX_TAG_LEN_BYTES: usize = 31;

/// The domain separators of every Poseidon2 hash in the protocol.
///
/// Domain separators are part of the protocol's wire format: they are hashed into
/// the circuits, so neither a tag nor its input count may be edited in place. Add a
/// new constant instead.
pub mod ds {
    use super::{DomainSeparator, VariableLengthDomainSeparator};

    /// Separates the canonical hash of a [`CredentialVersion::V1`](crate::CredentialVersion) credential.
    pub const CREDENTIAL_V1: DomainSeparator<7> = DomainSeparator::new(b"POSEIDON2+EDDSA-BJJ");
    /// Separates the blinded subject (`sub`) of a credential.
    pub const CREDENTIAL_SUB: DomainSeparator<2> = DomainSeparator::new(b"H_CS(id, r)");
    /// Separates the commitment of a [`SessionId`](crate::SessionId).
    ///
    /// TODO: Change DS to not use the same DS as the base Query Proof
    pub const SESSION_COMMITMENT: DomainSeparator<2> = DomainSeparator::new(b"H(id, r)");
    /// Separates the registry leaf hash of an
    /// [`AuthenticatorPublicKeySet`](crate::AuthenticatorPublicKeySet): the affine
    /// coordinates of [`MAX_AUTHENTICATOR_KEYS`](crate::MAX_AUTHENTICATOR_KEYS) keys.
    pub const AUTHENTICATOR_KEY_SET: DomainSeparator<14> = DomainSeparator::new(b"World ID PK");
    /// Separates the OPRF query digest, and is the OPRF evaluation's own separator.
    pub const OPRF_QUERY: DomainSeparator<3> = DomainSeparator::new(b"World ID Query");
    /// Separates the OPRF finalization hash (the nullifier), and is the separator
    /// handed to the OPRF nodes for the nullifier module.
    pub const OPRF_PROOF: DomainSeparator<3> = DomainSeparator::new(b"World ID Proof");
    /// Separates the message an authenticator signs for an ownership proof (WIP-103).
    pub const OWNERSHIP_PROOF: DomainSeparator<3> = DomainSeparator::new(b"WIP103");
    /// Separates the digest of a trust anchor key token (WIP-106). A token carries at
    /// most 7 field-element claims and is zero-padded to that width.
    pub const TRUST_ANCHOR_KEY_TOKEN: DomainSeparator<7> =
        DomainSeparator::new(b"WORLD_ID_TAKT_V1");
    /// Separates the hash of a single raw-bytes credential claim.
    pub const CLAIMS_HASH_V1: VariableLengthDomainSeparator =
        VariableLengthDomainSeparator::new(b"CLAIMS_HASH_V1");
    /// Separates the hash of a credential's associated data.
    pub const ASSOCIATED_DATA_V1: VariableLengthDomainSeparator =
        VariableLengthDomainSeparator::new(b"ASSOCIATED_DATA_HASH_V1");
}

/// Validates a raw domain separator tag, returning it unchanged.
///
/// # Panics
/// Panics if the tag is empty, longer than [`MAX_TAG_LEN_BYTES`] or starts with a zero byte,
/// which would be reduced modulo the field and could therefore alias a different tag. In a `const`
/// context — the intended usage — this is a compile-time error.
const fn checked_tag(tag: &'static [u8]) -> &'static [u8] {
    assert!(
        !tag.is_empty() && tag.len() <= MAX_TAG_LEN_BYTES && tag[0] != 0,
        "a domain separator must be between 1 and 31 bytes, and not start with a zero byte"
    );
    tag
}

/// A domain separator for a message of exactly `N` field elements, lowered into a
/// single field element when hashed.
///
/// `N` is what [`hash`] dispatches the permutation width on, so it is as much a part
/// of the hash's definition as the tag itself. Passing a different number of inputs
/// than the separator declares does not compile.
///
/// Construct these as `const` items in [`ds`] so that the tag invariant is checked at
/// compile time. `N` must be between 1 and 15; any other value fails the build at the
/// [`hash`] call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DomainSeparator<const N: usize>(&'static [u8]);

impl<const N: usize> DomainSeparator<N> {
    /// Referencing this from [`hash`] turns an unsupported input count into a
    /// build failure (a post-monomorphization const error, so it surfaces on
    /// `cargo build`/`test` rather than `cargo check`), which keeps the width
    /// dispatch total.
    const ARITY_SUPPORTED: () = assert!(
        N >= 1 && N <= 15,
        "a domain-separated Poseidon2 hash takes between 1 and 15 inputs"
    );

    /// Defines a domain separator from its raw tag.
    ///
    /// # Panics
    /// Panics if the tag is empty or longer than 31 bytes; in a `const` context —
    /// the intended usage — this is a compile-time error.
    #[must_use]
    pub const fn new(tag: &'static [u8]) -> Self {
        Self(checked_tag(tag))
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

/// A domain separator for a message of arbitrary length, used by the SAFE-style byte
/// sponge in [`crate::sponge`].
///
/// That construction absorbs the input length into its tag, so it needs no
/// compile-time input count — and it is deliberately not interchangeable with
/// [`DomainSeparator`], whose layout it does not share.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VariableLengthDomainSeparator(&'static [u8]);

impl VariableLengthDomainSeparator {
    /// Defines a domain separator from its raw tag.
    ///
    /// # Panics
    /// Panics if the tag is empty or longer than 31 bytes; in a `const` context —
    /// the intended usage — this is a compile-time error.
    #[must_use]
    pub const fn new(tag: &'static [u8]) -> Self {
        Self(checked_tag(tag))
    }

    /// Returns the raw tag, which the sponge binds into its SAFE tag.
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        self.0
    }
}

/// Hashes the `N` field elements of a message under its domain separator.
///
/// The permutation width is the smallest supported width larger than `N` (so
/// `N + 1` rounded up to one of `2, 3, 4, 8, 12, 16`); unused rate slots are zero.
/// Since `N` comes from the separator, the width is fixed by the message's
/// definition and cannot vary with runtime data.
///
/// Hashing a variable number of inputs at a *pinned* width — where padding is
/// load-bearing — is expressed by zero-filling an array of the separator's `N`, as
/// `TrustAnchorKeyToken::message_hash` does.
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
pub fn hash<const N: usize>(ds: DomainSeparator<N>, inputs: [FieldElement; N]) -> FieldElement {
    let () = DomainSeparator::<N>::ARITY_SUPPORTED;

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

    use super::{DomainSeparator, FieldElement, Fq, MAX_TAG_LEN_BYTES, ds, hash};

    const TEST_TAG: &[u8] = b"TEST_DS";
    const TEST_DS: DomainSeparator<2> = DomainSeparator::new(TEST_TAG);

    /// The raw tag of every constant in [`ds`], across both separator types, to keep
    /// the collision and length checks exhaustive.
    const ALL_TAGS: [&[u8]; 10] = [
        ds::CREDENTIAL_V1.as_bytes(),
        ds::CREDENTIAL_SUB.as_bytes(),
        ds::SESSION_COMMITMENT.as_bytes(),
        ds::AUTHENTICATOR_KEY_SET.as_bytes(),
        ds::OPRF_QUERY.as_bytes(),
        ds::OPRF_PROOF.as_bytes(),
        ds::OWNERSHIP_PROOF.as_bytes(),
        ds::TRUST_ANCHOR_KEY_TOKEN.as_bytes(),
        ds::CLAIMS_HASH_V1.as_bytes(),
        ds::ASSOCIATED_DATA_V1.as_bytes(),
    ];

    #[test]
    fn domain_separators_are_distinct_and_unreduced() {
        let mut seen = HashSet::new();
        for tag in ALL_TAGS {
            assert!(!tag.is_empty() && tag.len() <= MAX_TAG_LEN_BYTES);
            assert!(
                seen.insert(FieldElement::from_be_bytes_mod_order(tag)),
                "duplicate domain separator: {tag:?}"
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
        let ds_element = *FieldElement::from_be_bytes_mod_order(TEST_TAG);

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
                    DomainSeparator::<$n>::new(TEST_TAG),
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
