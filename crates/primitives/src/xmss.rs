//! XMSS (WOTS+ with w = 2) over Poseidon2, the hash-based share-fetch credential.
//!
//! Matches `world_id_components::xmss` in `crates/proof/noir`. w = 2 minimizes the hashing a
//! circuit verifying the signature does; the signature stays a private witness, so its size does
//! not matter.
//!
//! XMSS is stateful: a one-time key index must never sign twice. [`XmssSecretKey::sign`] advances
//! the index, and the OPRF nodes additionally reject a repeated [`tag`].

use ark_ff::{AdditiveGroup as _, BigInteger as _, PrimeField as _};

use crate::{
    FieldElement,
    poseidon::{self, ds},
};

/// Height of an authenticator's XMSS tree: 2^10 one-time keys.
pub const XMSS_HEIGHT: usize = 10;

/// WOTS+ chains for w = 2: 254 digest bits plus an 8-bit checksum.
pub const WOTS_CHAINS: usize = WOTS_MSG_CHAINS + WOTS_CHECKSUM_CHAINS;
const WOTS_MSG_CHAINS: usize = 254;
const WOTS_CHECKSUM_CHAINS: usize = 8;

/// Separates the seed derivations of `pub_seed` and `tag_key` from the chain starts, whose second
/// input is a leaf index below `2^XMSS_HEIGHT`.
const SEED_DERIVATION_INDEX: u64 = 1 << 32;

/// An XMSS signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmssSignature {
    /// One value per WOTS+ chain.
    pub chains: Vec<FieldElement>,
    /// The one-time key index.
    pub index: u64,
    /// Sibling nodes from the one-time key's leaf upwards.
    pub auth_path: Vec<FieldElement>,
}

/// Errors from signing with an [`XmssSecretKey`].
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum XmssError {
    /// Every one-time key has signed already.
    #[error("all XMSS one-time keys are used")]
    Exhausted,
}

/// An XMSS key pair with its signing state: the index of the next unused one-time key.
pub struct XmssSecretKey {
    seed: FieldElement,
    pub_seed: FieldElement,
    tag_key: FieldElement,
    /// `levels[0]` are the leaves, the last level is the root.
    levels: Vec<Vec<FieldElement>>,
    next_index: u64,
}

impl XmssSecretKey {
    /// Generates the full key of height [`XMSS_HEIGHT`] from a secret `seed`, which must be fresh
    /// randomness: deriving it from an elliptic-curve key would make it only as strong as that key.
    #[must_use]
    pub fn generate(seed: FieldElement) -> Self {
        Self::generate_with_height(seed, XMSS_HEIGHT)
    }

    fn generate_with_height(seed: FieldElement, height: usize) -> Self {
        let pub_seed = h3(
            ds::XMSS_SECRET,
            seed,
            FieldElement::from(SEED_DERIVATION_INDEX),
            FieldElement::ZERO,
        );
        let tag_key = h3(
            ds::XMSS_SECRET,
            seed,
            FieldElement::from(SEED_DERIVATION_INDEX),
            FieldElement::from(1u64),
        );

        let leaves: Vec<FieldElement> = (0..1u64 << height)
            .map(|index| {
                let ends: Vec<FieldElement> = (0..WOTS_CHAINS)
                    .map(|chain| chain_step(pub_seed, chain, chain_start(seed, index, chain)))
                    .collect();
                compress_public_key(&ends, pub_seed)
            })
            .collect();
        let mut levels = vec![leaves];
        for level in 0..height {
            let below = &levels[level];
            let above = below
                .as_chunks::<2>()
                .0
                .iter()
                .map(|[left, right]| node(*left, *right, pub_seed, level))
                .collect();
            levels.push(above);
        }

        Self {
            seed,
            pub_seed,
            tag_key,
            levels,
            next_index: 0,
        }
    }

    /// The XMSS root.
    #[must_use]
    pub fn root(&self) -> FieldElement {
        self.levels.last().expect("at least the leaf level")[0]
    }

    /// The public seed, which the circuit takes as a private input bound by [`Self::commitment`].
    #[must_use]
    pub const fn pub_seed(&self) -> FieldElement {
        self.pub_seed
    }

    /// The key deriving the one-time-key tags.
    #[must_use]
    pub const fn tag_key(&self) -> FieldElement {
        self.tag_key
    }

    /// The commitment registered on-chain for this credential.
    #[must_use]
    pub fn commitment(&self) -> FieldElement {
        commitment(self.root(), self.pub_seed, self.tag_key)
    }

    /// The index the next signature uses.
    #[must_use]
    pub const fn next_index(&self) -> u64 {
        self.next_index
    }

    /// Advances past one-time keys used elsewhere, for example after an OPRF node rejected a
    /// signature's tag as already seen. Never moves backwards.
    pub fn skip_to(&mut self, index: u64) {
        self.next_index = self.next_index.max(index);
    }

    /// Signs `message` with the next unused one-time key.
    ///
    /// # Errors
    /// Returns [`XmssError::Exhausted`] once every one-time key has signed.
    pub fn sign(&mut self, message: FieldElement) -> Result<XmssSignature, XmssError> {
        let height = self.levels.len() - 1;
        let index = self.next_index;
        if index >= 1 << height {
            return Err(XmssError::Exhausted);
        }
        self.next_index += 1;

        let bits = digits(h3(
            ds::XMSS_MESSAGE,
            self.pub_seed,
            FieldElement::from(index),
            message,
        ));
        let chains = (0..WOTS_CHAINS)
            .map(|chain| {
                let start = chain_start(self.seed, index, chain);
                if bits[chain] {
                    chain_step(self.pub_seed, chain, start)
                } else {
                    start
                }
            })
            .collect();
        let auth_path = (0..height)
            .map(|level| {
                let position = usize::try_from(index >> level).expect("index fits in usize");
                self.levels[level][position ^ 1]
            })
            .collect();

        Ok(XmssSignature {
            chains,
            index,
            auth_path,
        })
    }
}

/// Recomputes the root `signature` over `message` belongs to, as the circuit does.
#[must_use]
pub fn root_from_signature(
    message: FieldElement,
    signature: &XmssSignature,
    pub_seed: FieldElement,
) -> FieldElement {
    let bits = digits(h3(
        ds::XMSS_MESSAGE,
        pub_seed,
        FieldElement::from(signature.index),
        message,
    ));
    let ends: Vec<FieldElement> = signature
        .chains
        .iter()
        .enumerate()
        .map(|(chain, value)| {
            if bits[chain] {
                *value
            } else {
                chain_step(pub_seed, chain, *value)
            }
        })
        .collect();

    let mut current = compress_public_key(&ends, pub_seed);
    for (level, sibling) in signature.auth_path.iter().enumerate() {
        current = if (signature.index >> level) & 1 == 1 {
            node(*sibling, current, pub_seed, level)
        } else {
            node(current, *sibling, pub_seed, level)
        };
    }
    current
}

/// The on-chain commitment to an XMSS credential.
#[must_use]
pub fn commitment(
    root: FieldElement,
    pub_seed: FieldElement,
    tag_key: FieldElement,
) -> FieldElement {
    let tag_key_commitment = h3(
        ds::XMSS_TAG_KEY,
        tag_key,
        FieldElement::ZERO,
        FieldElement::ZERO,
    );
    h3(ds::XMSS_COMMITMENT, root, pub_seed, tag_key_commitment)
}

/// The public one-time-key tag for `index`, unlinkable to the credential without `tag_key`.
#[must_use]
pub fn tag(tag_key: FieldElement, index: u64) -> FieldElement {
    h3(
        ds::XMSS_TAG,
        tag_key,
        FieldElement::from(index),
        FieldElement::ZERO,
    )
}

fn chain_start(seed: FieldElement, index: u64, chain: usize) -> FieldElement {
    h3(
        ds::XMSS_SECRET,
        seed,
        FieldElement::from(index),
        FieldElement::from(chain as u64),
    )
}

fn chain_step(pub_seed: FieldElement, chain: usize, value: FieldElement) -> FieldElement {
    h3(
        ds::XMSS_CHAIN,
        pub_seed,
        FieldElement::from(chain as u64),
        value,
    )
}

fn node(
    left: FieldElement,
    right: FieldElement,
    pub_seed: FieldElement,
    level: usize,
) -> FieldElement {
    h3(
        ds::XMSS_NODE,
        left,
        right,
        FieldElement::from(*pub_seed + ark_babyjubjub::Fq::from(level as u64)),
    )
}

/// The 254 digest bits, least significant first, followed by the 8-bit checksum: the number of
/// zero digest bits.
fn digits(digest: FieldElement) -> [bool; WOTS_CHAINS] {
    let digest_bits = digest.into_bigint().to_bits_le();
    let mut out = [false; WOTS_CHAINS];
    out[..WOTS_MSG_CHAINS].copy_from_slice(&digest_bits[..WOTS_MSG_CHAINS]);
    let zeros = out[..WOTS_MSG_CHAINS].iter().filter(|bit| !**bit).count();
    for i in 0..WOTS_CHECKSUM_CHAINS {
        out[WOTS_MSG_CHAINS + i] = (zeros >> i) & 1 == 1;
    }
    out
}

/// Sponge over the chain ends: separator in the capacity slot, `pub_seed` in the first rate slot,
/// rate 3, digest from slot 1.
fn compress_public_key(ends: &[FieldElement], pub_seed: FieldElement) -> FieldElement {
    let mut state = [
        *ds::XMSS_PUBLIC_KEY.as_field_element(),
        *pub_seed,
        ark_babyjubjub::Fq::ZERO,
        ark_babyjubjub::Fq::ZERO,
    ];
    for block in ends.chunks(3) {
        for (lane, end) in block.iter().enumerate() {
            state[lane + 1] += **end;
        }
        poseidon2::bn254::t4::permutation_in_place(&mut state);
    }
    state[1].into()
}

fn h3(
    ds: poseidon::DomainSeparator<3>,
    a: FieldElement,
    b: FieldElement,
    c: FieldElement,
) -> FieldElement {
    poseidon::hash(ds, [a, b, c])
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_HEIGHT: usize = 3;

    fn key() -> XmssSecretKey {
        XmssSecretKey::generate_with_height(FieldElement::from(42u64), TEST_HEIGHT)
    }

    #[test]
    fn test_signatures_verify_against_the_root() {
        let mut key = key();
        for i in 0..1u64 << TEST_HEIGHT {
            let message = FieldElement::from(1000 + i);
            let signature = key.sign(message).unwrap();
            assert_eq!(signature.index, i);
            assert_eq!(
                root_from_signature(message, &signature, key.pub_seed()),
                key.root()
            );
        }
        assert_eq!(key.sign(FieldElement::ZERO), Err(XmssError::Exhausted));
    }

    #[test]
    fn test_signature_does_not_verify_another_message() {
        let mut key = key();
        let signature = key.sign(FieldElement::from(1u64)).unwrap();
        assert_ne!(
            root_from_signature(FieldElement::from(2u64), &signature, key.pub_seed()),
            key.root()
        );
    }

    #[test]
    fn test_skip_to_never_moves_backwards() {
        let mut key = key();
        key.skip_to(5);
        key.skip_to(2);
        assert_eq!(key.next_index(), 5);
        assert_eq!(key.sign(FieldElement::ZERO).unwrap().index, 5);
    }

    #[test]
    fn test_tags_differ_per_index() {
        let key = key();
        assert_ne!(tag(key.tag_key(), 0), tag(key.tag_key(), 1));
    }
}
