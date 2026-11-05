use ark_babyjubjub::Fq;
use ark_ff::Zero;
use sha3::{Digest, Sha3_256};

use crate::{FieldElement, PrimitiveError, VariableLengthDomainSeparator};

/// Bytes per chunk when mapping arbitrary data into field elements.
const CHUNK_SIZE_BYTES: usize = 31; // 248 bits < BN254 modulus
/// Rate for Poseidon2 t=16 with capacity=1 (last element).
const RATE_ELEMENTS: usize = 15;
/// IO pattern prefixes per SAFE (MSB set => absorb; unset => squeeze).
const IO_ABSORB_PREFIX: u32 = 0x8000_0000;
/// IO pattern prefix for squeezes (SAFE-style).
const IO_SQUEEZE_PREFIX: u32 = 0x0000_0000;
/// Fixed squeeze length (in bytes) for associated-data hashing.
const IO_SQUEEZE_LEN_BYTES: u32 = 32;

/// Hashes arbitrary bytes to a field element using Poseidon2 sponge construction.
///
/// This uses a SAFE-inspired sponge construction to support **arbitrary
/// length** input:
/// 1. Compute a SAFE-style tag from an IO pattern that encodes the input
///    length (in bytes), the squeeze size (32 bytes), and a domain separator.
///    The tag is derived by hashing these bytes with SHA3-256 and reducing to
///    a field element (placed in the capacity element, per SAFE guidance).
/// 2. Split input into 31-byte chunks, convert each to a field element.
/// 3. Absorb at most 15 field elements at a time (add into rate), then
///    permute (Poseidon2 t16) after each batch.
/// 4. Enforce the SAFE IO pattern (one absorb of `len(data)` bytes, one
///    squeeze of 32 bytes); abort on mismatch.
/// 5. Ensure a permutation has run before squeezing; squeeze one element
///    from the rate portion.
///
/// The state is divided into:
/// - Rate portion (indices 0-14): where data is absorbed via addition
/// - Capacity portion (index 15): provides security, not directly modified by input
///
/// # Arguments
/// * `ds` - The domain separator of this hash, see [`crate::poseidon::ds`].
/// * `data` - Arbitrary bytes to hash (any length).
///
/// # Errors
/// Will error if the data is empty.
pub fn hash_bytes_to_field_element(
    ds: VariableLengthDomainSeparator,
    data: &[u8],
) -> Result<FieldElement, PrimitiveError> {
    hash_bytes_to_field_element_raw(ds.as_bytes(), data)
}

/// Like [`hash_bytes_to_field_element`], with an unchecked domain separator tag.
///
/// For non-protocol hashes using tags [`VariableLengthDomainSeparator`] rejects (such as the
/// empty tag); protocol hashes use [`hash_bytes_to_field_element`] with [`crate::poseidon::ds`].
///
/// # Errors
/// Will error if `data` is empty or longer than `u32::MAX` bytes.
pub fn hash_bytes_to_field_element_raw(
    tag: &[u8],
    data: &[u8],
) -> Result<FieldElement, PrimitiveError> {
    hash_bytes_with_poseidon2_t16_r15(data, tag, "associated_data")
}

/// Convert arbitrary bytes into field elements using fixed-size chunks.
#[must_use]
pub fn bytes_to_field_elements(chunk_size: usize, data: &[u8]) -> Vec<Fq> {
    data.chunks(chunk_size)
        .map(|chunk| *FieldElement::from_be_bytes_mod_order(chunk))
        .collect()
}

/// SAFE-style IO pattern checker.
struct IoPattern<'a> {
    expected: Vec<u32>,
    idx: usize,
    attr: &'a str,
}

impl<'a> IoPattern<'a> {
    /// Create a new IO pattern checker for a given attribute and expected sequence.
    #[allow(clippy::missing_const_for_fn)]
    #[must_use]
    fn new(attr: &'a str, expected: Vec<u32>) -> Self {
        Self {
            expected,
            idx: 0,
            attr,
        }
    }

    /// Record an absorb call of a given byte length, enforcing the pattern.
    ///
    /// # Errors
    /// Returns an error when the IO pattern does not match an expected absorb call.
    fn record_absorb(&mut self, len_bytes: u32) -> Result<(), PrimitiveError> {
        self.check(IO_ABSORB_PREFIX.wrapping_add(len_bytes), "absorb")
    }

    /// # Errors
    /// Returns an error when the IO pattern does not match an expected squeeze call.
    /// Record a squeeze call of a given byte length, enforcing the pattern.
    fn record_squeeze(&mut self, len_bytes: u32) -> Result<(), PrimitiveError> {
        self.check(IO_SQUEEZE_PREFIX.wrapping_add(len_bytes), "squeeze")
    }

    /// # Errors
    /// Returns an error when the IO pattern has remaining, unconsumed entries.
    /// Verify that the pattern is fully consumed.
    fn finish(self) -> Result<(), PrimitiveError> {
        if self.idx != self.expected.len() {
            return Err(PrimitiveError::InvalidInput {
                attribute: self.attr.to_string(),
                reason: "SAFE IO pattern not fully consumed".to_string(),
            });
        }
        Ok(())
    }

    fn check(&mut self, word: u32, label: &str) -> Result<(), PrimitiveError> {
        if self.idx >= self.expected.len() || self.expected[self.idx] != word {
            return Err(PrimitiveError::InvalidInput {
                attribute: self.attr.to_string(),
                reason: format!("SAFE IO pattern violated during {label}"),
            });
        }
        self.idx += 1;
        Ok(())
    }
}

/// Derive a SAFE-style tag from an IO pattern and domain separator, hashed with SHA3-256.
#[must_use]
fn derive_safe_tag(
    absorb_len_bytes: u32,
    squeeze_len_bytes: u32,
    domain_separator: &[u8],
) -> FieldElement {
    let absorb_word = IO_ABSORB_PREFIX
        .wrapping_add(absorb_len_bytes)
        .to_be_bytes();
    let squeeze_word = IO_SQUEEZE_PREFIX
        .wrapping_add(squeeze_len_bytes)
        .to_be_bytes();

    let mut tag_input =
        Vec::with_capacity(absorb_word.len() + squeeze_word.len() + domain_separator.len());
    tag_input.extend_from_slice(&absorb_word);
    tag_input.extend_from_slice(&squeeze_word);
    tag_input.extend_from_slice(domain_separator);

    let tag_digest = Sha3_256::digest(&tag_input);
    FieldElement::from_be_bytes_mod_order(&tag_digest)
}

/// Hash arbitrary bytes to a field element with Poseidon2 (t=16, rate=15, capacity=1),
/// using a SAFE-style tag placed in the **capacity** portion
///
/// # Errors
/// - Returns `InvalidInput` if `data` is empty or exceeds `u32::MAX` bytes.
/// - Propagates `InvalidInput` if the SAFE IO pattern is violated (should not happen for valid inputs).
fn hash_bytes_with_poseidon2_t16_r15(
    data: &[u8],
    domain_separator: &[u8],
    attr: &str,
) -> Result<FieldElement, PrimitiveError> {
    if data.is_empty() {
        return Err(PrimitiveError::InvalidInput {
            attribute: attr.to_string(),
            reason: "data cannot be empty".to_string(),
        });
    }
    let data_len_u32 = u32::try_from(data.len()).map_err(|_| PrimitiveError::InvalidInput {
        attribute: attr.to_string(),
        reason: "data length exceeds supported range (u32::MAX)".to_string(),
    })?;

    // Initialize state with zeros
    let mut state: [Fq; 16] = [Fq::zero(); 16];

    let mut io_pattern = IoPattern::new(
        attr,
        vec![
            IO_ABSORB_PREFIX.wrapping_add(data_len_u32),
            IO_SQUEEZE_PREFIX.wrapping_add(IO_SQUEEZE_LEN_BYTES),
        ],
    );
    io_pattern.record_absorb(data_len_u32)?;

    // Compute SAFE-style tag and place it in the capacity (index 15).
    let tag_fe: Fq = *derive_safe_tag(data_len_u32, IO_SQUEEZE_LEN_BYTES, domain_separator);
    state[15] += tag_fe;

    // Convert bytes to field elements and absorb in RATE-sized batches.
    let field_elements = bytes_to_field_elements(CHUNK_SIZE_BYTES, data);
    for batch in field_elements.chunks(RATE_ELEMENTS) {
        for (i, &elem) in batch.iter().enumerate() {
            state[i] += elem;
        }
        poseidon2::bn254::t16::permutation_in_place(&mut state);
    }

    // Enforce squeeze step and pattern completion.
    io_pattern.record_squeeze(IO_SQUEEZE_LEN_BYTES)?;
    io_pattern.finish()?;

    // Squeeze from the rate portion (index 0).
    Ok(FieldElement::from(state[0]))
}

#[cfg(test)]
mod tests {
    use crate::{
        FieldElement, PrimitiveError, VariableLengthDomainSeparator,
        sponge::hash_bytes_with_poseidon2_t16_r15,
    };

    use super::{hash_bytes_to_field_element, hash_bytes_to_field_element_raw};

    const TEST_DS_TAG: VariableLengthDomainSeparator =
        VariableLengthDomainSeparator::new(b"TEST_DS_TAG");

    #[test]
    fn derive_tag_stable() {
        let tag = super::derive_safe_tag(10, super::IO_SQUEEZE_LEN_BYTES, b"DS");
        let again = super::derive_safe_tag(10, super::IO_SQUEEZE_LEN_BYTES, b"DS");
        assert_eq!(tag, again);
    }

    #[test]
    fn hash_bytes_rejects_empty() {
        let res = hash_bytes_with_poseidon2_t16_r15(&[], b"DS", "test");
        assert!(matches!(
            res,
            Err(PrimitiveError::InvalidInput { attribute, .. }) if attribute == "test"
        ));
    }

    #[test]
    fn hash_bytes_deterministic_nonzero() {
        let data = vec![1u8, 2, 3, 4];
        let h1 = hash_bytes_with_poseidon2_t16_r15(&data, b"DS", "test").unwrap();
        let h2 = hash_bytes_with_poseidon2_t16_r15(&data, b"DS", "test").unwrap();
        assert_eq!(h1, h2);
        assert_ne!(h1, FieldElement::ZERO);
    }

    #[test]
    fn test_hash_bytes_to_field_element_basic() {
        let data = vec![1u8, 2, 3, 4, 5];
        let result = hash_bytes_to_field_element(TEST_DS_TAG, &data);
        assert!(result.is_ok());

        // Should produce a non-zero result
        let hash = result.unwrap();
        assert_ne!(hash, FieldElement::ZERO);
    }

    #[test]
    fn test_hash_bytes_to_field_element_deterministic() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let result1 = hash_bytes_to_field_element(TEST_DS_TAG, &data).unwrap();
        let result2 = hash_bytes_to_field_element(TEST_DS_TAG, &data).unwrap();

        // Same input should produce same output
        assert_eq!(result1, result2);
        // Should produce a non-zero result
        assert_ne!(result1, FieldElement::ZERO);
    }

    #[test]
    fn test_hash_bytes_to_field_element_different_inputs() {
        let data1 = vec![1u8, 2, 3, 4, 5];
        let data2 = vec![5u8, 4, 3, 2, 1];
        let data3 = vec![1u8, 2, 3, 4, 5, 6];

        let hash1 = hash_bytes_to_field_element(TEST_DS_TAG, &data1).unwrap();
        let hash2 = hash_bytes_to_field_element(TEST_DS_TAG, &data2).unwrap();
        let hash3 = hash_bytes_to_field_element(TEST_DS_TAG, &data3).unwrap();

        // Different inputs should produce different outputs
        assert_ne!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_ne!(hash2, hash3);
    }

    #[test]
    fn test_hash_bytes_to_field_element_empty_error() {
        let data: Vec<u8> = vec![];
        let result = hash_bytes_to_field_element(TEST_DS_TAG, &data);

        assert!(result.is_err());
        if let Err(PrimitiveError::InvalidInput { attribute, reason }) = result {
            assert_eq!(attribute, "associated_data");
            assert!(reason.contains("empty"));
        } else {
            panic!("Expected InvalidInput error");
        }
    }

    #[test]
    fn test_hash_bytes_to_field_element_large_input() {
        // Test with a large input (10KB) to ensure arbitrary-length support
        let data = vec![42u8; 10 * 1024];
        let result = hash_bytes_to_field_element(TEST_DS_TAG, &data);
        assert!(result.is_ok());

        // Should produce a non-zero result
        let hash = result.unwrap();
        assert_ne!(hash, FieldElement::ZERO);
    }

    #[test]
    fn test_hash_bytes_to_field_element_length_domain_separation() {
        // Two inputs with same data but different lengths should hash differently
        let data1 = vec![0u8; 10];
        let data2 = vec![0u8; 11];

        let hash1 = hash_bytes_to_field_element(TEST_DS_TAG, &data1).unwrap();
        let hash2 = hash_bytes_to_field_element(TEST_DS_TAG, &data2).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_bytes_chunk_boundaries_and_batches() {
        // Exercise chunking (31-byte), just-over-chunk, and multi-batch (rate=15)
        let sizes = [
            1usize,
            31,
            32,
            33,
            15 * 31,     // exactly fills 15 chunks -> one batch
            15 * 31 + 1, // spills into a second batch
        ];

        for size in sizes {
            let data = vec![42u8; size];
            let h1 = hash_bytes_to_field_element(TEST_DS_TAG, &data).unwrap();
            let h2 = hash_bytes_to_field_element(TEST_DS_TAG, &data).unwrap();

            assert_ne!(
                h1,
                FieldElement::ZERO,
                "size {size} should not hash to zero"
            );
            assert_eq!(h1, h2, "hash should be deterministic for size {size}");
        }
    }

    #[test]
    fn raw_tag_matches_typed_separator() {
        let data = b"some data";
        assert_eq!(
            hash_bytes_to_field_element_raw(TEST_DS_TAG.as_bytes(), data).unwrap(),
            hash_bytes_to_field_element(TEST_DS_TAG, data).unwrap()
        );
    }

    /// Pins oxide and face-ampc face enrollment hashes, including the empty tag.
    #[test]
    fn raw_tag_outputs_are_stable() {
        for (tag, data, expected) in [
            (
                &b""[..],
                &b"hello"[..],
                "0x0aa3b1f35812331643e4d6116ec00b7b279ef4e3ac79f5d481f3c69250be387a",
            ),
            (
                b"ID_COMMITMENT_HASH_V1",
                b"0xfeedface",
                "0x299e43d7a6709260340fc353f1fe11a4083db8249790b8e230c29d918fd45b79",
            ),
        ] {
            let hash = hash_bytes_to_field_element_raw(tag, data).unwrap();
            assert_eq!(hash.to_string(), expected);
        }
    }

    #[test]
    fn raw_tag_rejects_empty_data() {
        assert!(matches!(
            hash_bytes_to_field_element_raw(b"", &[]),
            Err(PrimitiveError::InvalidInput { .. })
        ));
    }
}
