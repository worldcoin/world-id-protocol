use ark_babyjubjub::Fq;
use ark_ff::Zero;
use poseidon2::{Poseidon2, POSEIDON2_BN254_T16_PARAMS};
use sha3::{Digest, Sha3_256};

use crate::{FieldElement, PrimitiveError};

/// Bytes per chunk when mapping arbitrary data into field elements.
pub const CHUNK_SIZE_BYTES: usize = 31; // 248 bits < BN254 modulus
/// Rate for Poseidon2 t=16 with capacity=1 (last element).
pub const RATE_ELEMENTS: usize = 15;
/// IO pattern prefixes per SAFE (MSB set => absorb; unset => squeeze).
pub const IO_ABSORB_PREFIX: u32 = 0x8000_0000;
/// IO pattern prefix for squeezes (SAFE-style).
pub const IO_SQUEEZE_PREFIX: u32 = 0x0000_0000;
/// Fixed squeeze length (in bytes) for associated-data hashing.
pub const IO_SQUEEZE_LEN_BYTES: u32 = 32;

/// SAFE-style IO pattern checker.
pub struct IoPattern<'a> {
    expected: Vec<u32>,
    idx: usize,
    attr: &'a str,
}

impl<'a> IoPattern<'a> {
    /// Create a new IO pattern checker for a given attribute and expected sequence.
    pub fn new(attr: &'a str, expected: Vec<u32>) -> Self {
        Self {
            expected,
            idx: 0,
            attr,
        }
    }

    /// Record an absorb call of a given byte length, enforcing the pattern.
    pub fn record_absorb(&mut self, len_bytes: u32) -> Result<(), PrimitiveError> {
        self.check(IO_ABSORB_PREFIX.wrapping_add(len_bytes), "absorb")
    }

    /// Record a squeeze call of a given byte length, enforcing the pattern.
    pub fn record_squeeze(&mut self, len_bytes: u32) -> Result<(), PrimitiveError> {
        self.check(IO_SQUEEZE_PREFIX.wrapping_add(len_bytes), "squeeze")
    }

    /// Verify that the pattern is fully consumed.
    pub fn finish(self) -> Result<(), PrimitiveError> {
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
                reason: format!("SAFE IO pattern violated during {}", label),
            });
        }
        self.idx += 1;
        Ok(())
    }
}

/// Derive a SAFE-style tag from an IO pattern and domain separator, hashed with SHA3-256.
pub fn derive_safe_tag(
    absorb_len_bytes: u32,
    squeeze_len_bytes: u32,
    domain_separator: &[u8],
) -> FieldElement {
    let absorb_word = IO_ABSORB_PREFIX.wrapping_add(absorb_len_bytes).to_be_bytes();
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

/// Convert arbitrary bytes into field elements using fixed-size chunks.
pub fn bytes_to_field_elements(chunk_size: usize, data: &[u8]) -> Vec<Fq> {
    data.chunks(chunk_size)
        .map(|chunk| *FieldElement::from_be_bytes_mod_order(chunk))
        .collect()
}

/// Hash arbitrary bytes to a field element with Poseidon2 (t=16, rate=15, capacity=1),
/// using a SAFE-style tag placed in the rate portion (per design note).
pub fn hash_bytes_with_poseidon2_t16_r15(
    data: &[u8],
    domain_separator: &[u8],
    attr: &str,
) -> Result<FieldElement, PrimitiveError> {

    let poseidon2: Poseidon2<Fq, 16, 5> = Poseidon2::new(&POSEIDON2_BN254_T16_PARAMS);

    // Initialize state with zeros
    let mut state: [Fq; 16] = [Fq::zero(); 16];
    
    let mut io_pattern = IoPattern::new(
        attr,
        vec![
            IO_ABSORB_PREFIX.wrapping_add(data.len() as u32),
            IO_SQUEEZE_PREFIX.wrapping_add(IO_SQUEEZE_LEN_BYTES),
        ],
    );
    io_pattern.record_absorb(data.len() as u32)?;

    // Compute SAFE-style tag and place it in the rate (index 0). Capacity is the last element.
    let tag_fe: Fq = *derive_safe_tag(data.len() as u32, IO_SQUEEZE_LEN_BYTES, domain_separator);
    state[0] += tag_fe;

    // Convert bytes to field elements and absorb in RATE-sized batches.
    let field_elements = bytes_to_field_elements(CHUNK_SIZE_BYTES, data);
    for batch in field_elements.chunks(RATE_ELEMENTS) {
        for (i, &elem) in batch.iter().enumerate() {
            state[i] += elem;
        }
        poseidon2.permutation_in_place(&mut state);
    }

    // Enforce squeeze step and pattern completion.
    io_pattern.record_squeeze(IO_SQUEEZE_LEN_BYTES)?;
    io_pattern.finish()?;

    // Squeeze from the rate portion (index 0).
    Ok(FieldElement::from(state[0]))
}
