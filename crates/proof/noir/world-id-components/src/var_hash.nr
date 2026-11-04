// Variable-length hash H_var (WIP-100 §3.3.3): a SAFE sponge over the Poseidon2 t=16
// permutation, rate 15 at state indices 0..14, capacity at 15, squeezing from index 0.
use poseidon2::bn254::permutation;

/// Bytes per absorbed chunk: 31 bytes always stay below the BN254 modulus.
pub global CHUNK_BYTES: u32 = 31;
global RATE: u32 = 15;

/// The SAFE capacity tag of an `len`-byte input under `label`: SHA3-256 over the absorb word
/// `0x80000000 + len`, the squeeze word `32` and the label, read as a big-endian integer mod p.
pub comptime fn safe_tag<let L: u32>(label: [u8; L], len: u32) -> Field {
    assert(L + 8 < 136, "label too long for one SHA3-256 block");
    let absorb = 0x80000000 + len;
    let mut block: [u8; 136] = [0; 136];
    // Set absorb word
    block[0] = (absorb >> 24) as u8;
    block[1] = (absorb >> 16) as u8;
    block[2] = (absorb >> 8) as u8;
    block[3] = absorb as u8;
    // Set squeeze word (block[4..7] are already 0, squeeze length is 32)
    block[7] = 32;
    // Append label (domain separator)
    for i in 0..L {
        block[8 + i] = label[i];
    }
    // SHA3-256 padding for a single 136-byte block.
    block[8 + L] = 0x06;
    block[135] = block[135] | 0x80;
    // Initialize Keccak state
    let mut state: [u64; 25] = [0; 25];
    for w in 0..17 {
        let mut lane: u64 = 0;
        for b in 0..8 {
            lane = lane | ((block[w * 8 + b] as u64) << (8 * b) as u64);
        }
        state[w] = lane;
    }
    // Perform Keccak permutation
    state = std::hash::keccakf1600(state);

    // Reduce state to field element
    let mut tag: Field = 0;
    for w in 0..4 {
        for b in 0..8 {
            tag = tag * 256 + ((state[w] >> (8 * b) as u64) & 0xff) as Field;
        }
    }
    tag
}

/// Lookup table of SAFE capacity tags for every length in `min_len..min_len + N`, for [`h_var`].
pub comptime fn safe_tags<let L: u32, let N: u32>(label: [u8; L], min_len: u32) -> [Field; N] {
    let mut tags = [0; N];
    for i in 0..N {
        tags[i] = safe_tag(label, min_len + i);
    }
    tags
}

/// `H_var` over the first `len` bytes of `chunks`.
///
/// Compile-time window: `tags[i]` is the SAFE tag for length `MIN_LEN + i`, i.e. accepted
/// lengths `MIN_LEN..MIN_LEN + N`. `chunks` must be long enough for the longest of those
/// lengths (`MIN_LEN + N - 1` bytes).
///
/// Witnesses:
/// - `chunks`: message packed as 31-byte big-endian field elements (last chunk shorter);
///   slots past `len` must be zero. Not checked to be canonical encodings of bytes.
/// - `len`: actual message length in bytes.
///
/// Rejects an empty input (matching the Rust sponge).
pub fn h_var<let S: u32, let N: u32, let MIN_LEN: u32>(
    chunks: [Field; S],
    len: Field,
    tags: [Field; N],
) -> Field {
    assert(
        S * CHUNK_BYTES >= MIN_LEN + N - 1,
        "H_var chunk buffer is shorter than its length window",
    );
    len.assert_max_bit_size::<32>();
    let len = len as u32;
    assert(len > 0, "H_var input cannot be empty");
    assert(len >= MIN_LEN, "H_var input is shorter than its bound");
    assert(len < MIN_LEN + N, "H_var input exceeds its bound");
    let n = (len + CHUNK_BYTES - 1) / CHUNK_BYTES;

    let mut active: Field = 1;
    for c in 0..S {
        active = active * (1 - (c == n) as Field);
        assert((1 - active) * chunks[c] == 0, "chunk past the end must be zero");
    }

    let mut state: [Field; 16] = [0; 16];
    state[15] = tags[len - MIN_LEN];
    for batch in 0..(S + RATE - 1) / RATE {
        // Batches past the input keep the state; their chunks are zero.
        let batch_active = (batch * RATE < n) as Field;
        for slot in 0..RATE {
            let c = batch * RATE + slot;
            if c < S {
                state[slot] += chunks[c];
            }
        }
        let permuted = permutation::t16(state);
        for k in 0..16 {
            state[k] = state[k] + batch_active * (permuted[k] - state[k]);
        }
    }
    state[0]
}

mod tests {
    use super::{CHUNK_BYTES, h_var, safe_tag};

    global LABEL: [u8; 14] = "CLAIMS_HASH_V1".as_bytes();

    /// Bytes `i mod 251` packed into chunks, as in WIP-100 Appendix A1.4.
    fn ascending<let S: u32>(len: u32) -> [Field; S] {
        let mut chunks = [0; S];
        for i in 0..S * CHUNK_BYTES {
            if i < len {
                chunks[i / CHUNK_BYTES] = chunks[i / CHUNK_BYTES] * 256 + (i % 251) as Field;
            }
        }
        chunks
    }

    #[test]
    fn test_matches_the_wip_100_vectors() {
        assert_eq(
            h_var::<16, 1, 31>(ascending::<16>(31), 31, [comptime { safe_tag(LABEL, 31) }]),
            12658306072862357948815044357476041793480954961275831694284480429814652585452,
        );
        assert_eq(
            h_var::<16, 1, 32>(ascending::<16>(32), 32, [comptime { safe_tag(LABEL, 32) }]),
            7105501883046959224351664232028428089815911608118705425730076057190813037341,
        );
        assert_eq(
            h_var::<16, 1, 465>(
                ascending::<16>(465),
                465,
                [comptime { safe_tag(LABEL, 465) }],
            ),
            13435504409435728907439603956434602577345452839959452028063546759536561347478,
        );
        assert_eq(
            h_var::<16, 1, 466>(
                ascending::<16>(466),
                466,
                [comptime { safe_tag(LABEL, 466) }],
            ),
            15525893232164838192982873493581731321396161293199355856124601873305423262450,
        );
    }

    #[test(should_fail_with = "H_var chunk buffer is shorter than its length window")]
    fn test_rejects_a_chunk_buffer_shorter_than_the_window() {
        // 32 bytes need two 31-byte chunks.
        let _ = h_var::<1, 1, 32>(ascending::<1>(32), 32, [comptime { safe_tag(LABEL, 32) }]);
    }

    #[test(should_fail_with = "H_var input cannot be empty")]
    fn test_rejects_an_empty_input() {
        let _ = h_var::<16, 1, 0>(ascending::<16>(0), 0, [comptime { safe_tag(LABEL, 0) }]);
    }

    #[test(should_fail_with = "H_var input is shorter than its bound")]
    fn test_rejects_a_length_below_the_bound() {
        let _ = h_var::<16, 1, 32>(ascending::<16>(31), 31, [comptime { safe_tag(LABEL, 32) }]);
    }

    #[test(should_fail_with = "H_var input exceeds its bound")]
    fn test_rejects_a_length_above_the_bound() {
        let _ = h_var::<16, 1, 31>(ascending::<16>(32), 32, [comptime { safe_tag(LABEL, 31) }]);
    }

    #[test(should_fail_with = "chunk past the end must be zero")]
    fn test_rejects_a_chunk_past_the_end() {
        let mut chunks = ascending::<16>(31);
        chunks[1] = 1;
        let _ = h_var::<16, 1, 31>(chunks, 31, [comptime { safe_tag(LABEL, 31) }]);
    }

    #[test(should_fail_with = "call to assert_max_bit_size")]
    fn test_rejects_a_length_beyond_32_bits() {
        let _ = h_var::<16, 1, 31>(
            ascending::<16>(31),
            31 + 0x100000000,
            [comptime { safe_tag(LABEL, 31) }],
        );
    }
}
