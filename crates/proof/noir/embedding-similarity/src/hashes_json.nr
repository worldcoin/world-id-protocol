// PCP `hashes.json` binding: the credential claim and the thumbnail digest.
//
// The prover supplies `hashes.json` as the 31-byte chunks the sponge absorbs. Only the
// chunks covering the thumbnail entry are unpacked into bytes. Any other chunk set with
// the same claim would be a Poseidon2 collision.
use super::{
    constants::{
        CHUNK_BYTES, CHUNK_SLOTS, MAX_HASHES_JSON_BYTES, MIN_HASHES_JSON_BYTES, NUM_CHUNKS,
        WINDOW_CHUNKS,
    },
    types::HashesJsonInputs,
};
use poseidon2::bn254::permutation;

/// The `"thumbnail.png":"` key of the thumbnail entry.
global THUMBNAIL_KEY: [u8; 17] = "\"thumbnail.png\":\"".as_bytes();
/// Hex digits of a SHA-256 digest.
global DIGEST_HEX_LEN: u32 = 64;
/// Sponge rate in field elements.
global RATE: u32 = 15;
global NUM_BATCHES: u32 = (NUM_CHUNKS + RATE - 1) / RATE;
global WINDOW_BYTES: u32 = WINDOW_CHUNKS * CHUNK_BYTES;

global NUM_LENGTHS: u32 = MAX_HASHES_JSON_BYTES - MIN_HASHES_JSON_BYTES + 1;

/// SAFE tag of the `CLAIMS_HASH_V1` sponge for every accepted length, computed at
/// compile time so the circuit never evaluates SHA3. Entry `i` is length `MIN + i`.
global SAFE_TAGS: [Field; NUM_LENGTHS] = comptime {
    let mut tags = [0; NUM_LENGTHS];
    for i in 0..NUM_LENGTHS {
        tags[i] = safe_tag(MIN_HASHES_JSON_BYTES + i);
    }
    tags
};

/// Number of sponge chunks of a `len`-byte input.
fn num_chunks(len: u32) -> u32 {
    (len + CHUNK_BYTES - 1) / CHUNK_BYTES
}

/// The Credential claim over raw bytes: the WIP-100 SAFE Poseidon2 t=16 sponge with
/// domain separator `CLAIMS_HASH_V1`, 15 chunks per permutation, squeezing element 0.
pub fn claims_hash_v1(json: HashesJsonInputs) -> Field {
    let len = json.len;
    assert(len >= MIN_HASHES_JSON_BYTES, "hashes.json is shorter than its bound");
    assert(len <= MAX_HASHES_JSON_BYTES, "hashes.json exceeds its bound");
    let n = num_chunks(len);

    // Slots past the last chunk must be zero, so they neither absorb nor decode.
    let mut active: Field = 1;
    for c in 0..CHUNK_SLOTS {
        active = active * (1 - (c == n) as Field);
        assert((1 - active) * json.chunks[c] == 0, "chunk past the end must be zero");
    }

    let mut state: [Field; 16] = [0; 16];
    state[15] = SAFE_TAGS[len - MIN_HASHES_JSON_BYTES];
    for batch in 0..NUM_BATCHES {
        // A batch is permuted exactly when it holds at least one chunk.
        let batch_active = (batch * RATE < n) as Field;
        for slot in 0..RATE {
            let c = batch * RATE + slot;
            if c < NUM_CHUNKS {
                state[slot] += json.chunks[c];
            }
        }
        let permuted = permutation::t16(state);
        for k in 0..16 {
            state[k] = state[k] + batch_active * (permuted[k] - state[k]);
        }
    }
    state[0]
}

/// Returns `R(d)` for the thumbnail digest `d` in `hashes.json` (WIP-202 constraint 3.2).
///
/// The entry must start a JSON key: the byte before it is `{` or `,`. `hashes.json` is
/// compact JSON with lowercase hex values and file-name keys, so `"thumbnail.png":"`
/// cannot occur inside a key or value.
pub fn thumbnail_digest(json: HashesJsonInputs) -> Field {
    let len = json.len;
    let offset = json.thumbnail_offset;
    let end = offset + 17 + DIGEST_HEX_LEN;
    assert(offset > 0, "thumbnail entry must follow a delimiter");
    assert(end < len, "thumbnail entry exceeds hashes.json");

    let window = window_bytes(json, (offset - 1) / CHUNK_BYTES);
    let start = (offset - 1) % CHUNK_BYTES;

    let before = window[start];
    assert((before == 123) | (before == 44), "thumbnail entry must start a key");
    for i in 0..17 {
        assert(window[start + 1 + i] == THUMBNAIL_KEY[i], "thumbnail key mismatch");
    }
    // The 256-bit digest accumulated in the field is `R(d)`.
    let mut digest: Field = 0;
    for i in 0..DIGEST_HEX_LEN {
        digest = digest * 16 + hex_nibble(window[start + 18 + i]);
    }
    assert(window[start + 82] == 34, "thumbnail digest must be 64 hex digits");
    digest
}

/// The bytes of chunks `first..first + WINDOW_CHUNKS`, in order.
///
/// The last chunk holds only its remaining bytes, right-aligned in its 31-byte
/// big-endian encoding; its logical byte `t` is encoded byte `t + pad`.
fn window_bytes(json: HashesJsonInputs, first: u32) -> [u8; WINDOW_BYTES] {
    let n = num_chunks(json.len);
    let last_len = json.len - (n - 1) * CHUNK_BYTES;
    let mut window: [u8; WINDOW_BYTES] = [0; WINDOW_BYTES];
    for k in 0..WINDOW_CHUNKS {
        let c = first + k;
        // Constrains the chunk below 2^248, as a 31-byte chunk is.
        let encoded: [u8; 31] = json.chunks[c].to_be_bytes();
        let pad = if c + 1 == n {
            CHUNK_BYTES - last_len
        } else {
            0
        };
        for t in 0..CHUNK_BYTES {
            let i = t + pad;
            window[k * CHUNK_BYTES + t] = if i < CHUNK_BYTES { encoded[i] } else { 0 };
        }
    }
    window
}

/// Lowercase hex digit value.
fn hex_nibble(c: u8) -> Field {
    let is_digit = (c >= 48) & (c <= 57);
    let is_letter = (c >= 97) & (c <= 102);
    assert(is_digit | is_letter, "thumbnail digest must be lowercase hex");
    if is_digit {
        (c - 48) as Field
    } else {
        (c - 87) as Field
    }
}

/// `SHA3-256(absorb_word || squeeze_word || "CLAIMS_HASH_V1") mod p`, the SAFE tag of a
/// `len`-byte input squeezed to 32 bytes.
comptime fn safe_tag(len: u32) -> Field {
    let ds = "CLAIMS_HASH_V1".as_bytes();
    let absorb = 0x80000000 + len;
    let mut block: [u8; 136] = [0; 136];
    block[0] = (absorb >> 24) as u8;
    block[1] = (absorb >> 16) as u8;
    block[2] = (absorb >> 8) as u8;
    block[3] = absorb as u8;
    block[7] = 32;
    for i in 0..14 {
        block[8 + i] = ds[i];
    }
    // SHA3-256 padding for a single 136-byte block.
    block[22] = 0x06;
    block[135] = 0x80;

    let mut state: [u64; 25] = [0; 25];
    for w in 0..17 {
        let mut lane: u64 = 0;
        for b in 0..8 {
            lane = lane | ((block[w * 8 + b] as u64) << (8 * b) as u64);
        }
        state[w] = lane;
    }
    state = std::hash::keccakf1600(state);

    let mut tag: Field = 0;
    for w in 0..4 {
        for b in 0..8 {
            tag = tag * 256 + ((state[w] >> (8 * b) as u64) & 0xff) as Field;
        }
    }
    tag
}
