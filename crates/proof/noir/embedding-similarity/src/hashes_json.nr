// PCP `hashes.json` binding: the credential claim and the thumbnail digest.
//
// The prover supplies `hashes.json` as the 31-byte chunks the sponge absorbs. Only the
// chunks covering the thumbnail entry are unpacked into bytes. Any other chunk set with
// the same claim would be a Poseidon2 collision.
use super::{
    constants::{CHUNK_BYTES, MAX_HASHES_JSON_BYTES, MIN_HASHES_JSON_BYTES, WINDOW_CHUNKS},
    types::HashesJsonInputs,
};
use world_id_components::var_hash::{h_var, safe_tags};

/// The `"thumbnail.png":"` key of the thumbnail entry.
global THUMBNAIL_KEY: [u8; 17] = "\"thumbnail.png\":\"".as_bytes();
/// Hex digits of a SHA-256 digest.
global DIGEST_HEX_LEN: u32 = 64;
global WINDOW_BYTES: u32 = WINDOW_CHUNKS * CHUNK_BYTES;

global NUM_LENGTHS: u32 = MAX_HASHES_JSON_BYTES - MIN_HASHES_JSON_BYTES + 1;

/// SAFE tag of the `CLAIMS_HASH_V1` sponge for every accepted length, computed at
/// compile time so the circuit never evaluates SHA3. Entry `i` is length `MIN + i`.
global SAFE_TAGS: [Field; NUM_LENGTHS] =
    comptime { safe_tags("CLAIMS_HASH_V1".as_bytes(), MIN_HASHES_JSON_BYTES) };

/// Number of sponge chunks of a `len`-byte input.
fn num_chunks(len: u32) -> u32 {
    (len + CHUNK_BYTES - 1) / CHUNK_BYTES
}

/// The Credential claim over raw bytes: WIP-100 `H_var` with label `CLAIMS_HASH_V1`, for
/// lengths `MIN_HASHES_JSON_BYTES..=MAX_HASHES_JSON_BYTES`.
pub fn claims_hash_v1(json: HashesJsonInputs) -> Field {
    h_var(
        json.chunks,
        json.len as Field,
        MIN_HASHES_JSON_BYTES,
        SAFE_TAGS,
    )
}

/// Returns `R(d)` for the thumbnail digest `d` in `hashes.json` (WIP-202 constraint 3.2).
///
/// `digest_offset` is where the 64 hex digits start. The 17 bytes before them are the key
/// `"thumbnail.png":"`, preceded by `{` or `,`. `hashes.json` is compact JSON with
/// lowercase hex values and file-name keys, so that pattern cannot occur inside a key or value.
pub fn thumbnail_digest(json: HashesJsonInputs) -> Field {
    let len = json.len;
    let offset = json.digest_offset;
    assert(offset >= 18, "thumbnail entry must follow a delimiter");
    assert(offset + DIGEST_HEX_LEN < len, "thumbnail entry exceeds hashes.json");

    // The checked bytes run from the delimiter, 18 bytes before the digest, to its closing quote.
    let base = offset - 18;
    let window = window_bytes(json, base / CHUNK_BYTES);
    let start = base % CHUNK_BYTES;

    let before = window[start];
    assert((before == 123) | (before == 44), "thumbnail entry must start a key");
    for i in 0..17 {
        assert(window[start + 1 + i] == THUMBNAIL_KEY[i], "thumbnail key mismatch");
    }
    // The 256-bit digest accumulated in the field is `R(d)`.
    // Accumulating 256 bits in a field element reduces the digest mod p, which is exactly
    // `R(SHA-256(image))`, the value WIP-201 stores in `compared_entry_hash_0`.
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
