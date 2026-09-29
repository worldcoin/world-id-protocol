/// Converts a P-256 coordinate (x or y) which is encoded as big-endian
/// bytes into a set of two field elements where each represents a u128 limb.
pub(crate) fn p256_be_coord_to_field(coord: [u8; 32]) -> (Field, Field) {
    // REVIEW: specific indexing is more performant than iteration?
    let hi_bytes = [
        coord[0], coord[1], coord[2], coord[3], coord[4], coord[5], coord[6], coord[7], coord[8],
        coord[9], coord[10], coord[11], coord[12], coord[13], coord[14], coord[15],
    ];

    let lo_bytes = [
        coord[16], coord[17], coord[18], coord[19], coord[20], coord[21], coord[22], coord[23],
        coord[24], coord[25], coord[26], coord[27], coord[28], coord[29], coord[30], coord[31],
    ];

    (Field::from_be_bytes(hi_bytes), Field::from_be_bytes(lo_bytes))
}

/// Asserts that `value` requires a 4-byte CBOR uint encoding
/// (`2^16 <= value < 2^32`), so fixed template offsets stay valid.
pub(crate) fn assert_cbor_uint32(value: Field) {
    let bytes: [u8; 4] = value.to_be_bytes();
    assert((bytes[0] != 0) | (bytes[1] != 0), "value must require a 4-byte CBOR uint encoding");
}

/// Asserts CWT `exp` freshness: `now < exp` (expired at `exp`, RFC 8392).
///
/// `now` MUST be a verifier-supplied public input; a prover-chosen private
/// timestamp would make the check vacuous.
pub(crate) fn assert_not_expired(exp: Field, now: Field) {
    assert(std::field::bn254::lt(now, exp), "token is expired");
}

/// Asserts that `exp` is at most `max_lifetime` seconds beyond `now`, i.e. that
/// the token has no more than `max_lifetime` seconds of validity left.
///
/// MUST be called after [`assert_not_expired`] for the same `exp` and `now`.
/// That `now < exp` is what makes `exp - now` the true integer difference
/// rather than a value wrapped around the modulus, so neither operand needs a
/// separate range check and the comparison cannot overflow.
pub(crate) fn assert_max_lifetime(exp: Field, now: Field, max_lifetime: Field) {
    assert(
        std::field::bn254::lt(exp - now, max_lifetime + 1),
        "token lifetime exceeds the maximum",
    );
}
