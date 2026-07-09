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
