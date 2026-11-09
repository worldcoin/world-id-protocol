//! Circuit-independent Groth16 helpers shared by the query and nullifier proofs.

use groth16_material::circom::CircomGroth16MaterialBuilder;

/// The material builder of a World ID Circom circuit: its pinned fingerprints and the
/// black-box functions both circuits' witness graphs use.
pub(crate) fn groth16_material_builder(
    zkey_fingerprint: &str,
    graph_fingerprint: &str,
) -> CircomGroth16MaterialBuilder {
    CircomGroth16MaterialBuilder::new()
        .fingerprint_zkey(zkey_fingerprint.into())
        .fingerprint_graph(graph_fingerprint.into())
        .bbf_num_2_bits_helper()
        .bbf_inv()
        .bbf_legendre()
        .bbf_sqrt_input()
        .bbf_sqrt_unchecked()
}
