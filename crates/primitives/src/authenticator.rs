use crate::FieldElement;
use ark_ff::PrimeField as _;
use eddsa_babyjubjub::EdDSASignature;

/// Domain separator for the authenticator OPRF query digest.
const OPRF_QUERY_DS: &[u8] = b"World ID Query";

/// Computes the Poseidon2 digest for an authenticator OPRF query.
///
/// # Arguments
/// * `leaf_index` - The leaf index of the authenticator in the World ID Registry.
/// * `action` - The action field element.
/// * `query_origin_id` - The `RpId` or `issuer_schema_id`.
#[must_use]
pub fn oprf_query_digest(
    leaf_index: u64,
    action: FieldElement,
    query_origin_id: FieldElement,
) -> FieldElement {
    let input = [
        ark_babyjubjub::Fq::from_be_bytes_mod_order(OPRF_QUERY_DS),
        leaf_index.into(),
        *query_origin_id,
        *action,
    ];
    poseidon2::bn254::t4::permutation(&input)[1].into()
}

/// Enables entities that sign messages within the Protocol for use with the ZK circuits.
///
/// This is in particular used by Authenticators to authorize requests for nullifier generation.
pub trait ProtocolSigner {
    /// Signs a message with the protocol signer using the `EdDSA` scheme (**off-chain** signer), for use
    /// with the Protocol ZK circuits.
    fn sign(&self, message: FieldElement) -> EdDSASignature
    where
        Self: Sized + Send + Sync;
}
