use crate::{
    FieldElement,
    poseidon::{self, ds},
};
use eddsa_babyjubjub::EdDSASignature;

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
    poseidon::hash(ds::OPRF_QUERY, [leaf_index.into(), query_origin_id, action])
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
