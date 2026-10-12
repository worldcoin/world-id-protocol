//! Account state for the registration tests.

use alloy::primitives::Address;
use eddsa_babyjubjub::EdDSAPublicKey;
use world_id_primitives::{AuthenticatorPublicKeySet, api_types::IndexerAuthenticatorsResponse};

use crate::OnchainKeyRepresentable as _;

/// An `/authenticators` response with each slot's key and address, and the commitment to the
/// keys.
pub(super) fn indexed_account(
    slots: &[Option<(EdDSAPublicKey, Address)>],
) -> IndexerAuthenticatorsResponse {
    let pubkeys: Vec<_> = slots
        .iter()
        .map(|slot| {
            slot.as_ref()
                .map(|(pubkey, _)| pubkey.to_ethereum_representation().unwrap())
        })
        .collect();
    let key_set = AuthenticatorPublicKeySet::from_sparse_encoded_pubkeys(pubkeys.clone()).unwrap();
    IndexerAuthenticatorsResponse {
        authenticator_pubkeys: pubkeys,
        authenticator_addresses: slots
            .iter()
            .map(|slot| slot.as_ref().map(|(_, address)| *address))
            .collect(),
        offchain_signer_commitment: key_set.leaf_hash().into(),
        recovery_counter: 0,
    }
}
