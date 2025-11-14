#![allow(dead_code)]

use std::sync::Arc;

use alloy::primitives::{Address, U256};
use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature, EdwardsAffine};
use oprf_world_types::{MerkleMembership, UserPublicKeyBatch};
use oprf_zk::groth16_serde::Groth16Proof;
pub use world_id_primitives::{authenticator::ProtocolSigner, Config, TREE_DEPTH};
use world_id_primitives::{Credential, FieldElement, PrimitiveError};

use crate::types::RpRequest;

type DynProvider = ();
type AccountRegistryInstance<T> = ();
type UniquenessProof = (Groth16Proof, FieldElement);

#[derive(Debug)]
pub struct Authenticator {
    _private: (),
}

impl Authenticator {
    pub async fn init(_seed: &[u8], _config: Config) -> Result<Self, AuthenticatorError> {
        Err(AuthenticatorError::unsupported("init"))
    }

    pub async fn init_or_create(
        _seed: &[u8],
        _config: Config,
        _recovery_address: Option<Address>,
    ) -> Result<Option<Self>, AuthenticatorError> {
        Err(AuthenticatorError::unsupported("init_or_create"))
    }

    pub async fn init_or_create_blocking(
        _seed: &[u8],
        _config: Config,
        _recovery_address: Option<Address>,
    ) -> Result<Self, AuthenticatorError> {
        Err(AuthenticatorError::unsupported("init_or_create_blocking"))
    }

    pub async fn get_packed_account_index(
        _onchain_signer_address: Address,
        _registry: &AccountRegistryInstance<DynProvider>,
    ) -> Result<U256, AuthenticatorError> {
        Err(AuthenticatorError::unsupported("get_packed_account_index"))
    }

    pub fn onchain_address(&self) -> Address {
        unsupported("onchain_address")
    }

    pub fn offchain_pubkey(&self) -> EdDSAPublicKey {
        unsupported("offchain_pubkey")
    }

    pub fn offchain_pubkey_compressed(&self) -> Result<U256, AuthenticatorError> {
        Err(AuthenticatorError::unsupported(
            "offchain_pubkey_compressed",
        ))
    }

    pub fn registry(&self) -> Arc<AccountRegistryInstance<DynProvider>> {
        unsupported("registry")
    }

    pub fn provider(&self) -> DynProvider {
        unsupported("provider")
    }

    pub fn account_id(&self) -> U256 {
        unsupported("account_id")
    }

    pub fn raw_tree_index(&self) -> U256 {
        unsupported("raw_tree_index")
    }

    pub fn recovery_counter(&self) -> U256 {
        unsupported("recovery_counter")
    }

    pub fn pubkey_id(&self) -> U256 {
        unsupported("pubkey_id")
    }

    pub async fn fetch_inclusion_proof(
        &self,
    ) -> Result<(MerkleMembership, UserPublicKeyBatch), AuthenticatorError> {
        Err(AuthenticatorError::unsupported("fetch_inclusion_proof"))
    }

    pub async fn signing_nonce(&self) -> Result<U256, AuthenticatorError> {
        Err(AuthenticatorError::unsupported("signing_nonce"))
    }

    pub async fn generate_proof(
        &self,
        _message_hash: FieldElement,
        _rp_request: RpRequest,
        _credential: Credential,
    ) -> Result<UniquenessProof, AuthenticatorError> {
        Err(AuthenticatorError::unsupported("generate_proof"))
    }

    pub async fn insert_authenticator(
        &mut self,
        _new_authenticator_pubkey: EdDSAPublicKey,
        _new_authenticator_address: Address,
        _index: u32,
    ) -> Result<String, AuthenticatorError> {
        Err(AuthenticatorError::unsupported("insert_authenticator"))
    }

    pub async fn update_authenticator(
        &mut self,
        _old_authenticator_address: Address,
        _new_authenticator_address: Address,
        _new_authenticator_pubkey: EdDSAPublicKey,
        _index: u32,
    ) -> Result<String, AuthenticatorError> {
        Err(AuthenticatorError::unsupported("update_authenticator"))
    }

    pub async fn remove_authenticator(
        &mut self,
        _authenticator_address: Address,
        _index: u32,
    ) -> Result<String, AuthenticatorError> {
        Err(AuthenticatorError::unsupported("remove_authenticator"))
    }

    pub fn leaf_hash(_pk: &UserPublicKeyBatch) -> ark_babyjubjub::Fq {
        unsupported("leaf_hash")
    }

    pub fn compress_offchain_pubkey(_pk: &EdwardsAffine) -> Result<U256, PrimitiveError> {
        Err(unsupported_primitive_error("compress_offchain_pubkey"))
    }

    async fn create_account(
        _seed: &[u8],
        _config: &Config,
        _recovery_address: Option<Address>,
    ) -> Result<String, AuthenticatorError> {
        Err(AuthenticatorError::unsupported("create_account"))
    }
}

impl ProtocolSigner for Authenticator {
    fn sign(&self, _message: FieldElement) -> EdDSASignature {
        unsupported("sign")
    }
}

pub fn leaf_hash(_pk: &UserPublicKeyBatch) -> ark_babyjubjub::Fq {
    unsupported("leaf_hash")
}

pub fn compress_offchain_pubkey(_pk: &EdwardsAffine) -> Result<U256, PrimitiveError> {
    Err(unsupported_primitive_error("compress_offchain_pubkey"))
}

#[derive(Debug, thiserror::Error)]
pub enum AuthenticatorError {
    #[error("`Authenticator::{0}` is not supported on wasm32 targets")]
    Unsupported(&'static str),
}

impl AuthenticatorError {
    const fn unsupported(operation: &'static str) -> Self {
        Self::Unsupported(operation)
    }
}

fn unsupported<T>(operation: &'static str) -> T {
    panic!("`Authenticator::{operation}` is not supported on wasm32 targets")
}

fn unsupported_primitive_error(operation: &'static str) -> PrimitiveError {
    PrimitiveError::InvalidInput {
        attribute: format!("Authenticator::{operation}"),
        reason: "unsupported on wasm32 targets".to_string(),
    }
}
