#![allow(dead_code)]

use std::sync::Arc;

use alloy::primitives::{Address, U256};
use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature, EdwardsAffine};
use oprf_world_types::{Groth16Proof, MerkleMembership, UserPublicKeyBatch};
use oprf_zk::{Groth16Material, ZkError};
pub use world_id_primitives::{authenticator::ProtocolSigner, Config, TREE_DEPTH};
use world_id_primitives::{Credential, FieldElement, PrimitiveError};

use crate::types::RpRequest;

type DynProvider = ();
type AccountRegistryInstance<T> = ();
type UniquenessProof = (Groth16Proof, FieldElement);

/// Describes where Groth16 assets for a single circuit can be fetched.
#[derive(Clone, Debug)]
pub struct RemoteGroth16Circuit {
    /// URL pointing to the `.zkey` proving key.
    pub zkey_url: String,
    /// URL pointing to the witness graph binary.
    pub graph_url: String,
    /// Optional SHA-256 fingerprint expected for the `.zkey`.
    pub fingerprint: Option<String>,
}

impl RemoteGroth16Circuit {
    #[must_use]
    pub fn new(zkey_url: impl Into<String>, graph_url: impl Into<String>) -> Self {
        Self {
            zkey_url: zkey_url.into(),
            graph_url: graph_url.into(),
            fingerprint: None,
        }
    }

    #[must_use]
    pub fn with_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.fingerprint = Some(fingerprint.into());
        self
    }
}

/// Remote Groth16 sources required to generate proofs (query + nullifier circuits).
#[derive(Clone, Debug)]
pub struct RemoteGroth16MaterialSources {
    pub query: RemoteGroth16Circuit,
    pub nullifier: RemoteGroth16Circuit,
}

impl RemoteGroth16MaterialSources {
    #[must_use]
    pub fn new(query: RemoteGroth16Circuit, nullifier: RemoteGroth16Circuit) -> Self {
        Self { query, nullifier }
    }
}

/// In-memory Groth16 materials fetched from remote sources.
#[derive(Debug)]
pub struct RemoteGroth16Materials {
    pub query: Groth16Material,
    pub nullifier: Groth16Material,
}

impl RemoteGroth16Materials {
    #[must_use]
    pub fn into_inner(self) -> (Groth16Material, Groth16Material) {
        (self.query, self.nullifier)
    }
}

#[derive(Debug)]
pub struct Authenticator {
    _private: (),
}

impl Authenticator {
    pub async fn fetch_groth16_materials(
        sources: &RemoteGroth16MaterialSources,
    ) -> Result<RemoteGroth16Materials, AuthenticatorError> {
        let query = load_circuit_material(&sources.query).await?;
        let nullifier = load_circuit_material(&sources.nullifier).await?;
        Ok(RemoteGroth16Materials { query, nullifier })
    }

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

async fn load_circuit_material(
    circuit: &RemoteGroth16Circuit,
) -> Result<Groth16Material, AuthenticatorError> {
    let material = Groth16Material::from_urls(
        &circuit.zkey_url,
        circuit.fingerprint.as_deref(),
        &circuit.graph_url,
    )
    .await?;
    Ok(material)
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

    #[error("failed to prepare Groth16 material: {0}")]
    Groth16Material(#[from] ZkError),
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
