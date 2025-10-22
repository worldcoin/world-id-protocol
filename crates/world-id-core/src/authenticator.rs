//! This module contains all the base functionality to support Authenticators in World ID.
//!
//! An Authenticator is the application layer with which a user interacts with the Protocol.
use std::io::Cursor;
use std::sync::{Arc, OnceLock};

use crate::account_registry::AccountRegistry::{self, AccountRegistryInstance};
use crate::account_registry::{
    domain, sign_insert_authenticator, sign_remove_authenticator, sign_update_authenticator,
};
use crate::config::Config;
use crate::types::{
    CreateAccountRequest, GatewayStatusResponse, InclusionProofResponse,
    InsertAuthenticatorRequest, RemoveAuthenticatorRequest, RpRequest, UpdateAuthenticatorRequest,
};
use crate::{Credential, FieldElement, Signer};
use alloy::primitives::{Address, U256};
use alloy::providers::ProviderBuilder;
use alloy::providers::{DynProvider, Provider};
use alloy::uint;
use ark_babyjubjub::EdwardsAffine;
use ark_ff::AdditiveGroup;
use ark_serde_compat::groth16::Groth16Proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use eddsa_babyjubjub::EdDSAPublicKey;
use eyre::Result;
use oprf_client::zk::Groth16Material;
use oprf_client::{MerkleMembership, NullifierArgs, OprfQuery, UserKeyMaterial};
use oprf_types::crypto::UserPublicKeyBatch;
use oprf_types::{MerkleRoot, RpId, ShareEpoch};
use poseidon2::Poseidon2;
use secrecy::ExposeSecret;
use std::str::FromStr;

static MASK_RECOVERY_COUNTER: U256 =
    uint!(0xFFFFFFFF00000000000000000000000000000000000000000000000000000000_U256);
static MASK_PUBKEY_ID: U256 =
    uint!(0x00000000FFFFFFFF000000000000000000000000000000000000000000000000_U256);
static MASK_ACCOUNT_INDEX: U256 =
    uint!(0x0000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_U256);

static TREE_DEPTH: usize = 30;

static QUERY_ZKEY_PATH: &str = "OPRFQueryProof.zkey";
static NULLIFIER_ZKEY_PATH: &str = "OPRFNullifierProof.zkey";

type UniquenessProof = (Groth16Proof, FieldElement);

/// An Authenticator is the base layer with which a user interacts with the Protocol.
#[derive(Debug)]
pub struct Authenticator {
    /// General configuration for the Authenticator.
    pub config: Config,
    signer: Signer,
    packed_account_index: Option<U256>,
    registry: OnceLock<Arc<AccountRegistryInstance<DynProvider>>>,
    provider: OnceLock<DynProvider>,
}

impl Authenticator {
    /// Create a new Authenticator from a seed and config.
    ///
    /// # Errors
    /// Will error if the provided seed is not valid.
    pub fn new(seed: &[u8], config: Config) -> Result<Self> {
        let signer = Signer::from_seed_bytes(seed)?;
        Ok(Self {
            packed_account_index: None,
            signer,
            config,
            registry: OnceLock::new(),
            provider: OnceLock::new(),
        })
    }

    /// Returns the k256 public key of the Authenticator signer which is used to verify on-chain operations,
    /// chiefly with the `AccountRegistry` contract.
    #[must_use]
    pub const fn onchain_address(&self) -> Address {
        self.signer.onchain_signer_address()
    }

    /// Returns the `EdDSA` public key of the Authenticator signer which is used to verify off-chain operations. For example,
    /// the Nullifier Oracle uses it to verify requests for nullifiers.
    #[must_use]
    pub fn offchain_pubkey(&self) -> EdDSAPublicKey {
        self.signer.offchain_signer_pubkey()
    }

    /// Returns the compressed `EdDSA` public key of the Authenticator signer which is used to verify off-chain operations.
    /// For example, the Nullifier Oracle uses it to verify requests for nullifiers.
    /// # Errors
    /// Will error if the public key cannot be serialized.
    pub fn offchain_pubkey_compressed(&self) -> Result<U256> {
        let pk = self.signer.offchain_signer_pubkey().pk;
        let mut compressed_bytes = Vec::new();
        pk.serialize_compressed(&mut compressed_bytes)?;
        Ok(U256::from_le_slice(&compressed_bytes))
    }

    /// Returns a reference to the `AccountRegistry` contract instance.
    ///
    /// # Errors
    /// Will error if the RPC URL is not valid.
    pub fn registry(&self) -> Result<Arc<AccountRegistryInstance<DynProvider>>> {
        if let Some(registry) = self.registry.get() {
            return Ok(Arc::clone(registry));
        }

        let provider = self.provider()?;
        let contract = Arc::new(AccountRegistry::new(
            *self.config.registry_address(),
            provider.erased(),
        ));

        let _ = self.registry.set(Arc::clone(&contract));
        Ok(self.registry.get().map_or(contract, Arc::clone))
    }

    /// Returns a reference to the Ethereum provider.
    ///
    /// # Errors
    /// Will error if the provided RPC URL is not valid.
    pub fn provider(&self) -> Result<DynProvider> {
        if let Some(provider) = self.provider.get() {
            return Ok(provider.clone());
        }

        let provider = ProviderBuilder::new().connect_http(self.config.rpc_url().parse()?);
        let erased = provider.erased();

        let _ = self.provider.set(erased.clone());
        Ok(self.provider.get().map_or(erased, std::clone::Clone::clone))
    }

    /// Returns the packed account index for the holder's World ID.
    ///
    /// The packed account index is a 256 bit integer which includes the user's account index, their recovery counter,
    /// and their pubkey id/commitment.
    ///
    /// # Errors
    /// Will error if the provided RPC URL is not valid or if there are RPC call failures.
    pub async fn packed_account_index(&mut self) -> Result<U256> {
        if let Some(packed_account_index) = self.packed_account_index {
            return Ok(packed_account_index);
        }

        let registry = self.registry()?;
        let raw_index = registry
            .authenticatorAddressToPackedAccountIndex(self.signer.onchain_signer_address())
            .call()
            .await?;

        if raw_index == U256::ZERO {
            return Err(AuthenticatorError::AccountDoesNotExist.into());
        }

        self.packed_account_index = Some(raw_index);
        Ok(raw_index)
    }

    /// Returns the account index for the holder's World ID.
    ///
    /// This is the index at the tree where the holder's World ID account is registered.
    ///
    /// # Errors
    /// Will error if the provided RPC URL is not valid or if there are RPC call failures.
    pub async fn account_index(&mut self) -> Result<U256> {
        let packed_account_index = self.packed_account_index().await?;
        let tree_index = packed_account_index & MASK_ACCOUNT_INDEX;
        Ok(tree_index)
    }

    /// Returns the raw index at the tree where the holder's World ID account is registered.
    ///
    /// # Errors
    /// Will error if the provided RPC URL is not valid or if there are RPC call failures.
    pub async fn tree_index(&mut self) -> Result<U256> {
        let account_index = self.account_index().await?;
        Ok(account_index - U256::from(1))
    }

    /// Returns the recovery counter for the holder's World ID.
    ///
    /// The recovery counter is used to efficiently invalidate all the old keys when an account is recovered.
    ///
    /// # Errors
    /// Will error if the provided RPC URL is not valid or if there are RPC call failures.
    pub async fn recovery_counter(&mut self) -> Result<U256> {
        let packed_account_index = self.packed_account_index().await?;
        let recovery_counter = packed_account_index & MASK_RECOVERY_COUNTER;
        Ok(recovery_counter >> 224)
    }

    /// Returns the pubkey id (or commitment) for the holder's World ID.
    ///
    /// This is a commitment to all the off-chain public keys that are authorized to act on behalf of the holder.
    ///
    /// # Errors
    /// Will error if the provided RPC URL is not valid or if there are RPC call failures.
    pub async fn pubkey_id(&mut self) -> Result<U256> {
        let packed_account_index = self.packed_account_index().await?;
        let pubkey_id = packed_account_index & MASK_PUBKEY_ID;
        Ok(pubkey_id >> 192)
    }

    /// Fetches a Merkle inclusion proof for the holder's World ID given their account index.
    ///
    /// # Errors
    /// - Will error if the provided indexer URL is not valid or if there are HTTP call failures.
    /// - Will error if the user is not registered on the registry.
    pub async fn fetch_inclusion_proof(
        &mut self,
    ) -> Result<(MerkleMembership, UserPublicKeyBatch)> {
        let account_index = self.account_index().await?;
        let url = format!("{}/proof/{}", self.config.indexer_url(), account_index);
        let response = reqwest::get(url).await?;
        let proof = response.json::<InclusionProofResponse>().await?;
        let root: FieldElement = proof
            .root
            .try_into()
            .map_err(|_| eyre::eyre!("Root is not a valid field element"))?;
        let siblings_vec: Vec<ark_babyjubjub::Fq> = proof
            .proof
            .into_iter()
            .map(|s| {
                s.try_into()
                    .map_err(|_| eyre::eyre!("Sibling is not a valid field element"))
            })
            .collect::<Result<Vec<_>, eyre::Error>>()
            .map_err(|_| eyre::eyre!("Siblings are not valid field elements"))?;
        let siblings: [ark_babyjubjub::Fq; TREE_DEPTH] =
            siblings_vec.try_into().map_err(|v: Vec<_>| {
                eyre::eyre!("Expected {} siblings, got {}", TREE_DEPTH, v.len())
            })?;

        let mut pubkey_batch = UserPublicKeyBatch {
            values: [EdwardsAffine::default(); 7],
        };

        for i in 0..proof.authenticator_pubkeys.len() {
            pubkey_batch.values[i] = EdwardsAffine::deserialize_compressed(Cursor::new(
                proof.authenticator_pubkeys[i].as_le_slice(),
            ))?;
        }

        Ok((
            MerkleMembership {
                root: MerkleRoot::from(*root),
                siblings,
                depth: TREE_DEPTH as u64,
                mt_index: proof.leaf_index,
            },
            pubkey_batch,
        ))
    }

    /// Returns the signing nonce for the holder's World ID.
    ///
    /// # Errors
    /// Will return an error if the registry contract call fails.
    pub async fn signing_nonce(&mut self) -> Result<U256> {
        let registry = self.registry()?;
        Ok(registry
            .signatureNonces(self.account_index().await?)
            .call()
            .await?)
    }

    /// Generates a World ID Uniqueness Proof given a provided context.
    ///
    /// # Errors
    /// - Will error if the any of the provided parameters are not valid.
    /// - Will error if any of the required network requests fail.
    /// - Will error if the user does not have a registered World ID.
    #[allow(clippy::future_not_send)]
    pub async fn generate_proof(
        &mut self,
        message_hash: FieldElement,
        rp_request: RpRequest,
        credential: Credential,
    ) -> Result<UniquenessProof> {
        let (merkle_membership, pk_batch) = self.fetch_inclusion_proof().await?;
        let pk_index = pk_batch
            .values
            .iter()
            .position(|pk| pk == &self.offchain_pubkey().pk)
            .ok_or_else(|| eyre::eyre!("Public key not found in batch"))?
            as u64;

        let query = OprfQuery {
            rp_id: RpId::new(rp_request.rp_id.parse::<u128>()?),
            share_epoch: ShareEpoch::default(), // TODO
            action: *rp_request.action_id,
            nonce: *rp_request.nonce,
            current_time_stamp: rp_request.current_time_stamp, // TODO
            nonce_signature: rp_request.signature,
        };

        // TODO: load once and from bytes
        let groth16_material = Groth16Material::new(QUERY_ZKEY_PATH, NULLIFIER_ZKEY_PATH)?;

        let key_material = UserKeyMaterial {
            pk_batch,
            pk_index,
            sk: self
                .signer
                .offchain_signer_private_key()
                .expose_secret()
                .clone(),
        };

        // TODO: check rp nullifier key
        let args = NullifierArgs {
            credential_signature: credential.try_into()?,
            merkle_membership,
            query,
            groth16_material,
            key_material,
            signal_hash: *message_hash,
            rp_nullifier_key: rp_request.rp_nullifier_key,
        };

        let mut rng = rand::thread_rng();
        let (proof, _public, nullifier) =
            oprf_client::nullifier(self.config.nullifier_oracle_urls(), 2, args, &mut rng).await?;

        Ok((proof, nullifier.into()))
    }

    /// Creates a new World ID account.
    ///
    /// # Errors
    /// Will error if the provided RPC URL is not valid or if there are HTTP call failures.
    pub async fn create_account(&mut self, recovery_address: Option<Address>) -> Result<String> {
        // Check locally if the account already exists, the request will fail on-chain otherwise.
        if self.packed_account_index().await.is_ok() {
            return Err(AuthenticatorError::AccountAlreadyExists.into());
        }

        let mut pubkey_batch = UserPublicKeyBatch {
            values: [EdwardsAffine::default(); 7],
        };

        pubkey_batch.values[0] = self.offchain_pubkey().pk;
        let leaf_hash = Self::leaf_hash(&pubkey_batch);

        let req = CreateAccountRequest {
            recovery_address,
            authenticator_addresses: vec![self.signer.onchain_signer_address()],
            authenticator_pubkeys: vec![self.offchain_pubkey_compressed()?],
            offchain_signer_commitment: leaf_hash.into(),
        };

        let resp = reqwest::Client::new()
            .post(format!("{}/create-account", self.config.gateway_url()))
            .json(&req)
            .send()
            .await?;

        let status = resp.status();

        if status.is_success() {
            let body: GatewayStatusResponse = resp.json().await?;
            Ok(body.request_id)
        } else {
            let body_text = resp.text().await.unwrap_or_else(|_| String::new());
            Err(eyre::eyre!(
                "failed to create account: status={status}, body={body_text}"
            ))
        }
    }

    /// Inserts a new authenticator to the account.
    ///
    /// # Errors
    /// Will error if the provided RPC URL is not valid or if there are HTTP call failures.
    pub async fn insert_authenticator(
        &mut self,
        new_authenticator_pubkey: EdDSAPublicKey,
        new_authenticator_address: Address,
        index: u32,
    ) -> Result<String> {
        let account_index = self.account_index().await?;
        let nonce = self.signing_nonce().await?;
        let (merkle_membership, mut pk_batch) = self.fetch_inclusion_proof().await?;
        let old_offchain_signer_commitment = Self::leaf_hash(&pk_batch);
        pk_batch.values[index as usize] = new_authenticator_pubkey.pk;
        let new_offchain_signer_commitment = Self::leaf_hash(&pk_batch);

        // TODO: remove this once compression is merged
        let mut compressed_bytes = Vec::new();
        new_authenticator_pubkey
            .pk
            .serialize_compressed(&mut compressed_bytes)?;
        let compressed_pubkey = U256::from_le_slice(&compressed_bytes);

        let eip712_domain = domain(
            self.provider()?.get_chain_id().await?,
            *self.config.registry_address(),
        );

        let signature = sign_insert_authenticator(
            &self.signer.onchain_signer(),
            account_index,
            new_authenticator_address,
            U256::from(index),
            compressed_pubkey,
            new_offchain_signer_commitment.into(),
            nonce,
            &eip712_domain,
        )
        .await
        .map_err(|e| eyre::eyre!("failed to sign insert authenticator: {}", e))?;

        let req = InsertAuthenticatorRequest {
            account_index,
            new_authenticator_address,
            pubkey_id: U256::from(index),
            new_authenticator_pubkey: compressed_pubkey,
            old_offchain_signer_commitment: old_offchain_signer_commitment.into(),
            new_offchain_signer_commitment: new_offchain_signer_commitment.into(),
            sibling_nodes: merkle_membership
                .siblings
                .iter()
                .map(std::convert::Into::into)
                .collect(),
            signature: signature.as_bytes().to_vec(),
            nonce,
        };

        let resp = reqwest::Client::new()
            .post(format!(
                "{}/insert-authenticator",
                self.config.gateway_url()
            ))
            .json(&req)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            let body: GatewayStatusResponse = resp.json().await?;
            Ok(body.request_id)
        } else {
            let body_text = resp.text().await.unwrap_or_else(|_| String::new());
            Err(eyre::eyre!(
                "failed to insert authenticator: status={status}, body={body_text}"
            ))
        }
    }

    /// Updates an existing authenticator slot with a new authenticator.
    ///
    /// # Errors
    /// Returns an error if the gateway rejects the request or a network error occurs.
    pub async fn update_authenticator(
        &mut self,
        old_authenticator_address: Address,
        new_authenticator_address: Address,
        new_authenticator_pubkey: EdDSAPublicKey,
        index: u32,
    ) -> Result<String> {
        let account_index = self.account_index().await?;
        let nonce = self.signing_nonce().await?;
        let (merkle_membership, mut pk_batch) = self.fetch_inclusion_proof().await?;
        let old_commitment: U256 = Self::leaf_hash(&pk_batch).into();
        pk_batch.values[index as usize] = new_authenticator_pubkey.pk;
        let new_commitment: U256 = Self::leaf_hash(&pk_batch).into();

        // TODO: remove this once compression is merged
        let mut compressed_bytes = Vec::new();
        new_authenticator_pubkey
            .pk
            .serialize_compressed(&mut compressed_bytes)?;
        let compressed_pubkey = U256::from_le_slice(&compressed_bytes);

        let eip712_domain = domain(
            self.provider()?.get_chain_id().await?,
            *self.config.registry_address(),
        );

        let signature = sign_update_authenticator(
            &self.signer.onchain_signer(),
            account_index,
            old_authenticator_address,
            new_authenticator_address,
            U256::from(index),
            compressed_pubkey,
            new_commitment,
            nonce,
            &eip712_domain,
        )
        .await
        .map_err(|e| eyre::eyre!("failed to sign update authenticator: {}", e))?;

        let sibling_nodes: Vec<U256> = merkle_membership
            .siblings
            .iter()
            .map(|s| (*s).into())
            .collect();

        let req = UpdateAuthenticatorRequest {
            account_index,
            old_authenticator_address,
            new_authenticator_address,
            old_offchain_signer_commitment: old_commitment,
            new_offchain_signer_commitment: new_commitment,
            sibling_nodes,
            signature: signature.as_bytes().to_vec(),
            nonce,
            pubkey_id: Some(U256::from(index)),
            new_authenticator_pubkey: Some(compressed_pubkey),
        };

        let resp = reqwest::Client::new()
            .post(format!(
                "{}/update-authenticator",
                self.config.gateway_url()
            ))
            .json(&req)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            let gateway_resp: GatewayStatusResponse = resp.json().await?;
            Ok(gateway_resp.request_id)
        } else {
            let body_text = resp.text().await.unwrap_or_else(|_| String::new());
            Err(eyre::eyre!(
                "failed to update authenticator: status={status}, body={body_text}"
            ))
        }
    }

    /// Removes an authenticator from the account.
    ///
    /// # Errors
    /// Returns an error if the gateway rejects the request or a network error occurs.
    pub async fn remove_authenticator(
        &mut self,
        authenticator_address: Address,
        index: u32,
    ) -> Result<String> {
        let account_index = self.account_index().await?;
        let nonce = self.signing_nonce().await?;
        let (merkle_membership, mut pk_batch) = self.fetch_inclusion_proof().await?;
        let old_commitment: U256 = Self::leaf_hash(&pk_batch).into();
        let existing_pubkey = pk_batch.values[index as usize];

        let mut compressed_old = Vec::new();
        existing_pubkey.serialize_compressed(&mut compressed_old)?;
        let compressed_old_pubkey = U256::from_le_slice(&compressed_old);

        pk_batch.values[index as usize] = EdwardsAffine::default();
        let new_commitment: U256 = Self::leaf_hash(&pk_batch).into();

        let eip712_domain = domain(
            self.provider()?.get_chain_id().await?,
            *self.config.registry_address(),
        );

        let signature = sign_remove_authenticator(
            &self.signer.onchain_signer(),
            account_index,
            authenticator_address,
            U256::from(index),
            compressed_old_pubkey,
            new_commitment,
            nonce,
            &eip712_domain,
        )
        .await
        .map_err(|e| eyre::eyre!("failed to sign remove authenticator: {}", e))?;

        let sibling_nodes: Vec<U256> = merkle_membership
            .siblings
            .iter()
            .map(|s| (*s).into())
            .collect();

        let req = RemoveAuthenticatorRequest {
            account_index,
            authenticator_address,
            old_offchain_signer_commitment: old_commitment,
            new_offchain_signer_commitment: new_commitment,
            sibling_nodes,
            signature: signature.as_bytes().to_vec(),
            nonce,
            pubkey_id: Some(U256::from(index)),
            authenticator_pubkey: Some(compressed_old_pubkey),
        };

        let resp = reqwest::Client::new()
            .post(format!(
                "{}/remove-authenticator",
                self.config.gateway_url()
            ))
            .json(&req)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            let gateway_resp: GatewayStatusResponse = resp.json().await?;
            Ok(gateway_resp.request_id)
        } else {
            let body_text = resp.text().await.unwrap_or_else(|_| String::new());
            Err(eyre::eyre!(
                "failed to remove authenticator: status={status}, body={body_text}"
            ))
        }
    }

    /// Fetches the status of a previously submitted gateway request.
    ///
    /// # Errors
    /// Returns an error if the gateway reports the request as missing or the status request fails.
    pub async fn request_status(&self, request_id: &str) -> Result<GatewayStatusResponse> {
        let resp = reqwest::Client::new()
            .get(format!(
                "{}/status/{}",
                self.config.gateway_url(),
                request_id
            ))
            .send()
            .await?;

        let status = resp.status();

        if status.is_success() {
            let body: GatewayStatusResponse = resp.json().await?;
            Ok(body)
        } else if status == reqwest::StatusCode::NOT_FOUND {
            Err(eyre::eyre!("gateway request {request_id} not found"))
        } else {
            let body_text = resp.text().await.unwrap_or_else(|_| String::new());
            Err(eyre::eyre!(
                "failed to fetch status for {request_id}: status={status}, body={body_text}"
            ))
        }
    }

    /// Computes the Merkle leaf for a given public key batch.
    ///
    /// # Errors
    /// Will error if the provided public key batch is not valid.
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    fn leaf_hash(pk: &UserPublicKeyBatch) -> ark_babyjubjub::Fq {
        let poseidon2_16: Poseidon2<ark_babyjubjub::Fq, 16, 5> = Poseidon2::default();
        let mut input = [ark_babyjubjub::Fq::ZERO; 16];
        #[allow(clippy::unwrap_used)]
        {
            input[0] = ark_babyjubjub::Fq::from_str("105702839725298824521994315").unwrap();
        }
        for i in 0..7 {
            input[i * 2 + 1] = pk.values[i].x;
            input[i * 2 + 2] = pk.values[i].y;
        }
        poseidon2_16.permutation(&input)[1]
    }
}

/// Errors that can occur when interacting with the Authenticator.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Hash, Clone, Copy)]
pub enum AuthenticatorError {
    /// This operation requires a registered account and an account is not registered
    /// for this authenticator. Call `create_account` first to register it.
    #[error("Account is not registered for this authenticator.")]
    AccountDoesNotExist,

    /// The account already exists for this authenticator. Call `account_index` to get the account index.
    #[error("Account already exists for this authenticator.")]
    AccountAlreadyExists,
}
