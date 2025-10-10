//! This module contains all the base functionality to support Authenticators in World ID.
//!
//! An Authenticator is the application layer with which a user interacts with the Protocol.
use std::io::Cursor;
use std::sync::{Arc, OnceLock};

use crate::account_registry::AccountRegistry::{self, AccountRegistryInstance};
use crate::config::Config;
use crate::types::{BaseField, InclusionProofResponse, RpRequest};
use crate::Credential;
use alloy::primitives::{Address, U256};
use alloy::providers::ProviderBuilder;
use alloy::providers::{DynProvider, Provider};
use alloy::signers::local::PrivateKeySigner;
use alloy::uint;
use ark_babyjubjub::EdwardsAffine;
use ark_ff::AdditiveGroup;
use ark_serde_compat::groth16::Groth16Proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey};
use eyre::Result;
use oprf_client::zk::Groth16Material;
use oprf_client::{MerkleMembership, NullifierArgs, OprfQuery, UserKeyMaterial};
use oprf_types::crypto::UserPublicKeyBatch;
use oprf_types::{MerkleEpoch, MerkleRoot, RpId, ShareEpoch};
use poseidon2::Poseidon2;
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

static REGISTRY: OnceLock<Arc<AccountRegistryInstance<DynProvider>>> = OnceLock::new();

type UniquenessProof = (Groth16Proof, BaseField);

/// An Authenticator is the base layer with which a user interacts with the Protocol.
#[derive(Debug)]
pub struct Authenticator {
    /// General configuration for the Authenticator.
    pub config: Config,
    signer: AuthenticatorSigner,
    packed_account_index: Option<U256>,
}

impl Authenticator {
    /// Create a new Authenticator from a seed and config.
    ///
    /// # Errors
    /// Will error if the provided seed is not valid.
    pub fn new(seed: &[u8], config: Config) -> Result<Self> {
        let signer = AuthenticatorSigner::from_seed_bytes(seed)?;
        Ok(Self {
            packed_account_index: None,
            signer,
            config,
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
        let provider = ProviderBuilder::new().connect_http(self.config.rpc_url().parse()?);
        let contract = AccountRegistry::new(*self.config.registry_address(), provider.erased());
        Ok(REGISTRY.get_or_init(|| Arc::new(contract)).clone())
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
        let root: BaseField = proof.root.try_into()?;
        let siblings_vec: Vec<BaseField> = proof
            .proof
            .into_iter()
            .map(std::convert::TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;
        let siblings: [BaseField; TREE_DEPTH] = siblings_vec.try_into().map_err(|v: Vec<_>| {
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
                root: MerkleRoot::from(root),
                siblings,
                depth: TREE_DEPTH as u64,
                mt_index: proof.leaf_index,
                epoch: MerkleEpoch::default(),
            },
            pubkey_batch,
        ))
    }

    /// Computes the Merkle leaf for a given public key batch.
    ///
    /// # Errors
    /// Will error if the provided public key batch is not valid.
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn merkle_leaf(&self, pk: &UserPublicKeyBatch) -> ark_babyjubjub::Fq {
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

    /// Generates a World ID Uniqueness Proof given a provided context.
    ///
    /// # Errors
    /// - Will error if the any of the provided parameters are not valid.
    /// - Will error if any of the required network requests fail.
    /// - Will error if the user does not have a registered World ID.
    #[allow(clippy::future_not_send)]
    pub async fn generate_proof(
        &mut self,
        message_hash: BaseField,
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
            action: rp_request.action_id,
            nonce: rp_request.nonce,
            current_time_stamp: rp_request.current_time_stamp, // TODO
            nonce_signature: rp_request.signature,
        };

        // TODO: load once and from bytes
        let groth16_material = Groth16Material::new(QUERY_ZKEY_PATH, NULLIFIER_ZKEY_PATH)?;

        let key_material = UserKeyMaterial {
            pk_batch,
            pk_index,
            sk: self.signer.offchain_signer_private_key().clone(),
        };

        // TODO: check rp nullifier key
        let args = NullifierArgs {
            credential_signature: credential.try_into()?,
            merkle_membership,
            query,
            groth16_material,
            key_material,
            signal_hash: message_hash,
            rp_nullifier_key: rp_request.rp_nullifier_key,
        };

        let mut rng = rand::thread_rng();
        let (proof, _public, nullifier) =
            oprf_client::nullifier(self.config.nullifier_oracle_urls(), 2, args, &mut rng).await?;

        Ok((proof, nullifier))
    }
}

/// The inner signer which can sign requests for both on-chain and off-chain operations on behalf of the authenticator.
///
/// Both keys are zeroized on drop.
#[derive(Debug)]
pub struct AuthenticatorSigner {
    /// An on-chain SECP256K1 private key.
    onchain_signer: PrivateKeySigner,
    /// An off-chain `EdDSA` private key.
    offchain_signer: EdDSAPrivateKey,
}

impl AuthenticatorSigner {
    /// Initializes a new signer from an input seed.
    pub fn from_seed_bytes(seed: &[u8]) -> Result<Self> {
        if seed.len() != 32 {
            return Err(eyre::eyre!("seed must be 32 bytes"));
        }
        let bytes: [u8; 32] = seed.try_into()?;
        let onchain_signer = PrivateKeySigner::from_bytes(&bytes.into())?;
        let offchain_signer = EdDSAPrivateKey::from_bytes(bytes);

        Ok(Self {
            onchain_signer,
            offchain_signer,
        })
    }

    /// Returns a reference to the internal signer.
    #[allow(unused)]
    pub const fn onchain_signer(&self) -> &PrivateKeySigner {
        &self.onchain_signer
    }

    /// Returns a reference to the internal offchain signer.
    pub const fn offchain_signer_private_key(&self) -> &EdDSAPrivateKey {
        &self.offchain_signer
    }

    pub const fn onchain_signer_address(&self) -> Address {
        self.onchain_signer.address()
    }

    pub fn offchain_signer_pubkey(&self) -> EdDSAPublicKey {
        self.offchain_signer.public()
    }
}
