//! This module contains all the base functionality to support Authenticators in World ID.
//!
//! An Authenticator is the application layer with which a user interacts with the Protocol.
use std::sync::{Arc, OnceLock};
use std::{io::Cursor, sync::LazyLock};

use crate::account_registry::AccountRegistry::{self, AccountRegistryInstance};
use crate::config::Config;
use crate::credential::BaseField;
use crate::types::InclusionProofResponse;
use alloy::primitives::{Address, U256};
use alloy::providers::ProviderBuilder;
use alloy::providers::{DynProvider, Provider};
use alloy::signers::local::PrivateKeySigner;
use alloy::uint;
use ark_bn254::{Bn254, Fr};
use ark_ff::{AdditiveGroup, PrimeField};
use ark_serde_compat::groth16::Groth16Proof;
use circom_types::{groth16::ZKey, traits::CheckElement};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use eyre::Result;
use groth16::{ConstraintMatrices, ProvingKey};
use oprf_types::{MerkleEpoch, RpId, ShareEpoch};

type Affine = ark_babyjubjub::EdwardsAffine;

static MASK_RECOVERY_COUNTER: U256 =
    uint!(0xFFFFFFFF00000000000000000000000000000000000000000000000000000000_U256);
static MASK_PUBKEY_ID: U256 =
    uint!(0x00000000FFFFFFFF000000000000000000000000000000000000000000000000_U256);
static MASK_ACCOUNT_INDEX: U256 =
    uint!(0x0000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_U256);

static MAX_PUBKEYS: usize = 7;
static TREE_DEPTH: usize = 30;

static ZKEY_QUERY_BYTES: &[u8] = include_bytes!("../../../OPRFQueryProof.zkey");
static ZKEY_NULLIFIER_BYTES: &[u8] = include_bytes!("../../../OPRFNullifierProof.zkey");

static ZKEY_QUERY: LazyLock<Result<(ConstraintMatrices<Fr>, ProvingKey<Bn254>)>> =
    LazyLock::new(|| {
        let query_zkey = ZKey::from_reader(Cursor::new(ZKEY_QUERY_BYTES), CheckElement::No)?;
        Ok(query_zkey.into())
    });

static ZKEY_NULLIFIER: LazyLock<Result<(ConstraintMatrices<Fr>, ProvingKey<Bn254>)>> =
    LazyLock::new(|| {
        let nullifier_zkey =
            ZKey::from_reader(Cursor::new(ZKEY_NULLIFIER_BYTES), CheckElement::No)?;
        Ok(nullifier_zkey.into())
    });

static REGISTRY: OnceLock<Arc<AccountRegistryInstance<DynProvider>>> = OnceLock::new();

type OPRFPublicKey = (Affine, ShareEpoch);
type UniquenessProof = (Groth16Proof, BaseField);
type MerkleProof = (BaseField, [BaseField; TREE_DEPTH], MerkleEpoch);

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
    pub async fn fetch_inclusion_proof(&mut self) -> Result<MerkleProof> {
        let account_index = self.account_index().await?;
        let url = format!("{}/proof/{}", self.config.indexer_url(), account_index);
        let response = reqwest::get(url).await?;
        let proof = response.json::<InclusionProofResponse>().await?;
        let root = BaseField::from_be_bytes_mod_order(&proof.root.to_be_bytes::<32>());
        let proof = proof
            .proof
            .into_iter()
            .map(|p| BaseField::from_be_bytes_mod_order(&p.to_be_bytes::<32>()))
            .collect::<Vec<_>>();
        Ok((
            root,
            proof
                .try_into()
                .map_err(|e| eyre::eyre!("error parsing merkle inclusion proof"))?,
            MerkleEpoch::default(),
        ))
    }

    /// Fetches the off-chain public keys for the holder's World ID.
    ///
    /// # Errors
    /// Will error if the user does not have a registered World ID.
    pub fn fetch_pubkeys(&self) -> Result<[[BaseField; 2]; MAX_PUBKEYS]> {
        // TODO: actually fetch from registry
        let pubkeys = std::array::from_fn(|i| {
            if i == 0 {
                let pk = self.signer.offchain_signer_pubkey();
                [pk.pk.x, pk.pk.y]
            } else {
                [BaseField::ZERO, BaseField::ZERO]
            }
        });
        Ok(pubkeys)
    }

    // TODO: implement
    // pub async fn fetch_rp_pubkey(&self, rp_id: U256) -> Result<EdDSAPublicKey> {
    //     // TODO: fetch from contract
    //     let sk = EdDSAPrivateKey::from_bytes([0; 32]);
    //     Ok(sk.public())
    // }

    // async fn fetch_oprf_public_key(&self) -> Result<OPRFPublicKey> {
    //     // TODO: fetch from contract
    //     Ok((
    //         (Projective::generator() * ScalarField::from(42)).into_affine(),
    //         ShareEpoch::default(),
    //     ))
    // }

    // fn query_matrices(&self) -> Result<Arc<ConstraintMatrices<Fr>>> {
    //     let (matrices, _) = ZKEY_QUERY.as_ref().map_err(|e| eyre::eyre!(e))?;
    //     Ok(Arc::new(matrices.clone()))
    // }

    // fn query_pk(&self) -> Result<Arc<ProvingKey<Bn254>>> {
    //     let (_, pk) = ZKEY_QUERY.as_ref().map_err(|e| eyre::eyre!(e))?;
    //     Ok(Arc::new(pk.clone()))
    // }

    fn nullifier_matrices() -> Result<Arc<ConstraintMatrices<Fr>>> {
        let (matrices, _) = ZKEY_NULLIFIER.as_ref().map_err(|e| eyre::eyre!(e))?;
        Ok(Arc::new(matrices.clone()))
    }

    fn nullifier_pk() -> Result<Arc<ProvingKey<Bn254>>> {
        let (_, pk) = ZKEY_NULLIFIER.as_ref().map_err(|e| eyre::eyre!(e))?;
        Ok(Arc::new(pk.clone()))
    }

    /// Generates a World ID Uniqueness Proof given a provided context.
    ///
    /// # Errors
    /// - Will error if the any of the provided parameters are not valid.
    /// - Will error if any of the required network requests fail.
    /// - Will error if the user does not have a registered World ID.
    pub fn generate_proof(
        &mut self,
        _rp_id: RpId,
        _action_id: BaseField,
        _message_hash: BaseField,
        _rp_signature: &EdDSASignature,
        _nonce: BaseField,
    ) -> Result<UniquenessProof> {
        // let mut rng = rand::thread_rng();
        // let (oprf_public_key, oprf_key_epoch) = self.fetch_oprf_public_key().await?;
        // let tree_index = self.tree_index().await?.as_limbs()[0];
        // let pubkey_id = self.pubkey_id().await?.as_limbs()[0];
        // let pubkeys = self.fetch_pubkeys().await?;
        // let (merkle_root, siblings, merkle_epoch) = self.fetch_inclusion_proof().await?;
        // let id_commitment_r = BaseField::ZERO;
        // let mut rp_signing_key = SigningKey::random(&mut rng);
        // let signature = rp_signing_key.sign(nonce.to_string().as_bytes());

        // let nullifier_args = NullifierArgs {
        //     oprf_public_key,
        //     key_epoch:oprf_key_epoch,
        //     sk: self.signer.offchain_signer_private_key().clone(),
        //     pks: pubkeys,
        //     pk_index: pubkey_id,
        //     merkle_root,
        //     mt_index: tree_index,
        //     siblings,
        //     rp_id,
        //     action: action_id,
        //     signal_hash: message_hash,
        //     merkle_epoch,
        //     nonce,
        //     signature,
        //     id_commitment_r,
        //     degree: DEGREE,
        //     query_pk: self.query_pk()?,
        //     query_matrices: self.query_matrices()?,
        //     nullifier_pk: self.nullifier_pk()?,
        //     nullifier_matrices: self.nullifier_matrices()?,
        // };

        // Ok(oprf_client::nullifier(
        //     &self.config.nullifier_oracle_urls(),
        //     nullifier_args,
        //     &mut rng,
        // )
        // .await?)
        unimplemented!()
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
