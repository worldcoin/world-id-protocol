use std::array;
use std::os::macos::raw;
use std::sync::{Arc, OnceLock};
use std::{io::Cursor, sync::LazyLock};

use crate::authenticator_registry::AuthenticatorRegistry::AuthenticatorRegistryInstance;
use crate::ProofResponse;
use crate::{authenticator_registry::AuthenticatorRegistry, AuthenticatorSigner, Config};
use alloy::primitives::{Address, U256};
use alloy::providers::ProviderBuilder;
use alloy::providers::{DynProvider, Provider};
use alloy::uint;
use ark_bn254::{Bn254, Fr};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{AdditiveGroup, PrimeField};
use ark_serde_compat::groth16::Groth16Proof;
use circom_types::{groth16::ZKey, traits::CheckElement};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use eyre::Result;
use groth16::{ConstraintMatrices, ProvingKey};
use oprf_client::{Affine, BaseField, Projective, ScalarField};
use oprf_types::{KeyEpoch, MerkleEpoch, RpId};

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

static REGISTRY: OnceLock<Arc<AuthenticatorRegistryInstance<DynProvider>>> = OnceLock::new();

type OPRFPublicKey = (Affine, KeyEpoch);
type UniquenessProof = (Groth16Proof, BaseField);
type MerkleProof = (BaseField, [BaseField; TREE_DEPTH], MerkleEpoch);

// TODO: remove
static DEGREE: usize = 1;

#[derive(Clone, Debug)]
pub struct Authenticator {
    signer: AuthenticatorSigner,
    config: Config,
    packed_account_index: Option<U256>,
}

impl Authenticator {
    /// Create a new Authenticator from a seed and config.
    pub async fn new(seed: &[u8], config: Config) -> Result<Self> {
        let signer = AuthenticatorSigner::from_seed_bytes(seed)?;
        Ok(Self {
            packed_account_index: None,
            signer,
            config,
        })
    }

    pub fn onchain_address(&self) -> Address {
        self.signer.onchain_signer_address()
    }

    pub fn offchain_pubkey(&self) -> EdDSAPublicKey {
        self.signer.offchain_signer_pubkey()
    }

    pub async fn registry(&self) -> Result<Arc<AuthenticatorRegistryInstance<DynProvider>>> {
        let provider = ProviderBuilder::new().connect_http(self.config.rpc_url().parse()?);
        let contract =
            AuthenticatorRegistry::new(*self.config.registry_address(), provider.erased());
        Ok(REGISTRY.get_or_init(|| Arc::new(contract)).clone())
    }

    pub async fn packed_account_index(&mut self) -> Result<U256> {
        if let Some(packed_account_index) = self.packed_account_index {
            return Ok(packed_account_index);
        }

        let registry = self.registry().await?;
        let raw_index = registry
            .authenticatorAddressToPackedAccountIndex(self.signer.onchain_signer_address())
            .call()
            .await?;

        self.packed_account_index = Some(raw_index);
        Ok(raw_index)
    }

    pub async fn account_index(&mut self) -> Result<U256> {
        let packed_account_index = self.packed_account_index().await?;
        let tree_index = packed_account_index & MASK_ACCOUNT_INDEX;
        Ok(tree_index)
    }

    pub async fn tree_index(&mut self) -> Result<U256> {
        let account_index = self.account_index().await?;
        Ok(account_index - U256::from(1))
    }

    pub async fn recovery_counter(&mut self) -> Result<U256> {
        let packed_account_index = self.packed_account_index().await?;
        let recovery_counter = packed_account_index & MASK_RECOVERY_COUNTER;
        Ok(recovery_counter >> 224)
    }

    pub async fn pubkey_id(&mut self) -> Result<U256> {
        let packed_account_index = self.packed_account_index().await?;
        let pubkey_id = packed_account_index & MASK_PUBKEY_ID;
        Ok(pubkey_id >> 192)
    }

    pub async fn fetch_inclusion_proof(&mut self) -> Result<MerkleProof> {
        let account_index = self.account_index().await?;
        let url = format!("{}/proof/{}", self.config.indexer_url(), account_index);
        let response = reqwest::get(url).await?;
        let proof = response.json::<ProofResponse>().await?;
        let root = BaseField::from_be_bytes_mod_order(&proof.root.to_be_bytes::<32>());
        let proof = proof
            .proof
            .into_iter()
            .map(|p| BaseField::from_be_bytes_mod_order(&p.to_be_bytes::<32>()))
            .collect::<Vec<_>>();
        Ok((root, proof.try_into().unwrap(), MerkleEpoch::default()))
    }

    pub async fn fetch_pubkeys(&self) -> Result<[[BaseField; 2]; MAX_PUBKEYS]> {
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

    pub async fn fetch_rp_pubkey(&self, rp_id: U256) -> Result<EdDSAPublicKey> {
        // TODO: fetch from contract
        let sk = EdDSAPrivateKey::from_bytes([0; 32]);
        Ok(sk.public())
    }

    async fn fetch_oprf_public_key(&self) -> Result<OPRFPublicKey> {
        // TODO: fetch from contract
        Ok((
            (Projective::generator() * ScalarField::from(42)).into_affine(),
            KeyEpoch::default(),
        ))
    }

    fn query_matrices(&self) -> Result<&ConstraintMatrices<Fr>> {
        let (matrices, _) = ZKEY_QUERY.as_ref().map_err(|e| eyre::eyre!(e))?;
        Ok(matrices)
    }

    fn query_pk(&self) -> Result<&ProvingKey<Bn254>> {
        let (_, pk) = ZKEY_QUERY.as_ref().map_err(|e| eyre::eyre!(e))?;
        Ok(pk)
    }

    fn nullifier_matrices(&self) -> Result<&ConstraintMatrices<Fr>> {
        let (matrices, _) = ZKEY_NULLIFIER.as_ref().map_err(|e| eyre::eyre!(e))?;
        Ok(matrices)
    }

    fn nullifier_pk(&self) -> eyre::Result<&'static ProvingKey<Bn254>> {
        let (_, pk) = ZKEY_NULLIFIER.as_ref().map_err(|e| eyre::eyre!(e))?;
        Ok(pk)
    }

    pub async fn generate_proof(
        &mut self,
        rp_id: RpId,
        action_id: BaseField,
        message_hash: BaseField,
        rp_signature: EdDSASignature,
        nonce: BaseField,
    ) -> Result<UniquenessProof> {
        let mut rng = rand::thread_rng();
        let (oprf_public_key, oprf_key_epoch) = self.fetch_oprf_public_key().await?;
        let tree_index = self.tree_index().await?.as_limbs()[0];
        let pubkey_id = self.pubkey_id().await?.as_limbs()[0];
        let pubkeys = self.fetch_pubkeys().await?;
        let (merkle_root, siblings, merkle_epoch) = self.fetch_inclusion_proof().await?;
        let rp_pk = self.fetch_rp_pubkey(U256::from(rp_id.into_inner())).await?;
        let id_commitment_r = BaseField::ZERO;

        Ok(oprf_client::nullifier(
            &self.config.nullifier_oracle_urls(),
            oprf_public_key,
            oprf_key_epoch,
            self.signer.offchain_signer_private_key().clone(),
            pubkeys,
            pubkey_id,
            merkle_root,
            tree_index,
            siblings,
            rp_id,
            rp_pk,
            action_id,
            message_hash,
            merkle_epoch,
            nonce,
            rp_signature,
            id_commitment_r,
            DEGREE,
            self.query_pk()?,
            self.query_matrices()?,
            self.nullifier_pk()?,
            self.nullifier_matrices()?,
            &mut rng,
        )
        .await?)
    }
}
