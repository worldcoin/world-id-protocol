use std::time::{SystemTime, UNIX_EPOCH};

use alloy::{
    network::EthereumWallet,
    primitives::{Address, U160, U256},
    providers::ProviderBuilder,
    signers::{local::PrivateKeySigner, Signature, SignerSync},
    sol_types::SolEvent,
};
use ark_babyjubjub::{EdwardsAffine, Fq, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger as _, PrimeField, UniformRand};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey};
use eyre::{eyre, Context as _, Result};
use k256::ecdsa::SigningKey;
use rand::{thread_rng, Rng};
use taceo_oprf_types::{OprfKeyId, ShareEpoch};
use world_id_primitives::{
    authenticator::AuthenticatorPublicKeySet, credential::Credential, merkle::MerkleInclusionProof,
    rp::RpId as WorldRpId, FieldElement, TREE_DEPTH,
};

use crate::{
    anvil::{CredentialSchemaIssuerRegistry, TestAnvil},
    merkle::first_leaf_merkle_path,
};

/// Holds the default on-chain environment used by the E2E tests
pub struct RegistryTestContext {
    pub anvil: TestAnvil,
    pub world_id_registry: Address,
    pub credential_registry: Address,
    pub issuer_private_key: EdDSAPrivateKey,
    pub issuer_public_key: EdDSAPublicKey,
    pub issuer_schema_id: U256,
}

impl RegistryTestContext {
    /// Spawns Anvil, deploys the WorldIDRegistry and CredentialSchemaIssuerRegistry,
    /// and registers a random issuer.
    pub async fn new() -> Result<Self> {
        let anvil = TestAnvil::spawn().wrap_err("failed to spawn anvil")?;
        let deployer = anvil
            .signer(0)
            .wrap_err("failed to acquire default anvil signer")?;
        let world_id_registry = anvil
            .deploy_world_id_registry(deployer.clone())
            .await
            .wrap_err("failed to deploy WorldIDRegistry")?;
        let credential_registry = anvil
            .deploy_credential_schema_issuer_registry(deployer.clone())
            .await
            .wrap_err("failed to deploy CredentialSchemaIssuerRegistry")?;

        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(deployer.clone()))
            .connect_http(
                anvil
                    .endpoint()
                    .parse()
                    .wrap_err("invalid anvil endpoint URL")?,
            );
        let registry_contract = CredentialSchemaIssuerRegistry::new(credential_registry, provider);

        let issuer_private_key = EdDSAPrivateKey::random(&mut thread_rng());
        let issuer_public_key = issuer_private_key.public();
        let issuer_pubkey_repr = CredentialSchemaIssuerRegistry::Pubkey {
            x: U256::from_limbs(issuer_public_key.pk.x.into_bigint().0),
            y: U256::from_limbs(issuer_public_key.pk.y.into_bigint().0),
        };

        let receipt = registry_contract
            .register(issuer_pubkey_repr, deployer.address())
            .send()
            .await
            .wrap_err("failed to submit issuer registration")?
            .get_receipt()
            .await
            .wrap_err("failed to fetch issuer registration receipt")?;

        let issuer_schema_id = receipt
            .logs()
            .iter()
            .find_map(|log| {
                CredentialSchemaIssuerRegistry::IssuerSchemaRegistered::decode_log(
                    log.inner.as_ref(),
                )
                .ok()
            })
            .map(|event| event.issuerSchemaId)
            .ok_or_else(|| eyre!("IssuerSchemaRegistered event not emitted"))?;

        Ok(Self {
            anvil,
            world_id_registry,
            credential_registry,
            issuer_private_key,
            issuer_public_key,
            issuer_schema_id,
        })
    }

    pub fn issuer_schema_id_u64(&self) -> Result<u64> {
        self.issuer_schema_id
            .try_into()
            .map_err(|_| eyre!("issuer schema id exceeded u64 range"))
    }
}

/// Helper for building a minimal credential used in tests.
pub fn build_base_credential(
    issuer_schema_id: u64,
    leaf_index: u64,
    genesis_issued_at: u64,
    expires_at: u64,
) -> (Credential, FieldElement) {
    let mut rng = rand::thread_rng();
    let credential_sub_blinding_factor = FieldElement::random(&mut rng);
    let credential = Credential::new()
        .issuer_schema_id(issuer_schema_id)
        .sub(leaf_index, credential_sub_blinding_factor)
        .genesis_issued_at(genesis_issued_at)
        .expires_at(expires_at);

    (credential, credential_sub_blinding_factor)
}

pub struct MerkleFixture {
    pub key_set: AuthenticatorPublicKeySet,
    pub inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
    pub root: FieldElement,
    pub leaf: Fq,
}

/// Builds the Merkle witness for the first leaf given a set of public keys.
pub fn single_leaf_merkle_fixture(
    pubkeys: Vec<EdDSAPublicKey>,
    leaf_index: u64,
) -> Result<MerkleFixture> {
    let key_set = AuthenticatorPublicKeySet::new(Some(pubkeys))?;
    let leaf = key_set.leaf_hash();
    let (siblings, root) = first_leaf_merkle_path(leaf);
    let inclusion_proof = MerkleInclusionProof::new(root, leaf_index, siblings);

    Ok(MerkleFixture {
        key_set,
        inclusion_proof,
        root,
        leaf,
    })
}

pub struct RpFixture {
    pub world_rp_id: WorldRpId,
    pub oprf_key_id: OprfKeyId,
    pub share_epoch: ShareEpoch,
    pub action: Fq,
    pub nonce: Fq,
    pub current_timestamp: u64,
    pub signature: Signature,
    pub rp_session_id_r_seed: FieldElement,
    pub signing_key: SigningKey,
    pub rp_secret: Fr,
    pub rp_nullifier_point: EdwardsAffine,
}

/// Generates RP identifiers, signatures, and ancillary inputs shared across tests.
pub fn generate_rp_fixture() -> RpFixture {
    let mut rng = thread_rng();
    let rp_id_value: U160 = rng.gen();
    // Atm we use the same value for both WorldRpId and OprfKeyId, this is also done line this in the RpRegistry contract
    let world_rp_id = WorldRpId::new(rp_id_value);
    let oprf_rp_id = OprfKeyId::new(rp_id_value);

    let action = Fq::rand(&mut rng);
    let nonce = Fq::rand(&mut rng);
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();

    let signing_key = SigningKey::random(&mut rng);
    let signer = PrivateKeySigner::from_signing_key(signing_key.clone());

    let mut msg = Vec::new();
    msg.extend(nonce.into_bigint().to_bytes_le());
    msg.extend(current_timestamp.to_le_bytes());
    let signature = signer.sign_message_sync(&msg).expect("can sign");

    let rp_session_id_r_seed = FieldElement::from(Fq::rand(&mut rng));

    let rp_secret = Fr::rand(&mut rng);
    let rp_nullifier_point = (EdwardsAffine::generator() * rp_secret).into_affine();

    RpFixture {
        world_rp_id,
        oprf_key_id: oprf_rp_id,
        share_epoch: ShareEpoch::default(),
        action,
        nonce,
        current_timestamp,
        signature,
        rp_session_id_r_seed,
        signing_key,
        rp_secret,
        rp_nullifier_point,
    }
}
