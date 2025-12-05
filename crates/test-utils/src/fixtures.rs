use std::time::{SystemTime, UNIX_EPOCH};

use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::ProviderBuilder,
    sol_types::SolEvent,
};
use ark_babyjubjub::{EdwardsAffine, Fq, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey};
use eyre::{eyre, Context as _, Result};
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use oprf_types::{RpId as OprfRpId, ShareEpoch};
use rand::{thread_rng, Rng};
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
    pub account_registry: Address,
    pub credential_registry: Address,
    pub issuer_private_key: EdDSAPrivateKey,
    pub issuer_public_key: EdDSAPublicKey,
    pub issuer_schema_id: U256,
}

impl RegistryTestContext {
    /// Spawns Anvil, deploys the AccountRegistry and CredentialSchemaIssuerRegistry,
    /// and registers a random issuer.
    pub async fn new() -> Result<Self> {
        let anvil = TestAnvil::spawn().wrap_err("failed to spawn anvil")?;
        let deployer = anvil
            .signer(0)
            .wrap_err("failed to acquire default anvil signer")?;
        let account_registry = anvil
            .deploy_account_registry(deployer.clone())
            .await
            .wrap_err("failed to deploy account registry")?;
        let credential_registry = anvil
            .deploy_credential_schema_issuer_registry(deployer.clone())
            .await
            .wrap_err("failed to deploy credential registry")?;

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
            account_registry,
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
    account_id: u64,
    genesis_issued_at: u64,
    expires_at: u64,
) -> Credential {
    Credential::new()
        .issuer_schema_id(issuer_schema_id)
        .account_id(account_id)
        .genesis_issued_at(genesis_issued_at)
        .expires_at(expires_at)
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
    account_id: u64,
) -> Result<MerkleFixture> {
    let key_set = AuthenticatorPublicKeySet::new(Some(pubkeys))?;
    let leaf = key_set.leaf_hash();
    let (siblings, root) = first_leaf_merkle_path(leaf);
    let inclusion_proof = MerkleInclusionProof::new(root, account_id, siblings);

    Ok(MerkleFixture {
        key_set,
        inclusion_proof,
        root,
        leaf,
    })
}

pub struct RpFixture {
    pub world_rp_id: WorldRpId,
    pub oprf_rp_id: OprfRpId,
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
    let rp_id_value: u128 = rng.gen();
    let world_rp_id = WorldRpId::new(rp_id_value);
    let oprf_rp_id = OprfRpId::new(rp_id_value);

    let action = Fq::rand(&mut rng);
    let nonce = Fq::rand(&mut rng);
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();

    let mut msg = Vec::new();
    msg.extend(nonce.into_bigint().to_bytes_le());
    msg.extend(current_timestamp.to_le_bytes());
    let signing_key = SigningKey::random(&mut rng);
    let signature = signing_key.sign(&msg);

    let rp_session_id_r_seed = FieldElement::from(Fq::rand(&mut rng));

    let rp_secret = Fr::rand(&mut rng);
    let rp_nullifier_point = (EdwardsAffine::generator() * rp_secret).into_affine();

    RpFixture {
        world_rp_id,
        oprf_rp_id,
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
