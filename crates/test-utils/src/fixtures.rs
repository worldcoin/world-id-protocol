use std::time::{SystemTime, UNIX_EPOCH};

use alloy::{
    primitives::{Address, U160},
    signers::{Signature, SignerSync, local::PrivateKeySigner},
};
use ark_babyjubjub::{EdwardsAffine, Fq, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use eddsa_babyjubjub::EdDSAPublicKey;
use eyre::{Context as _, Result};
use k256::ecdsa::SigningKey;
use rand::{Rng, thread_rng};
use taceo_oprf::types::{OprfKeyId, ShareEpoch};
use taceo_oprf_test_utils::PEER_ADDRESSES;
use world_id_primitives::{
    FieldElement, TREE_DEPTH, authenticator::AuthenticatorPublicKeySet, credential::Credential,
    merkle::MerkleInclusionProof, rp::RpId as WorldRpId,
};

use crate::{anvil::TestAnvil, merkle::first_leaf_merkle_path};

/// Holds the default on-chain environment used by the E2E tests
pub struct RegistryTestContext {
    pub anvil: TestAnvil,
    pub world_id_registry: Address,
    pub oprf_key_registry: Address,
    pub credential_registry: Address,
    pub rp_registry: Address,
    pub world_id_verifier: Address,
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
        let oprf_key_registry = anvil
            .deploy_oprf_key_registry(deployer.clone())
            .await
            .wrap_err("failed to deploy OprfKeyRegistry")?;
        let credential_registry = anvil
            .deploy_credential_schema_issuer_registry(deployer.clone(), oprf_key_registry)
            .await
            .wrap_err("failed to deploy CredentialSchemaIssuerRegistry")?;
        let rp_registry = anvil
            .deploy_rp_registry(deployer.clone(), oprf_key_registry)
            .await
            .wrap_err("failed to deploy RpRegistry")?;
        let world_id_verifier = anvil
            .deploy_world_id_verifier(
                deployer.clone(),
                credential_registry,
                world_id_registry,
                oprf_key_registry,
            )
            .await
            .wrap_err("failed to deploy Verifier")?;

        anvil
            .register_oprf_nodes(oprf_key_registry, deployer.clone(), PEER_ADDRESSES.to_vec())
            .await?;

        // add RpRegistry as OprfKeyRegistry admin because it needs to init key-gens
        anvil
            .add_oprf_key_registry_admin(oprf_key_registry, deployer.clone(), rp_registry)
            .await?;

        // Add CredentialSchemaIssuerRegistry as OprfKeyRegistry admin so it can call initKeyGen
        anvil
            .add_oprf_key_registry_admin(oprf_key_registry, deployer.clone(), credential_registry)
            .await
            .wrap_err("failed to add CredentialSchemaIssuerRegistry as OprfKeyRegistry admin")?;

        Ok(Self {
            anvil,
            world_id_registry,
            oprf_key_registry,
            credential_registry,
            rp_registry,
            world_id_verifier,
        })
    }

    /// Spawns Anvil and deploys protocol registries with a lightweight mock OPRF key registry.
    ///
    /// This variant is useful for auth tests that need issuer removal without running OPRF key-gen rounds.
    pub async fn new_with_mock_oprf_key_registry() -> Result<Self> {
        let anvil = TestAnvil::spawn().wrap_err("failed to spawn anvil")?;
        let deployer = anvil
            .signer(0)
            .wrap_err("failed to acquire default anvil signer")?;
        let world_id_registry = anvil
            .deploy_world_id_registry(deployer.clone())
            .await
            .wrap_err("failed to deploy WorldIDRegistry")?;
        let oprf_key_registry = anvil
            .deploy_mock_oprf_key_registry(deployer.clone())
            .await
            .wrap_err("failed to deploy mock OprfKeyRegistry")?;
        let credential_registry = anvil
            .deploy_credential_schema_issuer_registry(deployer.clone(), oprf_key_registry)
            .await
            .wrap_err("failed to deploy CredentialSchemaIssuerRegistry")?;
        let rp_registry = anvil
            .deploy_rp_registry(deployer.clone(), oprf_key_registry)
            .await
            .wrap_err("failed to deploy RpRegistry")?;

        Ok(Self {
            anvil,
            world_id_registry,
            oprf_key_registry,
            credential_registry,
            rp_registry,
            world_id_verifier: Address::ZERO,
        })
    }
}

/// Helper for building a minimal credential used in tests.
pub fn build_base_credential(
    issuer_schema_id: u64,
    leaf_index: u64,
    genesis_issued_at: u64,
    expires_at: u64,
    credential_sub_blinding_factor: FieldElement,
) -> Credential {
    let sub = Credential::compute_sub(leaf_index, credential_sub_blinding_factor);
    Credential::new()
        .issuer_schema_id(issuer_schema_id)
        .subject(sub)
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
    leaf_index: u64,
) -> Result<MerkleFixture> {
    let key_set = AuthenticatorPublicKeySet::new(pubkeys)?;
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

#[derive(Clone)]
pub struct RpFixture {
    pub world_rp_id: WorldRpId,
    pub oprf_key_id: OprfKeyId,
    pub share_epoch: ShareEpoch,
    pub action: Fq,
    pub nonce: Fq,
    pub current_timestamp: u64,
    pub expiration_timestamp: u64,
    pub signature: Signature,
    pub rp_session_id_r_seed: FieldElement,
    pub signing_key: SigningKey,
    pub rp_secret: Fr,
    pub rp_nullifier_point: EdwardsAffine,
}

/// Generates RP identifiers, signatures, and ancillary inputs shared across tests.
pub fn generate_rp_fixture() -> RpFixture {
    let mut rng = thread_rng();
    let rp_id_value: u64 = rng.r#gen();
    // Atm we use the same value for both WorldRpId and OprfKeyId, this is also done line this in the RpRegistry contract
    let world_rp_id = WorldRpId::new(rp_id_value);
    let oprf_key_id = OprfKeyId::new(U160::from(rp_id_value));

    let action = Fq::rand(&mut rng);
    let nonce = Fq::rand(&mut rng);
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let expiration_timestamp = current_timestamp + 300; // 5 minutes from now

    let signing_key = SigningKey::random(&mut rng);
    let signer = PrivateKeySigner::from_signing_key(signing_key.clone());

    let msg = world_id_primitives::rp::compute_rp_signature_msg(
        nonce,
        current_timestamp,
        expiration_timestamp,
    );
    let signature = signer.sign_message_sync(&msg).expect("can sign");

    let rp_session_id_r_seed = FieldElement::from(Fq::rand(&mut rng));

    let rp_secret = Fr::rand(&mut rng);
    let rp_nullifier_point = (EdwardsAffine::generator() * rp_secret).into_affine();

    RpFixture {
        world_rp_id,
        oprf_key_id,
        share_epoch: ShareEpoch::default(),
        action,
        nonce,
        current_timestamp,
        expiration_timestamp,
        signature,
        rp_session_id_r_seed,
        signing_key,
        rp_secret,
        rp_nullifier_point,
    }
}
