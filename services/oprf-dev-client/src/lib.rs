use std::sync::Arc;

use alloy::primitives::Address;
use ark_bn254::Bn254;
use ark_groth16::Proof;
use eyre::Context as _;
use secrecy::ExposeSecret as _;
use taceo_oprf::{core::oprf::BlindingFactor, dev_client::DevClientConfig};
use world_id_core::{
    Authenticator, EdDSAPrivateKey, EdDSASignature, FieldElement, proof::CircomGroth16Material,
};
use world_id_primitives::{
    TREE_DEPTH, authenticator::AuthenticatorPublicKeySet, circuit_inputs::QueryProofCircuitInput,
    merkle::MerkleInclusionProof,
};

pub struct CreateQueryProofArgs<'a> {
    pub authenticator_signature: EdDSASignature,
    pub action: FieldElement,
    pub nonce: FieldElement,
    pub rp_id: u64,
    pub blinding_factor: BlindingFactor,
    pub inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
    pub key_set: AuthenticatorPublicKeySet,
    pub key_index: u64,
    pub query_material: &'a CircomGroth16Material,
}

pub fn create_query_proof(args: CreateQueryProofArgs<'_>) -> eyre::Result<Proof<Bn254>> {
    let CreateQueryProofArgs {
        authenticator_signature,
        action,
        nonce,
        rp_id: id,
        blinding_factor,
        inclusion_proof,
        key_set,
        key_index,
        query_material,
    } = args;
    let siblings: [ark_babyjubjub::Fq; TREE_DEPTH] = inclusion_proof.siblings.map(|s| *s);

    let query_proof_input = QueryProofCircuitInput::<TREE_DEPTH> {
        pk: key_set.as_affine_array(),
        pk_index: key_index.into(),
        s: authenticator_signature.s,
        r: authenticator_signature.r,
        merkle_root: *inclusion_proof.root,
        depth: ark_babyjubjub::Fq::from(TREE_DEPTH as u64),
        mt_index: inclusion_proof.leaf_index.into(),
        siblings,
        beta: blinding_factor.beta(),
        rp_id: ark_babyjubjub::Fq::from(id),
        action: *action,
        nonce: *nonce,
    };

    let (proof, public_inputs) =
        query_material.generate_proof(&query_proof_input, &mut rand::thread_rng())?;
    query_material
        .verify_proof(&proof, &public_inputs)
        .expect("proof verifies");
    Ok(proof)
}

pub async fn init_authenticator(
    indexer_url: String,
    gateway_url: String,
    world_id_registry_contract: Address,
    config: &DevClientConfig,
    anvil: bool,
    query_material: Arc<CircomGroth16Material>,
) -> eyre::Result<(Authenticator, EdDSAPrivateKey)> {
    let world_config = world_id_primitives::Config::new(
        Some(config.chain_rpc_url.expose_secret().to_string()),
        if anvil { 31_337 } else { 480 },
        world_id_registry_contract,
        indexer_url.clone(),
        gateway_url.clone(),
        config.nodes.clone(),
        config.threshold,
    )
    .context("while creating world config")?;

    let nullifier_material = world_id_core::proof::load_embedded_nullifier_material()
        .context("while loading query material")?;

    tracing::info!("creating account..");
    let seed = [7u8; 32];
    let authenticator = Authenticator::init_or_register(
        &seed,
        world_config.clone(),
        query_material,
        Arc::new(nullifier_material),
        None,
    )
    .await?;
    let authenticator_private_key = EdDSAPrivateKey::from_bytes(seed);
    Ok((authenticator, authenticator_private_key))
}
