use std::{str::FromStr as _, sync::Arc};

use alloy::{
    primitives::Address,
    signers::{k256::ecdsa::SigningKey, local::LocalSigner},
};
use ark_bn254::Bn254;
use ark_groth16::Proof;
use clap::Parser;
use eyre::Context as _;
use secrecy::ExposeSecret as _;
use taceo_oprf::{core::oprf::BlindingFactor, dev_client::DevClientConfig};
use world_id_core::{
    Authenticator, AuthenticatorError, EdDSAPrivateKey, EdDSASignature, FieldElement,
    proof::CircomGroth16Material,
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

/// Shared configuration structure for both client types
#[derive(Parser, Debug)]
pub struct WorldDevClientConfig {
    /// Indexer address
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_INDEXER_URL",
        default_value = "http://localhost:8080"
    )]
    pub indexer_url: String,

    /// Gateway address
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_GATEWAY_URL",
        default_value = "http://localhost:8081"
    )]
    pub gateway_url: String,

    /// If set to `true` uses chain_id 31_337 (anvil). If set to `false` uses chain_id 480 (world chain).
    #[clap(long, env = "OPRF_DEV_CLIENT_ANVIL")]
    pub anvil: bool,

    /// The Address of the WorldIDRegistry contract.
    #[clap(long, env = "OPRF_DEV_CLIENT_WORLD_ID_REGISTRY_CONTRACT")]
    pub world_id_registry_contract: Address,

    #[clap(flatten)]
    pub config: DevClientConfig,
}

/// Shared client components
pub struct SharedDevClientComponents {
    pub authenticator: Authenticator,
    pub signer: LocalSigner<SigningKey>,
    pub authenticator_private_key: EdDSAPrivateKey,
    pub query_material: Arc<CircomGroth16Material>,
}

impl SharedDevClientComponents {
    pub async fn fetch_inclusion_proof(
        &self,
    ) -> eyre::Result<(
        MerkleInclusionProof<TREE_DEPTH>,
        AuthenticatorPublicKeySet,
        u64,
    )> {
        let (inclusion_proof, key_set) = self.authenticator.fetch_inclusion_proof().await?;

        let key_index = key_set
            .iter()
            .position(|pk| {
                pk.as_ref()
                    .is_some_and(|pk| pk.pk == self.authenticator.offchain_pubkey().pk)
            })
            .ok_or(AuthenticatorError::PublicKeyNotFound)? as u64;
        Ok((inclusion_proof, key_set, key_index))
    }
}

pub async fn init_shared_components(
    config: &WorldDevClientConfig,
) -> eyre::Result<SharedDevClientComponents> {
    let query_material = Arc::new(
        world_id_core::proof::load_embedded_query_material()
            .context("while loading query material")?,
    );
    let (authenticator, authenticator_private_key) = init_authenticator(
        config.indexer_url.to_owned(),
        config.gateway_url.to_owned(),
        config.world_id_registry_contract,
        &config.config,
        config.anvil,
        Arc::clone(&query_material),
    )
    .await?;
    let signer = alloy::signers::local::PrivateKeySigner::from_str(
        config.config.taceo_private_key.expose_secret(),
    )?;

    Ok(SharedDevClientComponents {
        authenticator,
        signer,
        authenticator_private_key,
        query_material,
    })
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
