//! This module implements the authentication process for World ID.
//!
//! The MPC nodes use this authentication service to determine whether a user is eligible to
//! compute a nullifier or session identifier.
//!
//! It defines the following sub-modules:
//!
//! - [`credential_blinding_factor`] – implements authentication for OPRF credential blinding factor generation.
//! - [`merkle_watcher`] – validates and caches merkle roots from the `WorldIDRegistry`.
//! - [`nonce_history`] – keeps track of RP nonces in a node-local cache to
//!   detect replays already seen by this process
//! - [`rp_registry_watcher`] – validates and caches registered RPs from the `RpRegistry`.
//! - [`schema_issuer_registry_watcher`] – validates and caches registered Credential Schema Issuers.
//! - [`rp_module`] – unified implementation for session and uniqueness OPRF authentication.

use ark_bn254::Bn254;
use ark_groth16::PreparedVerifyingKey;
use taceo_oprf::types::OprfKeyId;
use world_id_primitives::TREE_DEPTH;

pub(crate) mod credential_blinding_factor;
pub(crate) mod merkle_watcher;
pub(crate) mod nonce_history;
pub(crate) mod rp_module;
pub(crate) mod rp_registry_watcher;
pub(crate) mod schema_issuer_registry_watcher;

pub(crate) fn verify_query_proof(
    vk: &PreparedVerifyingKey<Bn254>,
    proof: &ark_groth16::Proof<Bn254>,
    blinded_query: ark_babyjubjub::EdwardsAffine,
    merkle_root: ark_babyjubjub::Fq,
    oprf_key_id: OprfKeyId,
    action: ark_babyjubjub::Fq,
    nonce: ark_babyjubjub::Fq,
) -> bool {
    tracing::trace!("verifying user proof...");
    let public = [
        blinded_query.x,
        blinded_query.y,
        merkle_root,
        ark_babyjubjub::Fq::from(TREE_DEPTH as u64),
        oprf_key_id.into(),
        action,
        nonce,
    ];
    ark_groth16::Groth16::<Bn254>::verify_proof(vk, proof, &public)
        .expect("We expect that we loaded the correct key")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use alloy::{
        node_bindings::AnvilInstance,
        primitives::{Address, U256},
        signers::local::LocalSigner,
    };
    use ark_serialize::CanonicalSerialize;
    use eddsa_babyjubjub::EdDSAPrivateKey;
    use rand::Rng;
    use secrecy::ExposeSecret as _;
    use taceo_nodes_common::web3::{self, HttpRpcProviderBuilder};
    use taceo_oprf::core::oprf::BlindingFactor;
    use world_id_primitives::{
        AuthenticatorPublicKeySet, FieldElement, Signer, TREE_DEPTH, merkle::MerkleInclusionProof,
    };
    use world_id_proof::{circuit_inputs::QueryProofCircuitInput, errors};
    use world_id_test_utils::{
        anvil::TestAnvil,
        fixtures::{self, RegistryTestContext, RpFixture},
        merkle::first_leaf_merkle_path,
    };

    use crate::{
        auth::{
            merkle_watcher::MerkleWatcher, nonce_history::NonceHistory,
            rp_registry_watcher::RpRegistryWatcher,
            schema_issuer_registry_watcher::SchemaIssuerRegistryWatcher,
        },
        config::WatcherCacheConfig,
    };

    pub(crate) struct OprfRequestAuthTestSetup {
        pub(crate) anvil: TestAnvil,
        pub(crate) world_id_registry: Address,
        pub(crate) rp_registry: Address,
        pub(crate) credential_schema_issuer_registry: Address,
        pub(crate) issuer_schema_id: u64,
        pub(crate) rp_fixture: RpFixture,
        pub(crate) merkle_inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
        pub(crate) key_index: u64,
        pub(crate) key_set: AuthenticatorPublicKeySet,
        pub(crate) signer: Signer,
    }

    pub(crate) fn build_http_provider(anvil: &AnvilInstance) -> web3::HttpRpcProvider {
        HttpRpcProviderBuilder::with_default_values(vec![anvil.endpoint_url()])
            .environment(taceo_nodes_common::Environment::Dev)
            .chain_id(31_337)
            .wallet(anvil.wallet().expect("Should have signer wallet"))
            .build()
            .expect("can build RPC providers")
    }

    impl OprfRequestAuthTestSetup {
        pub(crate) async fn new() -> eyre::Result<Self> {
            let mut rng = rand::thread_rng();
            let RegistryTestContext {
                anvil,
                world_id_registry,
                rp_registry,
                credential_registry: credential_schema_issuer_registry,
                ..
            } = RegistryTestContext::new_with_mock_oprf_key_registry().await?;

            let deployer = anvil.signer(0)?;

            let rp_fixture = fixtures::generate_rp_fixture();

            // Register the RP which also triggers a OPRF key-gen.
            let rp_signer = LocalSigner::from_signing_key(rp_fixture.signing_key.clone());
            anvil
                .register_rp(
                    rp_registry,
                    deployer.clone(),
                    rp_fixture.world_rp_id,
                    rp_signer.address(),
                    rp_signer.address(),
                    "taceo.oprf".to_string(),
                )
                .await?;

            // Register an issuer which also triggers a OPRF key-gen.
            let issuer_schema_id = rng.r#gen::<u64>();
            let issuer_sk = EdDSAPrivateKey::random(&mut rng);
            let issuer_public_key = issuer_sk.public();
            anvil
                .register_issuer(
                    credential_schema_issuer_registry,
                    deployer.clone(),
                    issuer_schema_id,
                    issuer_public_key.clone(),
                )
                .await?;

            let signer =
                Signer::from_seed_bytes(&rng.r#gen::<[u8; 32]>()).expect("Can build from seed");

            let mut key_set = AuthenticatorPublicKeySet::default();
            key_set.try_push(signer.offchain_signer_pubkey())?;
            let leaf_hash = key_set.leaf_hash();

            let offchain_pubkey_compressed = {
                let pk = signer.offchain_signer_pubkey().pk;
                let mut compressed_bytes = Vec::new();
                pk.serialize_compressed(&mut compressed_bytes)
                    .expect("serialization to succeed");
                U256::from_le_slice(&compressed_bytes)
            };

            let leaf_index = 1;
            let (siblings, root) = first_leaf_merkle_path(leaf_hash);
            let key_index = key_set
                .iter()
                .position(|pk| {
                    pk.as_ref()
                        .is_some_and(|pk| pk.pk == signer.offchain_signer_pubkey().pk)
                })
                .expect("key set contains signer key") as u64;

            anvil
                .create_account(
                    world_id_registry,
                    deployer.clone(),
                    signer.onchain_signer_address(),
                    offchain_pubkey_compressed,
                    leaf_hash.into(),
                )
                .await;

            Ok(Self {
                anvil,
                world_id_registry,
                rp_registry,
                credential_schema_issuer_registry,
                issuer_schema_id,
                rp_fixture,
                merkle_inclusion_proof: MerkleInclusionProof {
                    root,
                    leaf_index,
                    siblings,
                },
                key_index,
                key_set,
                signer,
            })
        }
    }

    /// Common service-level infrastructure shared across auth module tests.
    ///
    /// Wraps [`OprfRequestAuthTestSetup`] with all initialized watchers and
    /// shared configuration constants, so each module's test setup only needs
    /// to add its own authenticator and request construction logic.
    pub(crate) struct AuthModulesTestSetup {
        pub(crate) setup: OprfRequestAuthTestSetup,
        pub(crate) merkle_watcher: MerkleWatcher,
        pub(crate) rp_registry_watcher: RpRegistryWatcher,
        pub(crate) schema_issuer_registry_watcher: SchemaIssuerRegistryWatcher,
        pub(crate) nonce_history: NonceHistory,
        pub(crate) current_time_stamp_max_difference: Duration,
        pub(crate) timeout_external_eth_call: Duration,
        pub(crate) http_rpc_provider: web3::HttpRpcProvider,
    }

    impl AuthModulesTestSetup {
        pub(crate) async fn new() -> eyre::Result<Self> {
            let setup = OprfRequestAuthTestSetup::new().await?;

            let current_time_stamp_max_difference = Duration::from_secs(1800);
            let timeout_external_eth_call = Duration::from_secs(10);

            let http_rpc_provider = build_http_provider(&setup.anvil.instance);

            let merkle_watcher = MerkleWatcher::init(
                setup.world_id_registry,
                &http_rpc_provider,
                WatcherCacheConfig::default(),
            );

            let rp_registry_watcher = RpRegistryWatcher::init(
                setup.rp_registry,
                http_rpc_provider.clone(),
                timeout_external_eth_call,
                WatcherCacheConfig::default(),
            );

            let schema_issuer_registry_watcher = SchemaIssuerRegistryWatcher::init(
                setup.credential_schema_issuer_registry,
                &http_rpc_provider,
                WatcherCacheConfig::default(),
            );

            let nonce_history = NonceHistory::init(current_time_stamp_max_difference * 2);

            Ok(Self {
                setup,
                merkle_watcher,
                rp_registry_watcher,
                schema_issuer_registry_watcher,
                nonce_history,
                current_time_stamp_max_difference,
                timeout_external_eth_call,
                http_rpc_provider,
            })
        }

        /// Generates a valid ZK query proof and blinds the query for use in OPRF
        /// request construction.
        ///
        /// `action` is the action field element (zero for credential blinding factor,
        /// a valid session/nullifier action for other modules).
        /// `query_origin_id` is the RP ID or issuer schema ID as a [`FieldElement`].
        pub(crate) fn generate_query_proof(
            &self,
            action: FieldElement,
            query_origin_id: FieldElement,
        ) -> eyre::Result<QueryProofBundle> {
            let mut rng = rand::thread_rng();

            let query_material =
                world_id_proof::load_embedded_query_material().expect("Can load query material");

            let query_blinding_factor = BlindingFactor::rand(&mut rng);

            let query_hash = world_id_primitives::authenticator::oprf_query_digest(
                self.setup.merkle_inclusion_proof.leaf_index,
                action,
                query_origin_id,
            );
            let signature = self
                .setup
                .signer
                .offchain_signer_private_key()
                .expose_secret()
                .sign(*query_hash);

            let siblings: [ark_babyjubjub::Fq; TREE_DEPTH] =
                self.setup.merkle_inclusion_proof.siblings.map(|s| *s);

            let query_proof_input = QueryProofCircuitInput::<TREE_DEPTH> {
                pk: self.setup.key_set.as_affine_array(),
                pk_index: self.setup.key_index.into(),
                s: signature.s,
                r: signature.r,
                merkle_root: *self.setup.merkle_inclusion_proof.root,
                depth: ark_babyjubjub::Fq::from(TREE_DEPTH as u64),
                mt_index: self.setup.merkle_inclusion_proof.leaf_index.into(),
                siblings,
                beta: query_blinding_factor.beta(),
                rp_id: *query_origin_id,
                action: *action,
                nonce: self.setup.rp_fixture.nonce,
            };
            let _affine = errors::check_query_input_validity(&query_proof_input)?;

            let (proof, public_inputs) =
                query_material.generate_proof(&query_proof_input, &mut rng)?;
            query_material.verify_proof(&proof, &public_inputs)?;

            let blinded_request =
                taceo_oprf::core::oprf::client::blind_query(*query_hash, query_blinding_factor);

            Ok(QueryProofBundle {
                proof: proof.into(),
                blinded_query: blinded_request.blinded_query(),
                nonce: self.setup.rp_fixture.nonce,
            })
        }
    }

    /// Result of [`AuthModulesTestSetup::generate_query_proof`], containing all
    /// outputs needed to construct an [`taceo_oprf::types::api::OprfRequest`].
    pub(crate) struct QueryProofBundle {
        pub(crate) proof: circom_types::groth16::Proof<ark_bn254::Bn254>,
        pub(crate) blinded_query: ark_babyjubjub::EdwardsAffine,
        pub(crate) nonce: ark_babyjubjub::Fq,
    }
}
