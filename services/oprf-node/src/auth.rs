//! This module implements the authentication process for World ID.
//!
//! During the user's session initialization, the MPC nodes uses this authentication service to determine whether a user is eligible to compute a nullifier.
//!
//! Additionally, it defines two sub-modules necessary for the authentication process.
//!
//! - [`credential_blinding_factor`] – implements authentication for OPRF credential blinding factor generation.
//! - [`merkle_watcher`] – watches the blockchain for merkle-root update events.
//! - [`nullifier`] – implements authentication for OPRF nullifier generation.
//! - [`rp_registry_watcher`] – keeps track of registered RPs
//! - [`schema_issuer_registry_watcher`] – keeps track of registered Credential Schema Issuers
//! - [`nonce_history`] – keeps track of nonces used for nonce + `time_stamp` signatures to detect replays

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use ark_bn254::Bn254;
use circom_types::groth16::VerificationKey;
use taceo_oprf::types::{OprfKeyId, api::OprfRequest};
use world_id_core::FieldElement;
use world_id_primitives::{
    TREE_DEPTH,
    oprf::{NullifierOprfRequestAuthV1, WorldIdRequestAuthError},
};

use crate::auth::{
    merkle_watcher::MerkleWatcher, nonce_history::NonceHistory,
    rp_registry_watcher::RpRegistryWatcher,
};

/// The embedded Groth16 verification key for OPRF query proofs.
const QUERY_VERIFICATION_KEY: &str = include_str!("../../../circom/OPRFQuery.vk.json");

pub(crate) mod credential_blinding_factor;
pub(crate) mod merkle_watcher;
pub(crate) mod nonce_history;
pub(crate) mod nullifier;
pub(crate) mod rp_registry_watcher;
pub(crate) mod schema_issuer_registry_watcher;
pub(crate) mod session;

pub(crate) struct OprfRequestAuthWithRpSignature {
    rp_registry_watcher: RpRegistryWatcher,
    nonce_history: NonceHistory,
    current_time_stamp_max_difference: Duration,
    query_auth: crate::auth::QueryProofAuthenticator,
}

impl OprfRequestAuthWithRpSignature {
    pub(crate) fn init(
        merkle_watcher: MerkleWatcher,
        rp_registry_watcher: RpRegistryWatcher,
        nonce_history: NonceHistory,
        current_time_stamp_max_difference: Duration,
    ) -> Self {
        Self {
            rp_registry_watcher,
            nonce_history,
            current_time_stamp_max_difference,
            query_auth: crate::auth::QueryProofAuthenticator::init(merkle_watcher),
        }
    }

    pub(crate) async fn verify(
        &self,
        msg: &[u8],
        request: &OprfRequest<NullifierOprfRequestAuthV1>,
    ) -> Result<OprfKeyId, WorldIdRequestAuthError> {
        tracing::trace!("checking timestamp...");
        // check the time stamp against system time +/- difference
        let req_time_stamp = Duration::from_secs(request.auth.current_time_stamp);
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time is after unix epoch");
        if current_time.abs_diff(req_time_stamp) > self.current_time_stamp_max_difference {
            return Err(WorldIdRequestAuthError::TimeStampTooOld);
        }

        tracing::trace!("fetching RP info...");
        // fetch the RP info
        let rp = self.rp_registry_watcher.get_rp(&request.auth.rp_id).await?;

        tracing::trace!("check RP signature...");
        let recovered = request
            .auth
            .signature
            .recover_address_from_msg(msg)
            .map_err(|err| {
                tracing::debug!("invalid signature: {err:?}");
                WorldIdRequestAuthError::InvalidRpSignature
            })?;
        if recovered != rp.signer {
            return Err(WorldIdRequestAuthError::InvalidRpSignature);
        }

        tracing::trace!("add nonce to store...");
        // add nonce to history to check if the nonces where only used once
        self.nonce_history
            .add_nonce(FieldElement::from(request.auth.nonce))
            .await?;

        // common verification
        self.query_auth
            .verify(
                &request.auth.proof.clone().into(),
                request.blinded_query,
                request.auth.merkle_root,
                rp.oprf_key_id,
                request.auth.action,
                request.auth.nonce,
            )
            .await?;

        tracing::trace!("authentication successful!");
        Ok(rp.oprf_key_id)
    }
}

/// Common authentication for [`NullifierOprfRequestAuthenticator`] and [`CredentialBlindingFactorOprfRequestAuthenticator`].
pub(crate) struct QueryProofAuthenticator {
    merkle_watcher: MerkleWatcher,
    vk: Arc<ark_groth16::PreparedVerifyingKey<Bn254>>,
}

impl QueryProofAuthenticator {
    pub(crate) fn init(merkle_watcher: MerkleWatcher) -> Self {
        let vk: VerificationKey<Bn254> =
            serde_json::from_str(QUERY_VERIFICATION_KEY).expect("can deserialize embedded vk");
        Self {
            merkle_watcher,
            vk: Arc::new(ark_groth16::prepare_verifying_key(&vk.into())),
        }
    }

    pub(crate) async fn verify(
        &self,
        proof: &ark_groth16::Proof<Bn254>,
        blinded_query: ark_babyjubjub::EdwardsAffine,
        merkle_root: ark_babyjubjub::Fq,
        oprf_key_id: OprfKeyId,
        action: ark_babyjubjub::Fq,
        nonce: ark_babyjubjub::Fq,
    ) -> Result<(), WorldIdRequestAuthError> {
        tracing::trace!("checking if merkle root is valid...");
        self.merkle_watcher
            .ensure_root_valid(merkle_root.into())
            .await?;

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
        let valid = ark_groth16::Groth16::<Bn254>::verify_proof(&self.vk, proof, &public)
            .expect("We expect that we loaded the correct key");
        if valid {
            tracing::trace!("proof valid");
            Ok(())
        } else {
            tracing::trace!("proof INVALID");
            Err(WorldIdRequestAuthError::InvalidQueryProof)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use alloy::{
        primitives::{Address, U256},
        signers::local::LocalSigner,
    };
    use ark_serialize::CanonicalSerialize;
    use rand::Rng;
    use secrecy::ExposeSecret as _;
    use taceo_oprf::{core::oprf::BlindingFactor, service::StartedServices};
    use tokio_util::sync::CancellationToken;
    use world_id_core::{EdDSAPrivateKey, FieldElement, Signer, proof::errors};
    use world_id_primitives::{
        TREE_DEPTH, authenticator::AuthenticatorPublicKeySet,
        circuit_inputs::QueryProofCircuitInput, merkle::MerkleInclusionProof,
    };
    use world_id_test_utils::{
        anvil::TestAnvil,
        fixtures::{RegistryTestContext, RpFixture, generate_rp_fixture},
        merkle::first_leaf_merkle_path,
    };

    use crate::auth::{
        merkle_watcher::MerkleWatcher, nonce_history::NonceHistory,
        rp_registry_watcher::RpRegistryWatcher,
        schema_issuer_registry_watcher::SchemaIssuerRegistryWatcher,
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

            let rp_fixture = generate_rp_fixture();

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
    }

    impl AuthModulesTestSetup {
        pub(crate) async fn new() -> eyre::Result<Self> {
            let setup = OprfRequestAuthTestSetup::new().await?;

            let max_cache_size = 100;
            let cache_maintenance_interval = Duration::from_secs(60);
            let current_time_stamp_max_difference = Duration::from_secs(300);
            let started_services = StartedServices::default();
            let cancellation_token = CancellationToken::new();

            let (merkle_watcher, _) = MerkleWatcher::init(
                setup.world_id_registry,
                setup.anvil.ws_endpoint(),
                max_cache_size,
                cache_maintenance_interval,
                started_services.new_service(),
                cancellation_token.clone(),
            )
            .await?;

            let (rp_registry_watcher, _) = RpRegistryWatcher::init(
                setup.rp_registry,
                setup.anvil.ws_endpoint(),
                max_cache_size,
                cache_maintenance_interval,
                started_services.new_service(),
                cancellation_token.clone(),
            )
            .await?;

            let (schema_issuer_registry_watcher, _) = SchemaIssuerRegistryWatcher::init(
                setup.credential_schema_issuer_registry,
                setup.anvil.ws_endpoint(),
                max_cache_size,
                cache_maintenance_interval,
                started_services.new_service(),
                cancellation_token.clone(),
            )
            .await?;

            let nonce_history = NonceHistory::init(
                current_time_stamp_max_difference * 2,
                cache_maintenance_interval,
            );

            Ok(Self {
                setup,
                merkle_watcher,
                rp_registry_watcher,
                schema_issuer_registry_watcher,
                nonce_history,
                current_time_stamp_max_difference,
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

            let query_material = world_id_core::proof::load_embedded_query_material()
                .expect("Can load query material");

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
